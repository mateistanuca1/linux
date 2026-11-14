// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/types.h>

#include <net/af_vsock.h>
#include <net/sock.h>
#include <net/vsock_addr.h>

#include <xen/argo/argo_ring.h>
#include <xen/interface/xen.h>
#include <xen/xen.h>
#include <xen/xenbus.h>

/*
 * Message types carried in the Argo message_type field. These are this
 * transport's own wire protocol, not part of the Argo ABI.
 */
#define ARGO_MSG_SYN		1
#define ARGO_MSG_ACK		2
#define ARGO_MSG_DATA		3
#define ARGO_MSG_FIN		4
#define ARGO_MSG_SYN_ACK	5

/*
 * Argo auto-bind default address.
 */
static const struct sockaddr_vm addr_auto = {
	.svm_family = AF_VSOCK,
	.svm_cid = XEN_ARGO_DOMID_ANY,
	.svm_port = 0,
	.svm_zero = {0},
};

/*
 * Argo private data.
 */
struct argo_transport {
	struct argo_ring_hnd *h;	/* Argo ring handle. */
	/*
	 * Bytes sitting in sk_receive_queue. Maintained under the socket lock
	 * in struct sock (sk->sk_lock), which both the receive worker and the
	 * reader hold. Kept as a counter rather than walked on demand:
	 * stream_has_data() is called on every recvmsg() and every poll(),
	 * and walking a deep queue there is quadratic.
	 */
	u32 rx_bytes;
	/* The peer has been told this end is finished. */
	bool fin_sent;
};

/*
 * Per-skb read cursor, for a recv() that consumed only part of a message.
 * The skb may be paged, so skb_pull() is not an option past the header.
 */
struct argo_skb_cb {
	u32 offset;
};

#define ARGO_SKB_CB(skb) ((struct argo_skb_cb *)(skb)->cb)

/*
 * Private data helpers.
 */
#define argo_trans(vsk) ((struct argo_transport *)((vsk)->trans))

/*
 * Initialize/Tear-down socket.
 */
static int argo_transport_socket_init(struct vsock_sock *vsk,
				      struct vsock_sock *psk)
{
	struct argo_transport *t;

	BUILD_BUG_ON(sizeof(struct argo_skb_cb) >
		     sizeof_field(struct sk_buff, cb));

	t = kzalloc_obj(*t, GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	vsk->trans = t;

	return 0;
}

static void argo_transport_destruct(struct vsock_sock *vsk)
{
	kfree(argo_trans(vsk));
	vsk->trans = NULL;
}

static void argo_send_fin(struct vsock_sock *vsk);

static void argo_transport_release(struct vsock_sock *vsk)
{
	struct argo_transport *t = argo_trans(vsk);

	/*
	 * af_vsock calls .release when the socket is closed and never calls
	 * .shutdown there, so a close() that was not preceded by shutdown()
	 * has to tell the peer from here. Before the handle is dropped: the
	 * send needs the ring.
	 */
	argo_send_fin(vsk);

	vsock_remove_sock(vsk);

	if (t->h) {
		argo_ring_handle_put(t->h);
		t->h = NULL;
	}
}

/*
 * vsock and Argo spell "any" differently: vsock uses VMADDR_CID_ANY and
 * VMADDR_PORT_ANY, Argo uses XEN_ARGO_DOMID_ANY and port zero. Rewrite an
 * address in place so it can be handed to the hypervisor.
 */
static int sockaddr_vm_normalize(struct sockaddr_vm *addr)
{
	if (addr->svm_cid == VMADDR_CID_ANY)
		addr->svm_cid = addr_auto.svm_cid;

	if (addr->svm_port == VMADDR_PORT_ANY)
		addr->svm_port = addr_auto.svm_port;

	if (addr->svm_cid > XEN_ARGO_DOMID_ANY)
		return -EINVAL;

	return 0;
}

static int sockaddrvm_to_argo(const struct sockaddr_vm *s, xen_argo_addr_t *d)
{
	struct sockaddr_vm c = *s;

	if (sockaddr_vm_normalize(&c))
		return -EINVAL;

	/*
	 * From the normalized copy, not from *s: a wildcard address has to
	 * reach Xen as XEN_ARGO_DOMID_ANY, and reading *s here would send it
	 * the raw VMADDR_CID_ANY instead - which is domain 0, dom0.
	 */
	d->domain_id = c.svm_cid;
	d->aport = c.svm_port;
	d->pad = 0;

	return 0;
}

/*
 * Release the ring's reference on its owning socket. A ring outlives the
 * socket that registered it - accepted children keep it alive - so the socket
 * recv_cb dereferences has to be pinned for exactly as long as the ring is.
 */
static void argo_transport_priv_put(void *priv)
{
	struct vsock_sock *vsk = priv;

	sock_put(&vsk->sk);
}

static int argo_ring_send_skb(struct argo_ring_hnd *h,
			      const struct sk_buff *skb,
			      xen_argo_send_addr_t *send, uint32_t msg_type)
{
	xen_argo_iov_t iov;

	/*
	 * No local check for room in the destination ring: h is *our* receive
	 * ring, not the peer's, so it says nothing about whether the send can
	 * succeed - and now that the receive path back-pressures by leaving
	 * data in the ring, our own ring is routinely full while the peer's is
	 * empty. Xen is authoritative here and returns -EAGAIN if the target is
	 * full.
	 */
	iov.iov_hnd = (uint64_t)skb->data;
	iov.iov_len = skb->len;
	iov.pad = 0;

	return argo_ring_send(h, &iov, send, msg_type);
}

/*
 * Queue a received ARGO_MSG_DATA message on a stream socket, and implement
 * the only flow control this transport has.
 *
 * Returning -ENOBUFS tells the ring layer to stop draining and hand the skb
 * back untouched, which leaves the message in the ring and blocks the sender
 * in sendv(). Without it a fast sender makes the receiver queue without bound
 * until it runs out of memory.
 *
 * Caller holds the socket lock.
 */
static int argo_transport_queue_data(struct sock *sk, struct sk_buff *skb)
{
	struct vsock_sock *vsk = vsock_sk(sk);
	struct argo_transport *t = argo_trans(vsk);
	size_t payload = skb->len - sizeof(struct xen_argo_ring_message_header);

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		return -ECONNRESET;

	/*
	 * Over the limit, but an empty queue accepts regardless: a message
	 * larger than buffer_size would otherwise never be taken and would
	 * block the ring forever.
	 */
	if (t->rx_bytes && t->rx_bytes + payload > vsk->buffer_size)
		return -ENOBUFS;

	skb_pull(skb, sizeof(struct xen_argo_ring_message_header));
	ARGO_SKB_CB(skb)->offset = 0;
	t->rx_bytes += skb->len;
	skb_queue_tail(&sk->sk_receive_queue, skb);

	sk->sk_data_ready(sk);

	return 0;
}

/*
 * Connections.
 */

static int argo_transport_stream_recv_cb(void *priv, void *data);
static int argo_transport_stream_listener_cb(void *priv, void *data);

static int argo_transport_stream_listen(struct vsock_sock *vsk)
{
	struct argo_transport *t = argo_trans(vsk);
	struct sockaddr_vm *addr = &vsk->local_addr;
	int rc;

	/* addr aliases vsk->local_addr, so this normalizes it in place. */
	if (sockaddr_vm_normalize(addr))
		return -EINVAL;

	sock_hold(&vsk->sk);
	t->h = argo_ring_handle_alloc(addr->svm_cid, addr->svm_port,
				      argo_transport_stream_listener_cb,
				      argo_transport_priv_put, vsk);
	if (IS_ERR(t->h)) {
		rc = PTR_ERR(t->h);
		/*
		 * Leaving the error pointer behind would get it dereferenced
		 * by release(), which only checks that t->h is non-NULL.
		 */
		t->h = NULL;
		sock_put(&vsk->sk);
		return rc;
	}

	rc = argo_ring_register(t->h);
	if (rc) {
		argo_ring_handle_put(t->h);
		t->h = NULL;
		return rc;
	}

	return 0;
}

/*
 * A SYN arrived on a listening socket's ring: create the child that will own
 * this connection, answer it, and put it on the accept queue.
 */
static int argo_stream_handle_syn(struct vsock_sock *vsk, struct sk_buff *skb,
				  const struct sockaddr_vm *local_addr,
				  const struct sockaddr_vm *remote_addr)
{
	struct xen_argo_ring_message_header *hdr = (void *)skb->data;
	struct sock *sk = &vsk->sk;
	struct vsock_sock *child_vsk;
	struct sk_buff *reply_skb;
	xen_argo_send_addr_t reply_addr;
	struct sock *child;
	int rc;

	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN) {
		release_sock(sk);
		return -ECONNREFUSED;
	}
	if (sk_acceptq_is_full(sk)) {
		pr_warn("Accept queue full for dom%u:%u, dropping SYN.\n",
			hdr->source.domain_id, hdr->source.aport);
		release_sock(sk);
		return -ENOMEM;
	}
	if (sk->sk_shutdown == SHUTDOWN_MASK) {
		release_sock(sk);
		return -ESHUTDOWN;
	}

	child = vsock_create_connected(sk);
	if (!child) {
		release_sock(sk);
		return -ENOMEM;
	}

	/*
	 * vsock_create_connected() hands back an unlocked socket. The
	 * ordering documented in af_vsock.c is listener first, then the
	 * pending child nested, so lockdep does not read the second
	 * lock of the same class as recursion.
	 */
	lock_sock_nested(child, SINGLE_DEPTH_NESTING);

	child->sk_state = TCP_ESTABLISHED;

	child_vsk = vsock_sk(child);
	vsock_addr_init(&child_vsk->local_addr, local_addr->svm_cid,
			local_addr->svm_port);
	vsock_addr_init(&child_vsk->remote_addr, remote_addr->svm_cid,
			remote_addr->svm_port);
	/*
	 * vsock_assign_transport() hands a remote CID of VMADDR_CID_LOCAL to
	 * vsock_loopback unless this flag is set, and VMADDR_CID_LOCAL is 1,
	 * which is an ordinary domain id here. An application that connects
	 * can set the flag itself; one that is connected to has no address to
	 * set it on until accept() returns, so the transport sets it.
	 */
	child_vsk->remote_addr.svm_flags |= VMADDR_FLAG_NO_LOCAL;

	rc = vsock_assign_transport(child_vsk, vsk);
	if (rc) {
		release_sock(child);
		sock_put(child);
		release_sock(sk);
		return rc;
	}

	/*
	 * The child answers on the listener's ring, so it holds a
	 * reference of its own: closing the listener first must not
	 * take the ring away from an established connection.
	 */
	argo_ring_handle_get(argo_trans(vsk)->h);
	argo_trans(child_vsk)->h = argo_trans(vsk)->h;

	/*
	 * Answer before the child goes on the accept queue: from that
	 * point userspace can accept() and close() it, and the
	 * addresses read here would be gone.
	 */
	reply_skb = alloc_skb(0, GFP_ATOMIC);
	if (reply_skb) {
		sockaddrvm_to_argo(&child_vsk->remote_addr,
				   &reply_addr.dst);
		sockaddrvm_to_argo(&child_vsk->local_addr,
				   &reply_addr.src);

		rc = argo_ring_send_skb(argo_trans(vsk)->h, reply_skb,
					&reply_addr, ARGO_MSG_SYN_ACK);
		kfree_skb(reply_skb);
		if (rc < 0)
			pr_warn("Failed to send SYN-ACK to dom%u:%u\n",
				hdr->source.domain_id,
				hdr->source.aport);
	}

	vsock_insert_connected(child_vsk);

	vsock_enqueue_accept(sk, child);
	sk_acceptq_added(sk);

	release_sock(child);

	sk->sk_data_ready(sk);
	release_sock(sk);

	return 0;
}

static int argo_transport_stream_listener_cb(void *priv, void *data)
{
	struct vsock_sock *vsk = priv;
	struct sk_buff *skb = data;
	struct xen_argo_ring_message_header *hdr = (void *)skb->data;
	struct sock *connected_sk;
	struct sockaddr_vm remote_addr;
	struct sockaddr_vm local_addr;
	int rc;

	vsock_addr_init(&remote_addr, hdr->source.domain_id, hdr->source.aport);
	vsock_addr_init(&local_addr, vsk->local_addr.svm_cid,
			vsk->local_addr.svm_port);

	if (hdr->message_type == ARGO_MSG_SYN)
		return argo_stream_handle_syn(vsk, skb, &local_addr,
					      &remote_addr);

	connected_sk = vsock_find_connected_socket(&remote_addr, &local_addr);
	if (!connected_sk) {
		pr_warn_ratelimited("No connected socket found for dom%u:%u\n",
				    remote_addr.svm_cid, remote_addr.svm_port);
		return -ECONNRESET;
	}

	lock_sock(connected_sk);

	if (hdr->message_type == ARGO_MSG_FIN) {
		/*
		 * The peer will send nothing more, which is not the same as
		 * the connection being over: what it sent before finishing is
		 * still on the receive queue, and af_vsock hands that to the
		 * reader before the end-of-file. It only does so while the
		 * socket is connected, though - recvmsg() checks the state
		 * before it looks at the queue - so the state stays as it is
		 * and only the peer's direction is recorded.
		 */
		vsock_sk(connected_sk)->peer_shutdown |= SEND_SHUTDOWN;
		connected_sk->sk_state_change(connected_sk);
		release_sock(connected_sk);
		sock_put(connected_sk);
		return 0;
	}

	rc = argo_transport_queue_data(connected_sk, skb);
	release_sock(connected_sk);
	sock_put(connected_sk);

	return rc;
}

static int argo_transport_stream_recv_cb(void *priv, void *data)
{
	struct sk_buff *skb = data;
	struct vsock_sock *vsk = priv;
	struct sock *sk = &vsk->sk;
	struct xen_argo_ring_message_header *hdr = (void *)skb->data;
	int rc;

	lock_sock(sk);

	if (hdr->message_type == ARGO_MSG_SYN_ACK) {
		vsock_insert_connected(vsk);
		sk->sk_state = TCP_ESTABLISHED;
		sk->sk_socket->state = SS_CONNECTED;
		sk->sk_state_change(sk);
		release_sock(sk);
		kfree_skb(skb);
		return 0;
	}

	if (hdr->message_type == ARGO_MSG_DATA) {
		rc = argo_transport_queue_data(sk, skb);
		release_sock(sk);
		return rc;
	}

	if (hdr->message_type == ARGO_MSG_FIN) {
		vsk->peer_shutdown |= SEND_SHUTDOWN;
		sk->sk_state_change(sk);
		kfree_skb(skb);
	}
	release_sock(sk);

	return 0;
}

static int argo_transport_connect(struct vsock_sock *vsk)
{
	struct sock *sk = &vsk->sk;
	struct argo_transport *t = argo_trans(vsk);
	xen_argo_send_addr_t sendaddr;
	struct sk_buff *skb;
	int rc;

	if (sockaddr_vm_normalize(&vsk->local_addr) ||
	    sockaddr_vm_normalize(&vsk->remote_addr))
		return -EINVAL;

	if (sockaddrvm_to_argo(&vsk->local_addr, &sendaddr.src) ||
	    sockaddrvm_to_argo(&vsk->remote_addr, &sendaddr.dst))
		return -EINVAL;

	if (!vsock_addr_bound(&vsk->local_addr))
		return -EINVAL;
	if (!vsock_addr_bound(&vsk->remote_addr))
		return -EINVAL;

	/*
	 * vsock tracks socket state with the TCP state constants whatever the
	 * transport, so a connected datagram socket is TCP_ESTABLISHED too.
	 * Nothing is sent: a datagram connect() only fixes the peer address.
	 */
	if (sk->sk_type == SOCK_DGRAM) {
		sk->sk_state = TCP_ESTABLISHED;
		return 0;
	}

	/* The rest is stream only: register a ring and send the SYN. */
	sock_hold(sk);
	t->h = argo_ring_handle_alloc(vsk->local_addr.svm_cid,
				      vsk->local_addr.svm_port,
				      argo_transport_stream_recv_cb,
				      argo_transport_priv_put, vsk);
	if (IS_ERR(t->h)) {
		rc = PTR_ERR(t->h);
		t->h = NULL;
		sock_put(sk);
		return rc;
	}

	rc = argo_ring_register(t->h);
	if (rc) {
		argo_ring_handle_put(t->h);
		t->h = NULL;
		return rc;
	}

	skb = alloc_skb(0, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	rc = argo_ring_send_skb(t->h, skb, &sendaddr, ARGO_MSG_SYN);
	kfree_skb(skb);
	if (rc < 0)
		return rc;

	sk->sk_state = TCP_SYN_SENT;

	return 0;
}

/*
 * DGRAM.
 */
static int argo_transport_recv_dgram_cb(void *priv, void *data);

/*
 * Candidates tried before giving an ephemeral bind up, as
 * __vsock_bind_connectible() allows itself for connectible sockets.
 */
#define ARGO_MAX_PORT_RETRIES	24

static int argo_transport_dgram_bind(struct vsock_sock *vsk,
				     struct sockaddr_vm *addr)
{
	struct argo_transport *t = argo_trans(vsk);
	bool auto_port = addr->svm_port == VMADDR_PORT_ANY;
	unsigned int tries = auto_port ? ARGO_MAX_PORT_RETRIES : 1;
	unsigned int i;
	int rc;

	if (sockaddr_vm_normalize(addr))
		return -EINVAL;

	/*
	 * The core assigns a port itself only for connectible sockets; for
	 * datagrams it calls this callback and leaves the choice here. There
	 * is no local table of bound aports to consult - the hypervisor owns
	 * that namespace - so a candidate above the reserved range is tried
	 * rather than looked up, and registration answering -EEXIST means it
	 * was taken.
	 */
	for (i = 0; i < tries; i++) {
		if (auto_port) {
			/*
			 * get_random_u32_above() draws from (floor, U32_MAX],
			 * and U32_MAX is VMADDR_PORT_ANY: a socket given that
			 * would still read as unbound to vsock_addr_bound().
			 */
			do {
				addr->svm_port = get_random_u32_above(
							LAST_RESERVED_PORT);
			} while (addr->svm_port == VMADDR_PORT_ANY);
		}

		/*
		 * Record the address bind() settled on; the ring is named
		 * after it.
		 */
		memcpy(&vsk->local_addr, addr, sizeof(*addr));

		sock_hold(&vsk->sk);
		t->h = argo_ring_handle_alloc(addr->svm_cid, addr->svm_port,
					      argo_transport_recv_dgram_cb,
					      argo_transport_priv_put, vsk);
		if (IS_ERR(t->h)) {
			rc = PTR_ERR(t->h);
			pr_debug("argo_ring_handle_alloc(dom%u:%u) failed (%d).\n",
				 addr->svm_cid, addr->svm_port, -rc);
			t->h = NULL;
			sock_put(&vsk->sk);
			return rc;
		}

		rc = argo_ring_register(t->h);
		if (!rc)
			return 0;

		pr_debug("argo_ring_register(dom%u:%u) failed (%d).\n",
			 addr->svm_cid, addr->svm_port, -rc);

		/* argo_transport_priv_put() drops the reference taken above. */
		argo_ring_handle_put(t->h);
		t->h = NULL;

		if (rc != -EEXIST)
			return rc;
		if (!auto_port)
			return -EADDRINUSE;
	}

	return -EADDRNOTAVAIL;
}

static int argo_transport_dgram_enqueue(struct vsock_sock *vsk,
					struct sockaddr_vm *remote_addr,
					struct msghdr *msg, size_t len)
{
	xen_argo_send_addr_t sendaddr;
	struct sk_buff *skb;
	int rc = 0;

	/* TODO: Auto-bind already done? */
	if (sockaddrvm_to_argo(&vsk->local_addr, &sendaddr.src) ||
	    sockaddrvm_to_argo(remote_addr, &sendaddr.dst))
		return -EINVAL;

	/*
	 * A datagram has to fit in the fixed-size ring whole, so check the
	 * length before allocating for it: alloc_skb() with a length taken
	 * straight from userspace answers -ENOMEM, which says nothing about
	 * the limit and lets a caller ask for an arbitrarily large
	 * allocation. Xen reports -EMSGSIZE for a message the ring cannot
	 * hold; give the same answer without the allocation.
	 */
	if (len + sizeof(struct xen_argo_ring_message_header) >= ARGO_RING_LEN)
		return -EMSGSIZE;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	if (memcpy_from_msg(skb_put(skb, len), msg, len)) {
		pr_debug("%s: memcpy_from_msg failed.\n", __func__);
		rc = -EMSGSIZE;
		goto out;
	}

	rc = argo_ring_send_skb(argo_trans(vsk)->h, skb, &sendaddr,
				ARGO_MSG_DATA);
	if (rc < 0) {
		pr_debug("%s: argo_ring_send_skb failed.\n", __func__);
		goto out;
	}

	pr_debug("enqueued %zuB dom%u:%u to dom%u:%u.\n", len,
		 sendaddr.src.domain_id, sendaddr.src.aport,
		 sendaddr.dst.domain_id, sendaddr.dst.aport);

out:
	kfree_skb(skb);
	return rc;
}

static int argo_transport_recv_dgram_cb(void *priv, void *data)
{
	struct sk_buff *skb = data;
	struct vsock_sock *vsk = priv;
	struct sock *sk = &vsk->sk;
	int rc;

	/* sk_receive_skb() does sock_put(). */
	sock_hold(sk);
	rc = sk_receive_skb(sk, skb, 0);
	if (rc != NET_RX_SUCCESS)
		pr_warn("dom%u:%u cannot queue packet, dropping.\n",
			vsk->local_addr.svm_cid, vsk->local_addr.svm_port);

	return rc == NET_RX_SUCCESS ? 0 : -1;
}

static int argo_transport_dgram_dequeue(struct vsock_sock *vsk,
					struct msghdr *msg, size_t len,
					int flags)
{
	struct xen_argo_ring_message_header *mh;
	struct sk_buff *skb;
	size_t msg_len;
	int rc = 0;

	skb = skb_recv_datagram(&vsk->sk, flags & MSG_DONTWAIT, &rc);
	if (!skb) {
		pr_debug("skb_recv_datagram failed (%d).\n", rc);
		goto out;
	}

	/* Assume skb is always in linear data area for now. */
	mh = (void *)skb->data;
	if (!mh) {
		pr_debug("could not access sk_buff data to read message header, dropping packet.\n");
		goto out;
	}

	msg_len = mh->len - sizeof(*mh);
	rc = skb_copy_datagram_msg(skb, sizeof(*mh), msg, msg_len);
	if (rc)
		goto out;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_vm *, vm_addr, msg->msg_name);

		vsock_addr_init(vm_addr, mh->source.domain_id,
				mh->source.aport);
		msg->msg_namelen = sizeof(*vm_addr);
		pr_debug("dequeued: report source as dom%u:%u\n",
			 vm_addr->svm_cid, vm_addr->svm_port);
	}
	pr_debug("dequeued skb: %uB (%zuB data) from dom%u:%u\n",
		 mh->len, msg_len, mh->source.domain_id, mh->source.aport);

	rc = msg_len;
out:
	skb_free_datagram(&vsk->sk, skb);
	return rc;
}

static bool argo_transport_dgram_allow(struct vsock_sock *vsk, u32 cid,
				       u32 port)
{
	return true;
}

/*
 * STREAM.
 */
static ssize_t argo_transport_stream_dequeue(struct vsock_sock *vsk,
					     struct msghdr *msg, size_t len,
					     int flags)
{
	struct sock *sk = &vsk->sk;
	struct argo_transport *t = argo_trans(vsk);
	struct sk_buff *skb;
	size_t copied = 0;
	int err = 0;

	/*
	 * skb_copy_datagram_msg() is the generic skb-to-iovec copy and handles
	 * paged skbs; the "datagram" in its name is historical.
	 */
	if (flags & MSG_PEEK) {
		skb_queue_walk(&sk->sk_receive_queue, skb) {
			u32 off = ARGO_SKB_CB(skb)->offset;
			size_t chunk = min_t(size_t, skb->len - off,
					     len - copied);

			err = skb_copy_datagram_msg(skb, off, msg, chunk);
			if (err)
				break;

			copied += chunk;
			if (copied >= len)
				break;
		}
		goto done;
	}

	while (copied < len) {
		u32 off;
		size_t chunk;

		skb = skb_peek(&sk->sk_receive_queue);
		if (!skb)
			break;

		off = ARGO_SKB_CB(skb)->offset;
		chunk = min_t(size_t, skb->len - off, len - copied);

		err = skb_copy_datagram_msg(skb, off, msg, chunk);
		if (err)
			break;

		copied += chunk;
		t->rx_bytes -= chunk;

		if (off + chunk < skb->len) {
			ARGO_SKB_CB(skb)->offset = off + chunk;
		} else {
			skb_unlink(skb, &sk->sk_receive_queue);
			kfree_skb(skb);
		}
	}

	/*
	 * Ring consumption stops while this socket is full, and nothing else
	 * restarts it: the sender is blocked, so no further interrupt is
	 * coming. Only relevant once the worker has actually parked an skb -
	 * kicking it after every recv() costs a worker wakeup per message for
	 * nothing.
	 */
	if (copied && t->h && !skb_queue_empty(&t->h->pending_skbs))
		argo_ring_schedule_recv(t->h, 0);

done:
	if (copied)
		return copied;

	return err ? err : -EAGAIN;
}

static ssize_t argo_transport_stream_enqueue(struct vsock_sock *vsk,
					     struct msghdr *msg, size_t len)
{
	struct sock *sk = &vsk->sk;
	size_t total_len = len + sizeof(struct xen_argo_ring_message_header);
	xen_argo_send_addr_t sendaddr;
	struct sk_buff *skb;
	unsigned long deadline;
	long timeo;
	int rc = 0;

	if (sockaddrvm_to_argo(&vsk->local_addr, &sendaddr.src) ||
	    sockaddrvm_to_argo(&vsk->remote_addr, &sendaddr.dst))
		return -EINVAL;

	skb = alloc_skb(total_len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, sizeof(struct xen_argo_ring_message_header));
	if (memcpy_from_msg(skb_put(skb, len), msg, len)) {
		kfree_skb(skb);
		return -EFAULT;
	}
	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	/*
	 * An absolute deadline, taken once. Subtracting the sleep from timeo on
	 * each pass cannot work: the shortest unit timeo is expressed in is one
	 * jiffy, which is 1ms at HZ=1000 and 4ms at HZ=250, so a ~100us sleep
	 * would retire SO_SNDTIMEO ten to forty times too fast.
	 */
	deadline = timeo == MAX_SCHEDULE_TIMEOUT ? 0 : jiffies + timeo;

	for (;;) {
		rc = argo_ring_send_skb(argo_trans(vsk)->h, skb, &sendaddr,
					ARGO_MSG_DATA);
		if (rc >= 0)
			break;
		if (rc != -EAGAIN && rc != -ENOBUFS)
			break;
		if (!timeo || (deadline && time_after_eq(jiffies, deadline))) {
			rc = -EAGAIN;
			break;
		}

		/*
		 * Argo gives no notification when the peer's ring drains -
		 * there is no credit exchange - so there is nothing to sleep
		 * on. Poll, dropping the socket lock so the receive path can
		 * make progress meanwhile.
		 */
		release_sock(sk);
		usleep_range(50, 150);
		lock_sock(sk);

		if (sk->sk_err) {
			rc = -sk->sk_err;
			break;
		}
		if (sk->sk_shutdown & SEND_SHUTDOWN) {
			rc = -EPIPE;
			break;
		}
	}

	kfree_skb(skb);

	if (rc < 0)
		return rc;

	return len;
}

static s64 argo_transport_stream_has_data(struct vsock_sock *vsk)
{
	return argo_trans(vsk)->rx_bytes;
}

static s64 argo_transport_stream_has_space(struct vsock_sock *vsk)
{
	/*
	 * How much the peer can take is not knowable without a credit exchange
	 * (XEN_ARGO_OP_notify would cost a hypercall per poll). Reporting our
	 * own ring's free space would be wrong: that is the receive direction,
	 * and returning 0 here parks sendmsg() on a wait queue that nothing
	 * wakes.
	 *
	 * Report the ring size and let stream_enqueue() do the real blocking
	 * against Xen's -EAGAIN.
	 */
	return ARGO_RING_LEN - ARGO_RING_ALIGN(1) -
	       sizeof(struct xen_argo_ring_message_header);
}

static u64 argo_transport_stream_rcvhiwat(struct vsock_sock *vsk)
{
	return vsk->buffer_size;
}

static bool argo_transport_stream_is_active(struct vsock_sock *vsk)
{
	return true;
}

static bool argo_transport_stream_allow(struct vsock_sock *vsk, u32 cid,
					u32 port)
{
	return true;
}

/*
 * Notification.
 */
static int argo_transport_notify_poll_in(struct vsock_sock *vsk, size_t target,
					 bool *data_ready_now)
{
	*data_ready_now = vsock_stream_has_data(vsk);
	return 0;
}

static int argo_transport_notify_poll_out(struct vsock_sock *vsk, size_t target,
					  bool *space_available_now)
{
	*space_available_now = vsock_stream_has_space(vsk);
	return 0;
}

static int argo_transport_notify_recv_init(struct vsock_sock *vsk, size_t target,
					   struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int argo_transport_notify_recv_pre_block(struct vsock_sock *vsk, size_t target,
						struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int argo_transport_notify_recv_pre_dequeue(struct vsock_sock *vsk, size_t target,
						  struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int argo_transport_notify_recv_post_dequeue(struct vsock_sock *vsk, size_t target,
						   ssize_t copied, bool data_read,
						   struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int argo_transport_notify_send_init(struct vsock_sock *vsk,
					   struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int argo_transport_notify_send_pre_block(struct vsock_sock *vsk,
						struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int argo_transport_notify_send_pre_enqueue(struct vsock_sock *vsk,
						  struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int argo_transport_notify_send_post_enqueue(struct vsock_sock *vsk, ssize_t written,
						   struct vsock_transport_send_notify_data *data)
{
	return 0;
}

/*
 * Shutdown.
 */
/*
 * Tell the peer this end is finished, once. Only a connected stream socket
 * has anywhere to send it: a datagram socket has no peer state to end, and a
 * listener's remote address is unset.
 */
static void argo_send_fin(struct vsock_sock *vsk)
{
	struct argo_transport *t = argo_trans(vsk);
	xen_argo_send_addr_t addr;
	struct sk_buff *skb;

	if (t->fin_sent || !t->h)
		return;
	if (vsk->sk.sk_type != SOCK_STREAM)
		return;
	if (!vsock_addr_bound(&vsk->remote_addr))
		return;

	skb = alloc_skb(0, GFP_KERNEL);
	if (!skb)
		return;

	sockaddrvm_to_argo(&vsk->remote_addr, &addr.dst);
	sockaddrvm_to_argo(&vsk->local_addr, &addr.src);
	argo_ring_send_skb(t->h, skb, &addr, ARGO_MSG_FIN);
	kfree_skb(skb);

	t->fin_sent = true;
}

static int argo_transport_shutdown(struct vsock_sock *vsk, int mode)
{
	argo_send_fin(vsk);

	return 0;
}

static u32 argo_transport_get_local_cid(void)
{
	/* The Argo CID is the Xen domain id. */
	return xen_get_domid();
}

static struct vsock_transport argo_transport = {
	.module = THIS_MODULE,

	.init = argo_transport_socket_init,
	.destruct = argo_transport_destruct,
	.release = argo_transport_release,

	.connect = argo_transport_connect,
	.listen = argo_transport_stream_listen,

	.dgram_bind = argo_transport_dgram_bind,
	.dgram_dequeue = argo_transport_dgram_dequeue,
	.dgram_enqueue = argo_transport_dgram_enqueue,
	.dgram_allow = argo_transport_dgram_allow,

	.stream_dequeue = argo_transport_stream_dequeue,
	.stream_enqueue = argo_transport_stream_enqueue,
	.stream_has_data = argo_transport_stream_has_data,
	.stream_has_space = argo_transport_stream_has_space,
	.stream_rcvhiwat = argo_transport_stream_rcvhiwat,
	.stream_is_active = argo_transport_stream_is_active,
	.stream_allow = argo_transport_stream_allow,

	.notify_poll_in = argo_transport_notify_poll_in,
	.notify_poll_out = argo_transport_notify_poll_out,
	.notify_recv_init = argo_transport_notify_recv_init,
	.notify_recv_pre_block = argo_transport_notify_recv_pre_block,
	.notify_recv_pre_dequeue = argo_transport_notify_recv_pre_dequeue,
	.notify_recv_post_dequeue = argo_transport_notify_recv_post_dequeue,
	.notify_send_init = argo_transport_notify_send_init,
	.notify_send_pre_block = argo_transport_notify_send_pre_block,
	.notify_send_pre_enqueue = argo_transport_notify_send_pre_enqueue,
	.notify_send_post_enqueue = argo_transport_notify_send_post_enqueue,

	.shutdown = argo_transport_shutdown,

	.get_local_cid = argo_transport_get_local_cid,
};

static int __init argo_transport_init(void)
{
	int rc;

	rc = vsock_core_register(&argo_transport, VSOCK_TRANSPORT_F_DGRAM);
	if (rc) {
		pr_err("vsock_core_register(DGRAM) failed (%d).\n", rc);
		return rc;
	}

	rc = vsock_core_register(&argo_transport, VSOCK_TRANSPORT_F_G2H);
	if (rc) {
		pr_err("vsock_core_register(G2H) failed (%d).\n", rc);
		vsock_core_unregister(&argo_transport);
		return rc;
	}

	rc = argo_core_init();
	if (rc) {
		pr_err("argo_core_init() failed (%d).\n", rc);
		vsock_core_unregister(&argo_transport);
		return rc;
	}

	pr_debug("registered.\n");

	return 0;
}
module_init(argo_transport_init);

static void __exit argo_transport_exit(void)
{
	argo_core_cleanup();
	vsock_core_unregister(&argo_transport);
	pr_debug("unregistered.\n");
}
module_exit(argo_transport_exit);

MODULE_DESCRIPTION("Argo transport for Virtual Socket.");
MODULE_VERSION("1.0.0");
MODULE_LICENSE("GPL");
MODULE_ALIAS("argo_vsock");
