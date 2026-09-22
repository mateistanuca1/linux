// SPDX-License-Identifier: GPL-2.0-only
/*
 * Argo transport for Virtual Sockets.
 *
 * Copyright (c) Assured Information Security, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/kmod.h>
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
	struct list_head sockets;	/* List of all argo_transport. */
	struct argo_ring_hnd *h;	/* Argo ring handle. */
	struct vsock_sock *vsk;		/* Parent vsock struct. */
	/*
	 * Bytes sitting in sk_receive_queue. Maintained under lock_sock, which
	 * both the receive worker and the reader hold. Kept as a counter rather
	 * than walked on demand: stream_has_data() is called on every recvmsg()
	 * and every poll(), and walking a deep queue there is quadratic.
	 */
	u32 rx_bytes;
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
 * Global socket list.
 */
static struct list_head sockets = LIST_HEAD_INIT(sockets);

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

	INIT_LIST_HEAD(&t->sockets);
	list_add_tail(&t->sockets, &sockets);
	t->vsk = vsk;
	t->h = NULL;
	t->rx_bytes = 0;

	vsk->trans = t;

	return 0;
}

static void argo_transport_destruct(struct vsock_sock *vsk)
{
	argo_trans(vsk)->vsk = NULL;
	list_del_init(&argo_trans(vsk)->sockets);
	kfree(argo_trans(vsk));
	vsk->trans = NULL;
}

static void argo_transport_release(struct vsock_sock *vsk)
{
	struct argo_transport *t = argo_trans(vsk);

	vsock_remove_sock(vsk);

	/*
	 * Disconnect/Detach before release of resources:
	 * TODO: Send RST for STREAM.
	 */

	if (t->h) {
		argo_ring_handle_put(t->h);
		t->h = NULL;
	}
}

/*
 * VSock VMADDR_CID_ANY & VMADDR_PORT_ANY do not match Argo definitions.
 * Convert sockaddr_vm to sockaddr_vm argo compatible:
 * - CID: 0 -> XEN_ARGO_DOMID_ANY.
 * - PORT: 0 -> ~0U - 1 ?
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
	 * From the normalised copy, not from *s: a wildcard address has to
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

static int argo_transport_connect(struct vsock_sock *vsk)
{
	struct sock *sk = &vsk->sk;
	xen_argo_send_addr_t sendaddr;

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

	sk->sk_state = TCP_ESTABLISHED;

	return 0;
}

/*
 * DGRAM.
 */
static int argo_transport_recv_dgram_cb(void *priv, void *data);

static int argo_transport_dgram_bind(struct vsock_sock *vsk,
				     struct sockaddr_vm *addr)
{
	struct argo_transport *t = argo_trans(vsk);
	int rc;

	if (sockaddr_vm_normalize(addr))
		return -EINVAL;

	/* Auto-bind local_addr. */
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
	if (rc) {
		pr_debug("argo_ring_register(dom%u:%u) failed (%d).\n",
			 addr->svm_cid, addr->svm_port, -rc);
		argo_ring_handle_put(t->h);
		t->h = NULL;
		return rc;
	}

	return 0;
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

static u32 argo_transport_get_local_cid(void)
{
	/* TODO: May require svm_cid format instead of Argo. */
	return argo_get_local_cid();
}

static struct vsock_transport argo_transport = {
	.init = argo_transport_socket_init,
	.destruct = argo_transport_destruct,
	.release = argo_transport_release,

	.connect = argo_transport_connect,

	.dgram_bind = argo_transport_dgram_bind,
	.dgram_dequeue = argo_transport_dgram_dequeue,
	.dgram_enqueue = argo_transport_dgram_enqueue,
	.dgram_allow = argo_transport_dgram_allow,

	.get_local_cid = argo_transport_get_local_cid,
};

/*
 * IRQ handler. Kicks the receive worker of every ring that has data.
 */
static irqreturn_t argo_interrupt(int irq, void *dev_id)
{
	struct argo_ring_hnd *h, *tmp;

	read_lock(&argo_rings_lock);
	list_for_each_entry_safe(h, tmp, &argo_rings, l) {
		if (argo_ring_has_data(h) >=
		    sizeof(struct xen_argo_ring_message_header)) {
			argo_ring_schedule_recv(h, 0);
		}
	}
	read_unlock(&argo_rings_lock);

	return IRQ_HANDLED;
}

static int __init argo_transport_init(void)
{
	int rc;

	rc = vsock_core_register(&argo_transport, VSOCK_TRANSPORT_F_DGRAM);
	if (rc)
		pr_err("vsock_core_register(DGRAM) failed (%d).\n", rc);

	rc = vsock_core_register(&argo_transport, VSOCK_TRANSPORT_F_G2H);
	if (rc)
		pr_err("vsock_core_register(G2H) failed (%d).\n", rc);

	rc = argo_core_init(argo_interrupt);
	if (rc) {
		pr_err("argo_core_init() failed (%d).\n", rc);
		vsock_core_unregister(&argo_transport);
		return rc;
	}

	pr_info("registered.\n");

	return 0;
}
module_init(argo_transport_init);

static void __exit argo_transport_exit(void)
{
	/* TODO: Flush sockets... */
	argo_core_cleanup();
	vsock_core_unregister(&argo_transport);
	pr_info("unregistered.\n");
}
module_exit(argo_transport_exit);

MODULE_AUTHOR("Assured Information Security, Inc.");
MODULE_DESCRIPTION("Argo transport for Virtual Socket.");
MODULE_VERSION("1.0.0");
MODULE_LICENSE("GPL");
MODULE_ALIAS("argo_vsock");
MODULE_ALIAS_NETPROTO(argo_vsock);
