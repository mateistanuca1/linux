#include <linux/types.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <xen/xen.h>
#include <xen/interface/xen.h>
#include <xen/xenbus.h>


#include <net/sock.h>
#include <net/af_vsock.h>
#include <net/vsock_addr.h>

#include <xen/argo/argo_ring.h>
/*
 * Argo auto-bind default address.
 */
static const struct sockaddr_vm addr_auto = {
    .svm_family = AF_VSOCK,
    .svm_cid = XEN_ARGO_DOMID_ANY,
    .svm_port = 0,
    .svm_zero = { 0 },
};

/*
 * Argo private data.
 */
struct argo_transport {
    struct list_head sockets;	/* List of all argo_transport. */
    struct argo_ring_hnd *h;	/* Argo ring handle. */
    struct vsock_sock *vsk;		/* Parent vsock struct. */
};

/*
 * Global socket list.
 */
struct list_head sockets = LIST_HEAD_INIT(sockets);

/*
 * Private data helpers.
 */
#define argo_trans(vsk)	((struct argo_transport *)((vsk)->trans))

/*
 * Initialize/Tear-down socket.
 */
static int argo_transport_socket_init(
    struct vsock_sock *vsk, struct vsock_sock *psk)
{
    vsk->trans = kmalloc(sizeof (struct argo_transport), GFP_KERNEL);
    if (!vsk->trans) {
        return -ENOMEM;
    }
    INIT_LIST_HEAD(&argo_trans(vsk)->sockets);
    list_add_tail(&argo_trans(vsk)->sockets, &sockets);
    argo_trans(vsk)->vsk = vsk;
    argo_trans(vsk)->h = NULL;

    return 0;
}

static void argo_transport_destruct(struct vsock_sock *vsk)
{
    argo_trans(vsk)->vsk = NULL;
    list_del_init(&argo_trans(vsk)->sockets);
    kfree(argo_trans(vsk));
    vsk->trans = NULL;

    return;
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
        argo_ring_unregister(t->h);
        argo_ring_handle_free(t->h);
    }
}

/*
 * VSock VMADDR_CID_ANY & VMADDR_PORT_ANY do not match Argo definitions.
 * Convert sockaddr_vm to sockaddr_vm argo compatible:
 * - CID: 0 -> XEN_ARGO_DOMID_ANY.
 * - PORT: 0 -> ~0U - 1 ?
 */
static inline int sockaddr_vm_normalize(struct sockaddr_vm *addr)
{
    if (addr->svm_cid == VMADDR_CID_ANY) {
        addr->svm_cid = addr_auto.svm_cid;
    }
    if (addr->svm_port == VMADDR_PORT_ANY) {
        addr->svm_port = addr_auto.svm_port;
    }

    if (addr->svm_cid > XEN_ARGO_DOMID_ANY) {
        return EINVAL;
    }

    return 0;
}
static inline int sockaddrvm_to_argo(const struct sockaddr_vm *s, xen_argo_addr_t *d)
{
    struct sockaddr_vm c = *s;

    if (sockaddr_vm_normalize(&c)) {
        return EINVAL;
    }

    d->domain_id = s->svm_cid;
    d->aport = s->svm_port;
    d->pad = 0;

    return 0;
}

static inline bool sockaddr_vm_match(const struct sockaddr_vm *src,
                                     const struct sockaddr_vm *dst)
{
    return ((src->svm_cid == dst->svm_cid) &&
            (src->svm_port == dst->svm_port));
}


static struct sk_buff *argo_ring_recv_skb(struct argo_ring_hnd *h)
{
	const struct xen_argo_ring_message_header *mh;
	struct sk_buff *skb;
	size_t msg_len;
	int rc = 0;

	/* There is at least a header. */
	skb = alloc_skb(sizeof (*mh), GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	/* FIXME: ring_lock.
	 * Tasklet can only be ran on one CPU (while it may be scheduled by
	 * more than one). This lock is useless, right?
	 */
	spin_lock(&h->ring_lock);
	argo_ring_recv(h, skb_put(skb, sizeof (*mh)), sizeof (*mh));

	mh = (void*)skb->data;
	msg_len = mh->len - sizeof (*mh);

	if (unlikely(msg_len > argo_ring_has_data(h))) {
		pr_debug("Invalid packet, message size exceeds ring capacity.");
		rc = E2BIG;
		goto out;
	}

	if (msg_len) {
		/* Data in this packet. */
		if (pskb_expand_head(skb, 0, msg_len, GFP_ATOMIC)) {
			pr_debug("Failed to allocate skb to receive message.");
			rc = ENOMEM;
			goto out;
		}
		argo_ring_recv(h, skb_put(skb, msg_len), msg_len);
	}
	/* FIXME: See ring_lock above. */
	spin_unlock(&h->ring_lock);

	return skb;

out:
	spin_unlock(&h->ring_lock);
	kfree_skb(skb);
	return ERR_PTR(-rc);
}

static int argo_ring_send_skb(struct argo_ring_hnd *h, const struct sk_buff *skb,
		xen_argo_send_addr_t *send, uint32_t msg_type)
{
	xen_argo_iov_t iov;

	if (argo_ring_has_space(h) <
		ARGO_RING_ALIGN(skb->len +
			sizeof (struct xen_argo_ring_message_header))) {
		pr_debug("%s: Insuficient space in target ring.\n", __func__);
		return -ENOBUFS;
	}

	iov.iov_hnd = (uint64_t)skb->data;
	iov.iov_len = skb->len;
	iov.pad = 0;

	/* TODO: Message-type is forced to 0 here. */
	return argo_ring_send(h, &iov, send, msg_type);
}



/*
 * Connections.
 */

// static int argo_transport_stream_recv_cb(void *priv, struct sk_buff *skb);
// static int argo_transport_stream_connect_recv_cb(void *priv, struct sk_buff *skb);

// static int argo_transport_stream_bind(struct vsock_sock *vsk, struct sockaddr_vm *addr)
// {
//     printk(KERN_INFO "argo_transport_stream_bind called");
//     struct argo_transport *t = argo_trans(vsk);
//     int rc;
//     if (sockaddr_vm_normalize(addr)) {
//         return EINVAL;
//     }

//     memcpy(&vsk->local_addr, addr, sizeof (*addr));

//     t->h = argo_ring_handle_alloc(addr->svm_cid, addr->svm_port,
//                                   argo_transport_stream_connect_recv_cb, vsk);
//     if (IS_ERR(t->h)) {
//         rc = PTR_ERR(t->h);
//         return rc;
//     }
//     rc = argo_ring_register(t->h);
//     if (rc) {
//         argo_ring_handle_free(t->h);
//         t->h = NULL;
//         return rc;
//     }
//     return 0;
// }

// static int argo_transport_stream_connect_recv_cb(void *priv, struct sk_buff *skb)
// {
//     struct vsock_sock *vsk = priv;
//     struct sock *sk = &vsk->sk;
//     int rc;
//     struct xen_argo_ring_message_header *hdr;
//     hdr = (struct xen_argo_ring_message_header *)skb->data;

//     struct sockaddr_vm remote_addr;
//     struct sock *connected_sk = NULL;
//     int rc;



//     if (hdr->message_type == XEN_ARGO_SEND_SYN) {
//         printk(KERN_INFO "Received SYN from dom%u:%u \n", hdr->source.domain_id, hdr->source.aport);
//         if(sk_acceptq_is_full(sk)) {
//             return -ENOMEM;
//         }
//         if (sk->sk_shutdown == SHUTDOWN_MASK) {
//             return -ESHUTDOWN;
//         }
//         struct sock *child;
//         child = vsock_create_connected(sk);
//         if(!child) {
//             return -ENOMEM;
//         }
//         printk(KERN_INFO "Created child socket for dom%u:%u \n", hdr->source.domain_id, hdr->source.aport);

//         lock_sock_nested(sk, SINGLE_DEPTH_NESTING);
//         child->sk_state = TCP_ESTABLISHED;
//         struct vsock_sock *child_vsk = vsock_sk(child);
//         vsock_addr_init(&child_vsk->local_addr,
//                         vsk->local_addr.svm_cid,
//                         vsk->local_addr.svm_port);
//         vsock_addr_init(&child_vsk->remote_addr,
//                         hdr->source.domain_id, hdr->source.aport);
//         rc = vsock_assign_transport(child_vsk, vsk);
//         if (rc) {
//             release_sock(child);
//             sock_put(child);
//             return rc;
//         }

//         vsock_enqueue_accept(sk, child);
//         release_sock(sk);

//         printk(KERN_INFO "Created child socket\n");


//     }

//     // connected_sk = vsock_find_connected_socket(sk->)

//                    return 0;

// }

// static int argo_transport_stream_recv_cb(void *priv, struct sk_buff *skb)
// {
//     struct vsock_sock *vsk = priv;
//     struct sock *sk = &vsk->sk;
//     int rc;

//     /* sk_receive_skb() does sock_put(). */
//     sock_hold(sk);
//     rc = sk_receive_skb(sk, skb, 0);
//     if (rc != NET_RX_SUCCESS)
//         pr_warn("dom%u:%u cannot queue packet, dropping.",
//                 vsk->local_addr.svm_cid,
//                 vsk->local_addr.svm_port);
//     return rc == NET_RX_SUCCESS ? 0 : -1;
// }

// static int argo_transport_connect(struct vsock_sock *vsk)
// {

//     struct sock *sk = &vsk->sk;
//     struct argo_transport *t = argo_trans(vsk);
//     xen_argo_send_addr_t sendaddr;
//     int rc;


//     if (sockaddr_vm_normalize(&vsk->local_addr) ||
//             sockaddr_vm_normalize(&vsk->remote_addr)) {
//         return -EINVAL;
//     }

//     if (sockaddrvm_to_argo(&vsk->local_addr, &sendaddr.src) ||
//             sockaddrvm_to_argo(&vsk->remote_addr, &sendaddr.dst)) {
//         return -EINVAL;
//     }

//     if (!vsock_addr_bound(&vsk->local_addr)) {
//         return -EINVAL;
//     }
//     if (!vsock_addr_bound(&vsk->remote_addr)) {
//         return -EINVAL;
//     }

//     if(sk->sk_type == SOCK_DGRAM) {
//         sk->sk_state = TCP_ESTABLISHED;
//         return 0;
//     }

//     /* TODO: STREAM will require SYN/ACK dance here.
//      *	 DGRAM requires nothing right? */

//     //registering a ring for client side
//     printk(KERN_INFO "connect used");
//     t->h = argo_ring_handle_alloc(vsk->remote_addr.svm_cid,
//                                   vsk->remote_addr.svm_port,
//                                   argo_transport_stream_recv_cb,
//                                   vsk);
//     if (IS_ERR(t->h)) {
//         printk(KERN_INFO "argo_ring_handle_alloc failed");
//         rc = PTR_ERR(t->h);
//         pr_debug("argo_ring_handle_alloc");
//         return rc;
//     }
//     rc = argo_ring_register(t->h);
//     if (rc) {
//         printk(KERN_INFO "argo_ring_register failed");
//         pr_debug("argo_ring_register");
//         argo_ring_handle_free(t->h);
//         t->h = NULL;
//         return rc;
//     }
//     printk(KERN_INFO "ring success");

//     //Sending SYN
//     struct sk_buff *skb;
//     skb = alloc_skb(1, GFP_ATOMIC);
//     if (!skb) {
//         pr_debug("%s: alloc_skb failed.\n", __func__);
//         return -ENOMEM;
//     }

//     printk(KERN_INFO "SYN preparing to send");

//     // Fill in the SYN packet header

//     printk(KERN_INFO "SYN prepared, sending");

//     rc = argo_ring_send_skb(t->h, skb, &sendaddr, XEN_ARGO_SEND_SYN);
//     if (rc < 0) {
//         printk(KERN_INFO "argo_ring_send_skb failed");
//         kfree_skb(skb);
//         return rc;
//     }
//     printk(KERN_INFO "SYN sent successfully");


//     sk->sk_state = TCP_ESTABLISHED;
//     return 0;
// }


/*
 * DGRAM.
 */
static int argo_transport_recv_dgram_cb(void *priv, void *data);
static int argo_transport_dgram_bind(struct vsock_sock *vsk,
                                     struct sockaddr_vm *addr)
{

    printk(KERN_INFO "argo_transport_dgram_bind called for dom%u:%u\n",
           addr->svm_cid, addr->svm_port);
    struct argo_transport *t = argo_trans(vsk);
    int rc;

    if (sockaddr_vm_normalize(addr)) {
        return EINVAL;
    }

    /* Auto-bind local_addr. */
    memcpy(&vsk->local_addr, addr, sizeof (*addr));

    t->h = argo_ring_handle_alloc(addr->svm_cid, addr->svm_port,
                                  argo_transport_recv_dgram_cb, vsk);
    if (IS_ERR(t->h)) {
        rc = PTR_ERR(t->h);
        pr_debug("argo_ring_handle_alloc(dom%u:%u) %s (%d).\n",
                 addr->svm_cid, addr->svm_port,
                 rc ? "failed" : "succeed", -rc);
        goto failed_alloc;
    }

    rc = argo_ring_register(t->h);
    if (rc) {
        pr_debug("argo_ring_register(dom%u:%u) %s (%d).\n",
                 addr->svm_cid, addr->svm_port,
                 rc ? "failed" : "succeed", -rc);
        goto failed_register;
    }

    return 0;

failed_register:
    argo_ring_handle_free(t->h);
    t->h = NULL;
failed_alloc:
    return rc;
}

static int argo_transport_dgram_enqueue(struct vsock_sock *vsk,
                                        struct sockaddr_vm *remote_addr, struct msghdr *msg, size_t len)
{
    int rc = 0;
    struct sk_buff *skb;
    xen_argo_send_addr_t sendaddr;

    /* TODO: Auto-bind already done? */
    if (sockaddrvm_to_argo(&vsk->local_addr, &sendaddr.src) ||
            sockaddrvm_to_argo(remote_addr, &sendaddr.dst)) {
        return EINVAL;
    }

    skb = alloc_skb(len, GFP_ATOMIC);
    if (!skb) {
        pr_debug("%s: alloc_skb failed.\n", __func__);
        return -ENOMEM;
    }

    if (memcpy_from_msg(skb_put(skb, len), msg, len)) {
        pr_debug("%s: memcpy_from_msg failed.\n", __func__);
        rc = -EMSGSIZE;
        goto out;
    }

    rc = argo_ring_send_skb(argo_trans(vsk)->h, skb, &sendaddr, 0);
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
        pr_warn("dom%u:%u cannot queue packet, dropping.",
                vsk->local_addr.svm_cid,
                vsk->local_addr.svm_port);
    return rc == NET_RX_SUCCESS ? 0 : -1;
}

static int argo_transport_dgram_dequeue(struct vsock_sock *vsk,
                                        struct msghdr *msg, size_t len, int flags)
{
    struct sk_buff *skb;
    struct xen_argo_ring_message_header *mh;
    size_t msg_len;
    int rc = 0;

    skb = skb_recv_datagram(&vsk->sk, flags & MSG_DONTWAIT, &rc);
    if (!skb) {
        pr_debug("skb_recv_datagram failed (%d).\n", rc);
        goto out;
    }

    /* Assume skb is always in linear data area for now. */
    mh = (void*)skb->data;
    if (!mh) {
        pr_debug("could not access sk_buff data to read message header, dropping packet.\n");
        goto out;
    }

    msg_len = mh->len - sizeof (*mh);
    rc = skb_copy_datagram_msg(skb, sizeof (*mh), msg, msg_len);
    if (rc) {
        goto out;
    }

    if (msg->msg_name) {
        DECLARE_SOCKADDR(struct sockaddr_vm *, vm_addr, msg->msg_name);
        vsock_addr_init(vm_addr, mh->source.domain_id, mh->source.aport);
        msg->msg_namelen = sizeof (*vm_addr);
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

static bool argo_transport_dgram_allow(struct vsock_sock *vsk, u32 cid, u32 port)
{
    return true;
}


/*
 * TODO: STREAM.
 */
static ssize_t argo_transport_stream_dequeue(
    struct vsock_sock *vsk,
    struct msghdr *msg,
    size_t len,
    int flags)
{
    return -ENOTSUPP;
}

static ssize_t argo_transport_stream_enqueue(
    struct vsock_sock *vsk,
    struct msghdr *msg,
    size_t len)
{
    return -ENOTSUPP;
}

static s64 argo_transport_stream_has_data(struct vsock_sock *vsk)
{
    return -ENOTSUPP;
}

static s64 argo_transport_stream_has_space(struct vsock_sock *vsk)
{
    return -ENOTSUPP;
}

static u64 argo_transport_stream_rcvhiwat(struct vsock_sock *vsk)
{
    return -ENOTSUPP;
    /* TODO: Return high-watermark... probably something to frob around
       with. */
}

static bool argo_transport_stream_is_active(struct vsock_sock *vsk)
{
    return true;
}

static bool argo_transport_stream_allow(struct vsock_sock *vsk, u32 cid, u32 port)
{

    return true;
}

/*
 * Notification.
 */
static int argo_transport_notify_poll_in(
    struct vsock_sock *vsk,
    size_t target,
    bool *data_ready_now)
{
    *data_ready_now = vsock_stream_has_data(vsk);
    return 0;
}

static int argo_transport_notify_poll_out(
    struct vsock_sock *vsk,
    size_t target,
    bool *space_available_now)
{
    *space_available_now = vsock_stream_has_space(vsk);
    return 0;
}

static int argo_transport_notify_recv_init(
    struct vsock_sock *vsk,
    size_t target,
    struct vsock_transport_recv_notify_data *data)
{
    /* TODO: Not sure... */
    return 0;
}

static int argo_transport_notify_recv_pre_block(
    struct vsock_sock *vsk,
    size_t target,
    struct vsock_transport_recv_notify_data *data)
{
    /* TODO: Not sure... */
    return 0;
}

static int argo_transport_notify_recv_pre_dequeue(
    struct vsock_sock *vsk,
    size_t target,
    struct vsock_transport_recv_notify_data *data)
{
    /* TODO: Not sure... */
    return 0;
}

static int argo_transport_notify_recv_post_dequeue(
    struct vsock_sock *vsk,
    size_t target,
    ssize_t copied,
    bool data_read,
    struct vsock_transport_recv_notify_data *data)
{
    /* TODO: Not sure... */
    return 0;
}

static int argo_transport_notify_send_init(
    struct vsock_sock *vsk,
    struct vsock_transport_send_notify_data *data)
{
    /* TODO: Not sure... */
    return 0;
}

static int argo_transport_notify_send_pre_block(
    struct vsock_sock *vsk,
    struct vsock_transport_send_notify_data *data)
{
    /* TODO: Not sure... */
    return 0;
}

static int argo_transport_notify_send_pre_enqueue(
    struct vsock_sock *vsk,
    struct vsock_transport_send_notify_data *data)
{
    /* TODO: Not sure... */
    return 0;
}

static int argo_transport_notify_send_post_enqueue(
    struct vsock_sock *vsk,
    ssize_t written,
    struct vsock_transport_send_notify_data *data)
{
    /* TODO: Not sure... */
    return 0;
}

/*
 * Shutdown.
 */
static int argo_transport_shutdown(struct vsock_sock *vsk, int mode)
{
    /* TODO: That might be where we want to send RST instead... */
    return 0;
}

/*
 * Buffer sizes.
 */
// static void argo_transport_set_buffer_size(struct vsock_sock *vsk, u64 val)
// {
// 	/* TODO: Probably not usable in our case. */
// }

// static void argo_transport_set_min_buffer_size(struct vsock_sock *vsk, u64 val)
// {
// }

// static void argo_transport_set_max_buffer_size(struct vsock_sock *vsk, u64 val)
// {
// }

// static u64 argo_transport_get_buffer_size(struct vsock_sock *vsk)
// {
// 	return 0ULL;
// }

// static u64 argo_transport_get_min_buffer_size(struct vsock_sock *vsk)
// {
// 	return 0ULL;
// }

// static u64 argo_transport_get_max_buffer_size(struct vsock_sock *vsk)
// {
// 	return 0ULL;
// }

static u32 argo_transport_get_local_cid(void)
{
    /* TODO: May require svm_cid format instead of Argo. */
    // return XEN_ARGO_DOMID_ANY;
    return argo_get_local_cid();
}

static struct vsock_transport argo_transport = {
    .init = argo_transport_socket_init,
    .destruct = argo_transport_destruct,
    .release = argo_transport_release,

    // .connect = argo_transport_connect,

    .dgram_bind = argo_transport_dgram_bind,
    .dgram_dequeue = argo_transport_dgram_dequeue,
    .dgram_enqueue = argo_transport_dgram_enqueue,
    .dgram_allow = argo_transport_dgram_allow,

    // .stream_bind = argo_transport_stream_bind,
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

    // .set_buffer_size = argo_transport_set_buffer_size,
    // .set_min_buffer_size = argo_transport_set_min_buffer_size,
    // .set_max_buffer_size = argo_transport_set_max_buffer_size,
    // .get_buffer_size = argo_transport_get_buffer_size,
    // .get_min_buffer_size = argo_transport_get_min_buffer_size,
    // .get_max_buffer_size = argo_transport_get_max_buffer_size,

    .get_local_cid = argo_transport_get_local_cid,
};

/*
 * Tasklet handling packets reception.
 */

static void argo_handle_event(struct tasklet_struct *t)
{
	struct argo_ring_hnd *h, *tmp;
	int rc;

	read_lock(&argo_rings_lock);
	list_for_each_entry_safe(h, tmp, &argo_rings, l) {
		struct sk_buff *skb;

		while (argo_ring_has_data(h) >=
			sizeof (struct xen_argo_ring_message_header)) {
			skb = argo_ring_recv_skb(h);
			if (IS_ERR(skb)) {
				pr_warn("Failed to retrieve packet from Argo "
					"ring (%ld).\n", -PTR_ERR(skb));
				break;
			}
			rc = h->recv_cb(h->priv, skb);
			if (rc) {
				pr_warn("Failed to queue received packet, dropping.\n");
				kfree_skb(skb);
				break;
			}
		}
	}
	read_unlock(&argo_rings_lock);
}

DECLARE_TASKLET(argo_event, argo_handle_event);
/*
 * IRQ handler scheduling tasklet.
 */
static irqreturn_t
argo_interrupt(int irq, void *dev_id)
{
	tasklet_schedule(&argo_event);
	return IRQ_HANDLED;
}

static int __init argo_transport_init(void)
{
    int rc;

    rc = vsock_core_register(&argo_transport, VSOCK_TRANSPORT_F_DGRAM);
    if (rc) {
        pr_err("vsock_core_init() failed (%d).\n", rc);

    }
    rc = vsock_core_register(&argo_transport, VSOCK_TRANSPORT_F_G2H);

    rc = argo_core_init(argo_interrupt);
    if (rc) {
        pr_err("argo_core_init() failed (%d).\n", rc);
        vsock_core_unregister(&argo_transport);
        return rc;
    }
    pr_info("vsock_argo_transport registered.\n");

    return 0;
}
module_init(argo_transport_init);

static void __exit argo_transport_exit(void)
{
    /* TODO: Flush sockets... */

    pr_info("vsock_argo_transport unregistered.\n");
    argo_core_cleanup();
    vsock_core_unregister(&argo_transport);
    return;
}
module_exit(argo_transport_exit);

MODULE_AUTHOR("Assured Information Security, Inc.");
MODULE_DESCRIPTION("Argo transport for Virtual Socket.");
MODULE_VERSION("1.0.0");
MODULE_LICENSE("GPL");
MODULE_ALIAS("argo_vsock");
MODULE_ALIAS_NETPROTO(argo_vsock);
