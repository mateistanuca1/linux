// SPDX-License-Identifier: GPL-2.0-only
/*
 * Xen Argo core ring primitives.
 *
 * Copyright (c) Assured Information Security, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include <xen/events.h>
#include <xen/page.h>

#include <xen/argo/argo.h>

#include <argo-compat.h>
#include <xen/argo/argo_ring.h>

/*
 * Global ring list.
 */
struct list_head argo_rings;
rwlock_t argo_rings_lock;

/*
 * Workqueue draining the rings into sk_buffs, in process context.
 */
static struct workqueue_struct *argo_recv_wq;

/* Retry delay when the receive path is out of memory. */
#define ARGO_RECV_RETRY_DELAY	msecs_to_jiffies(1)

static void argo_recv_work_fn(struct work_struct *work);

/*
 * Ring management helpers.
 */
static void argo_ring_free(xen_argo_ring_t *r)
{
	vfree(r);
}

static xen_argo_ring_t *argo_ring_alloc(size_t len)
{
	xen_argo_ring_t *r;

	if (unlikely(len < sizeof(struct xen_argo_ring_message_header) +
			   ARGO_RING_ALIGN(1) + ARGO_RING_ALIGN(1)))
		return ERR_PTR(-EINVAL);

	if (len > XEN_ARGO_MAX_RING_SIZE)
		return ERR_PTR(-E2BIG);
	if (len != ARGO_RING_ALIGN(len))
		return ERR_PTR(-EINVAL);

	r = vmalloc(sizeof(*r) + len);
	if (!r)
		return ERR_PTR(-ENOMEM);

	r->rx_ptr = 0;
	r->tx_ptr = 0;

	return r;
}

static void argo_gfn_array_free(struct argo_gfn_array *ga)
{
	kfree(ga);
}

static struct argo_gfn_array *argo_gfn_array_alloc(void *ring_ptr, size_t n)
{
	struct argo_gfn_array *ga;
	unsigned char *p = ring_ptr;
	size_t i;

	ga = kmalloc(struct_size(ga, gfns, n), GFP_KERNEL);
	if (!ga)
		return ERR_PTR(-ENOMEM);

	ga->n = n;
	for (i = 0; i < n; ++i)
		ga->gfns[i] = pfn_to_mfn(vmalloc_to_pfn(p + i * PAGE_SIZE));

	return ga;
}

/*
 * Ring interface.
 */
void argo_ring_handle_free(struct argo_ring_hnd *h)
{
	/*
	 * write_lock_irq(), not write_lock(): argo_interrupt() takes this lock
	 * for reading from hard interrupt context, so a VIRQ_ARGO arriving on
	 * this CPU while the write lock is held deadlocks against itself.
	 */
	write_lock_irq(&argo_rings_lock);
	list_del(&h->l);
	write_unlock_irq(&argo_rings_lock);

	cancel_delayed_work_sync(&h->recv_work);
	skb_queue_purge(&h->pending_skbs);

	argo_gfn_array_free(h->gfns);
	argo_ring_free(h->ring);

	kfree(h);
}
EXPORT_SYMBOL_GPL(argo_ring_handle_free);

struct argo_ring_hnd *argo_ring_handle_alloc(domid_t domain, unsigned int port,
					     argo_recv_data_cb recv_cb,
					     void *priv)
{
	struct argo_ring_hnd *h;
	size_t ring_npages;
	int rc;

	h = kzalloc_obj(*h, GFP_KERNEL);
	if (!h)
		return ERR_PTR(-ENOMEM);

	h->ring = argo_ring_alloc(ring_len);
	if (IS_ERR(h->ring)) {
		rc = PTR_ERR(h->ring);
		goto fail_alloc;
	}
	h->ring_len = ring_len;
	ring_npages = round_up(ARGO_RING_ALIGN(ring_len) +
			       sizeof(xen_argo_ring_t),
			       PAGE_SIZE) >> PAGE_SHIFT;

	h->gfns = argo_gfn_array_alloc(h->ring->ring, ring_npages);
	if (IS_ERR(h->gfns)) {
		rc = PTR_ERR(h->gfns);
		goto fail_gfns;
	}

	spin_lock_init(&h->ring_lock);
	skb_queue_head_init(&h->pending_skbs);
	INIT_DELAYED_WORK(&h->recv_work, argo_recv_work_fn);

	h->partner_id = domain;
	h->aport = port;

	h->recv_cb = recv_cb;
	h->priv = priv;

	/*
	 * Publish last: the interrupt handler walks this list and will kick
	 * the worker as soon as the handle is visible.
	 */
	write_lock_irq(&argo_rings_lock);
	list_add_tail(&h->l, &argo_rings);
	write_unlock_irq(&argo_rings_lock);

	pr_debug("New ring for partner dom%u:%u, %uB.\n",
		 h->partner_id, h->aport, h->ring_len);

	return h;

fail_gfns:
	argo_ring_free(h->ring);
	h->ring = NULL;
fail_alloc:
	kfree(h);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL_GPL(argo_ring_handle_alloc);

void argo_ring_unregister(struct argo_ring_hnd *h)
{
	xen_argo_unregister_ring_t unreg = {
		.aport = h->aport,
		.partner_id = h->partner_id,
		.pad = 0,
	};
	int rc;

	if (!h->ring || !h->gfns)
		return;

	rc = HYPERVISOR_argo_op(XEN_ARGO_OP_unregister_ring, &unreg, NULL, 0, 0);
	if (rc)
		pr_warn("Failed to unregister argo ring for dom%u:%u (%d).\n",
			h->partner_id, h->aport, rc);
	else
		pr_debug("Ring for dom%u:%u unregistered.\n",
			 h->partner_id, h->aport);
}
EXPORT_SYMBOL_GPL(argo_ring_unregister);

int argo_ring_register(struct argo_ring_hnd *h)
{
	xen_argo_register_ring_t reg = {
		.aport = h->aport,
		.partner_id = h->partner_id,
		.pad = 0,
		.len = h->ring_len,
	};
	int rc;

	rc = HYPERVISOR_argo_op(XEN_ARGO_OP_register_ring, &reg, h->gfns->gfns,
				h->gfns->n, 0);
	if (rc)
		pr_warn("Failed to register argo ring for dom%u:%u (%d).\n",
			h->partner_id, h->aport, rc);
	else
		pr_debug("Ring for dom%u:%u registered.\n",
			 h->partner_id, h->aport);

	return rc;
}
EXPORT_SYMBOL_GPL(argo_ring_register);

bool argo_ring_exists(domid_t domain, unsigned int port)
{
	struct argo_ring_hnd *h;
	bool found = false;

	read_lock(&argo_rings_lock);
	list_for_each_entry(h, &argo_rings, l) {
		if (h->partner_id == domain && h->aport == port) {
			found = true;
			break;
		}
	}
	read_unlock(&argo_rings_lock);

	return found;
}
EXPORT_SYMBOL_GPL(argo_ring_exists);

/*
 * Ring arithmetic helpers.
 * Argo rings never fill up completely, so tx == rx means the ring is empty.
 */
size_t argo_ring_has_data(const struct argo_ring_hnd *h)
{
	const xen_argo_ring_t *r = h->ring;
	/*
	 * tx_ptr is written by Xen behind our back and the ABI asks for atomic
	 * access. Without READ_ONCE() the compiler may reload it between the
	 * comparison and the subtraction and compute a bogus length - and this
	 * runs in the interrupt handler, where reading it low means the worker
	 * is never kicked and the ring stalls until the next message.
	 */
	const size_t rx = READ_ONCE(r->rx_ptr);
	const size_t tx = READ_ONCE(r->tx_ptr);

	if (rx > tx)
		return h->ring_len - (rx - tx);

	return tx - rx;
}
EXPORT_SYMBOL_GPL(argo_ring_has_data);

static size_t argo_ring_has_data_no_wrap(const struct argo_ring_hnd *h)
{
	const xen_argo_ring_t *r = h->ring;
	const size_t rx = READ_ONCE(r->rx_ptr);
	const size_t tx = READ_ONCE(r->tx_ptr);

	if (rx > tx)
		return h->ring_len - rx;

	return tx - rx;
}

size_t argo_ring_has_space(const struct argo_ring_hnd *h)
{
	return h->ring_len - argo_ring_has_data(h) - ARGO_RING_ALIGN(1);
}
EXPORT_SYMBOL_GPL(argo_ring_has_space);

/*
 * Copy len bytes out of the ring, starting off bytes past rx_ptr, handling
 * wrap-around. rx_ptr is left untouched: the caller decides whether the bytes
 * are really consumed. Caller must hold ring_lock.
 */
static void argo_ring_copy_out(const struct argo_ring_hnd *h, void *buf,
			       size_t off, size_t len)
{
	const xen_argo_ring_t *r = h->ring;
	unsigned char *p = buf;
	const size_t rx = (READ_ONCE(r->rx_ptr) + off) % h->ring_len;
	const size_t chunk = h->ring_len - rx;

	if (len > chunk) {
		memcpy(p, (void *)&r->ring[rx], chunk);
		memcpy(&p[chunk], (void *)&r->ring[0], len - chunk);
	} else {
		memcpy(p, (void *)&r->ring[rx], len);
	}
}

/*
 * Release len bytes back to the sender. Only call this once the payload is
 * safely out of the ring: past this point Xen may overwrite it.
 * Caller must hold ring_lock.
 */
static void argo_ring_consume(struct argo_ring_hnd *h, size_t len)
{
	xen_argo_ring_t *r = h->ring;
	const size_t rx = ARGO_RING_ALIGN(READ_ONCE(r->rx_ptr) + len) %
			  h->ring_len;

	/* The copy out of the ring must be complete before rx_ptr moves. */
	mb();
	WRITE_ONCE(r->rx_ptr, rx);
}

int argo_ring_recv(struct argo_ring_hnd *h, void *buf, size_t len)
{
	if (len > argo_ring_has_data(h)) {
		pr_err("Requested %zuB, but only %zuB available.\n",
		       len, argo_ring_has_data(h));
		return -E2BIG;
	}

	pr_debug("receive %zuB: ring_len:%uB data:%zuB data-no-wrap:%zuB space-left:%zuB, rx:%u, tx:%u.\n",
		 len, h->ring_len, argo_ring_has_data(h),
		 argo_ring_has_data_no_wrap(h), argo_ring_has_space(h),
		 h->ring->rx_ptr, h->ring->tx_ptr);

	argo_ring_copy_out(h, buf, 0, len);
	argo_ring_consume(h, len);

	return len;
}
EXPORT_SYMBOL_GPL(argo_ring_recv);

/*
 * Pull one message off the ring into an sk_buff.
 *
 * The message is only consumed once it is fully copied into an skb. On
 * failure rx_ptr stays put and the message is retried later: this carries
 * SOCK_STREAM traffic, so silently dropping a message would punch a hole in
 * the byte stream and wedge the peer forever.
 *
 * The skb is paged. A 64KB message would otherwise need an order-5 contiguous
 * allocation, which fails routinely once the machine is under load.
 */
static struct sk_buff *argo_ring_recv_skb(struct argo_ring_hnd *h)
{
	struct xen_argo_ring_message_header mh;
	struct sk_buff *skb;
	size_t msg_len, avail, off;
	int i, err = 0;

	spin_lock(&h->ring_lock);

	avail = argo_ring_has_data(h);
	if (avail < sizeof(mh)) {
		err = -ENODATA;
		goto out;
	}

	argo_ring_copy_out(h, &mh, 0, sizeof(mh));

	if (unlikely(mh.len < sizeof(mh) ||
		     ARGO_RING_ALIGN(mh.len) > avail)) {
		pr_err("Invalid packet, message size %u out of range (%zuB available).\n",
		       mh.len, avail);
		/* The ring is inconsistent, it cannot be resynchronised. */
		err = -EPROTO;
		goto out;
	}
	msg_len = mh.len - sizeof(mh);

	skb = alloc_skb_with_frags(sizeof(mh), msg_len, PAGE_ALLOC_COSTLY_ORDER,
				   &err, GFP_KERNEL | __GFP_NOWARN);
	if (!skb) {
		if (!err)
			err = -ENOMEM;
		goto out;
	}

	memcpy(skb_put(skb, sizeof(mh)), &mh, sizeof(mh));
	skb->len += msg_len;
	skb->data_len = msg_len;

	off = sizeof(mh);
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		const size_t flen = skb_frag_size(frag);

		argo_ring_copy_out(h, skb_frag_address(frag), off, flen);
		off += flen;
	}

	argo_ring_consume(h, ARGO_RING_ALIGN(mh.len));
	spin_unlock(&h->ring_lock);

	return skb;

out:
	spin_unlock(&h->ring_lock);
	return ERR_PTR(err);
}

void argo_ring_schedule_recv(struct argo_ring_hnd *h, unsigned long delay)
{
	if (!argo_recv_wq)
		return;

	/*
	 * An immediate kick has to be mod_delayed_work(): queue_delayed_work()
	 * is a no-op while the work is already armed, so an interrupt landing
	 * during the retry delay is swallowed and the ring sits untouched for
	 * the remainder of it - a lost wakeup that costs a full retry period.
	 * mod_delayed_work() with a zero delay runs the worker whatever state
	 * it was in, and is documented as safe from an interrupt handler.
	 */
	if (delay)
		queue_delayed_work(argo_recv_wq, &h->recv_work, delay);
	else
		mod_delayed_work(argo_recv_wq, &h->recv_work, 0);
}
EXPORT_SYMBOL_GPL(argo_ring_schedule_recv);

int argo_ring_send(struct argo_ring_hnd *h, xen_argo_iov_t *iov,
		   xen_argo_send_addr_t *send, uint32_t msg_type)
{
	int rc;

	rc = HYPERVISOR_argo_op(XEN_ARGO_OP_sendv, send, iov, 1, msg_type);

	/* -EAGAIN is normal back-pressure, do not log it per message. */
	if (rc < 0 && rc != -EAGAIN)
		pr_warn_ratelimited("Failed to send packet (%uB) through Argo to dom%u:%u (%d).\n",
				    iov[0].iov_len, send->dst.domain_id,
				    send->dst.aport, -rc);

	return rc;
}
EXPORT_SYMBOL_GPL(argo_ring_send);

domid_t argo_get_local_cid(void)
{
	domid_t domid = DOMID_INVALID;
	struct evtchn_alloc_unbound op;
	struct evtchn_status status;
	struct evtchn_close close_op;
	int rc;

	/* Allocate an unbound event channel. */
	op.dom = DOMID_SELF;
	op.remote_dom = DOMID_SELF;
	rc = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
	if (rc) {
		pr_err("alloc_unbound failed with rc=%d\n", rc);
		return domid;
	}

	/* Query the status of the port to find the real domid. */
	status.dom = DOMID_SELF;
	status.port = op.port;
	rc = HYPERVISOR_event_channel_op(EVTCHNOP_status, &status);
	if (rc)
		pr_err("EVTCHNOP_status failed with rc=%d\n", rc);
	else
		domid = status.u.unbound.dom;

	/* Clean up the port. */
	close_op.port = op.port;
	rc = HYPERVISOR_event_channel_op(EVTCHNOP_close, &close_op);
	if (rc)
		pr_warn("close_port %d failed rc=%d\n", op.port, rc);

	return domid;
}
EXPORT_SYMBOL_GPL(argo_get_local_cid);

/*
 * Worker draining one ring into sk_buffs and handing them to the transport.
 */
static void argo_recv_work_fn(struct work_struct *work)
{
	struct argo_ring_hnd *h = container_of(to_delayed_work(work),
					       struct argo_ring_hnd,
					       recv_work);
	struct sk_buff *skb;
	int rc;

	for (;;) {
		/* An skb the destination socket could not take last time. */
		skb = skb_dequeue(&h->pending_skbs);
		if (!skb) {
			skb = argo_ring_recv_skb(h);
			if (IS_ERR(skb)) {
				rc = PTR_ERR(skb);
				if (rc == -ENOMEM || rc == -ENOBUFS)
					/* Message still in the ring: retry. */
					argo_ring_schedule_recv(h,
								ARGO_RECV_RETRY_DELAY);
				else if (rc != -ENODATA)
					pr_err("Ring dom%u:%u unusable (%d), stopping receive.\n",
					       h->partner_id, h->aport, -rc);
				break;
			}
		}

		rc = h->recv_cb(h->priv, skb);
		if (rc == -ENOBUFS) {
			/*
			 * Destination socket receive queue is full. Stop
			 * draining the ring so that the sender blocks in
			 * sendv() instead of us buffering without bound; the
			 * reader kicks us again once it has made room.
			 */
			skb_queue_head(&h->pending_skbs, skb);
			break;
		}
		if (rc) {
			pr_warn_ratelimited("Failed to queue received packet, dropping.\n");
			kfree_skb(skb);
		}
	}
}

/*
 * Initialisation and cleanup of the VIRQ.
 */
static int argo_irq = -1;

int argo_core_init(irqreturn_t (*argo_vsock_interrupt)(int, void *))
{
	int rc;

	argo_ring_check_sizes();
	INIT_LIST_HEAD(&argo_rings);
	rwlock_init(&argo_rings_lock);

	/*
	 * Per-CPU rather than WQ_UNBOUND: the worker then runs on the CPU that
	 * took the interrupt, with the ring still cache-hot, and the wakeup
	 * skips the unbound pool's CPU selection.
	 */
	argo_recv_wq = alloc_workqueue("argo_recv", WQ_HIGHPRI | WQ_PERCPU, 0);
	if (!argo_recv_wq)
		return -ENOMEM;

	rc = bind_virq_to_irqhandler(VIRQ_ARGO, 0, argo_vsock_interrupt, 0,
				     "argo", NULL);
	if (rc < 0) {
		destroy_workqueue(argo_recv_wq);
		argo_recv_wq = NULL;
		return rc;
	}

	argo_irq = rc;

	return 0;
}
EXPORT_SYMBOL_GPL(argo_core_init);

void argo_core_cleanup(void)
{
	if (argo_irq >= 0) {
		unbind_from_irqhandler(argo_irq, NULL);
		argo_irq = -1;
	}

	if (argo_recv_wq) {
		destroy_workqueue(argo_recv_wq);
		argo_recv_wq = NULL;
	}
}
EXPORT_SYMBOL_GPL(argo_core_cleanup);

MODULE_AUTHOR("Assured Information Security, Inc.");
MODULE_DESCRIPTION("Xen Argo core ring primitives.");
MODULE_LICENSE("GPL");
