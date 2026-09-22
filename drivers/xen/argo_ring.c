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

#include <xen/argo/argo.h>
#include <xen/argo/argo_ring.h>
#include <xen/events.h>
#include <xen/page.h>

#include <asm/xen/argo.h>

/*
 * Global ring list.
 */
struct list_head argo_rings;
rwlock_t argo_rings_lock;

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
struct argo_ring_hnd *argo_ring_handle_alloc(domid_t domain, unsigned int port,
					     argo_recv_data_cb recv_cb,
					     argo_priv_put_cb priv_put,
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

	kref_init(&h->refcount);
	spin_lock_init(&h->ring_lock);

	h->partner_id = domain;
	h->aport = port;

	h->recv_cb = recv_cb;
	h->priv_put = priv_put;
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

static void argo_ring_unregister(struct argo_ring_hnd *h)
{
	xen_argo_unregister_ring_t unreg = {
		.aport = h->aport,
		.partner_id = h->partner_id,
		.pad = 0,
	};
	int rc;

	if (!h->registered)
		return;

	rc = HYPERVISOR_argo_op(XEN_ARGO_OP_unregister_ring, &unreg, NULL, 0, 0);
	if (rc)
		pr_warn("Failed to unregister argo ring for dom%u:%u (%d).\n",
			h->partner_id, h->aport, rc);
	else
		pr_debug("Ring for dom%u:%u unregistered.\n",
			 h->partner_id, h->aport);

	h->registered = false;
}

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
	if (rc) {
		pr_warn("Failed to register argo ring for dom%u:%u (%d).\n",
			h->partner_id, h->aport, rc);
		return rc;
	}

	h->registered = true;
	pr_debug("Ring for dom%u:%u registered.\n", h->partner_id, h->aport);

	return 0;
}
EXPORT_SYMBOL_GPL(argo_ring_register);

/*
 * A ring registered by a listening socket is shared by every connection
 * accepted on it, so its lifetime is not the lifetime of any one socket.
 */
static void argo_ring_handle_release(struct kref *kref)
{
	struct argo_ring_hnd *h = container_of(kref, struct argo_ring_hnd,
					       refcount);

	/*
	 * write_lock_irq(), not write_lock(): argo_interrupt() takes this lock
	 * for reading from hard interrupt context, so a VIRQ_ARGO arriving on
	 * this CPU while the write lock is held deadlocks against itself.
	 */
	write_lock_irq(&argo_rings_lock);
	list_del(&h->l);
	write_unlock_irq(&argo_rings_lock);

	/*
	 * Off the list, so nothing can reach the ring any more; only then
	 * tell Xen to stop delivering into it.
	 */
	argo_ring_unregister(h);

	if (h->priv_put)
		h->priv_put(h->priv);

	argo_gfn_array_free(h->gfns);
	argo_ring_free(h->ring);

	kfree(h);
}

void argo_ring_handle_get(struct argo_ring_hnd *h)
{
	kref_get(&h->refcount);
}
EXPORT_SYMBOL_GPL(argo_ring_handle_get);

void argo_ring_handle_put(struct argo_ring_hnd *h)
{
	kref_put(&h->refcount, argo_ring_handle_release);
}
EXPORT_SYMBOL_GPL(argo_ring_handle_put);

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

MODULE_AUTHOR("Assured Information Security, Inc.");
MODULE_DESCRIPTION("Xen Argo core ring primitives.");
MODULE_LICENSE("GPL");
