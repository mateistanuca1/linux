/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ARGO_RING_H_
#define _ARGO_RING_H_

#include <linux/interrupt.h>
#include <linux/kref.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include <xen/argo/argo.h>

/*
 * Ring GFN management.
 */
struct argo_gfn_array {
	size_t n;
	xen_argo_gfn_t gfns[];
};

/*
 * xen_argo_ring_t does not have a length field.
 * Arbitrary fixed ring size for now.
 * This size is chosen to match other Argo driver implementations.
 */
static const size_t ring_len = 128 * PAGE_SIZE;

/*
 * Messages on the ring are aligned on XEN_ARGO_MSG_SLOT_SIZE.
 * XEN_ARGO_MSG_SLOT_SIZE needs to be a power of 2.
 */
#define ARGO_RING_ALIGN(a) round_up((a), XEN_ARGO_MSG_SLOT_SIZE)

static inline void argo_ring_check_sizes(void)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(XEN_ARGO_MSG_SLOT_SIZE);
}

/*
 * Ring management.
 */
extern struct list_head argo_rings;
extern rwlock_t argo_rings_lock;

typedef int (*argo_recv_data_cb)(void *priv, void *data);
/*
 * Drops the reference the ring holds on its owner. Called once, when the last
 * user of the handle is gone, so that recv_cb can never run against a freed
 * owner.
 */
typedef void (*argo_priv_put_cb)(void *priv);

struct argo_ring_hnd {
	struct list_head l;
	/*
	 * A listening socket registers the ring; every connection accepted on
	 * it shares the same handle. Closing the listener must not pull the
	 * ring out from under established children, so the handle outlives
	 * whichever socket drops it last.
	 */
	struct kref refcount;
	/* Serialises consumers of ring against each other. */
	spinlock_t ring_lock;
	xen_argo_ring_t *ring;
	unsigned int ring_len;
	struct argo_gfn_array *gfns;
	xen_argo_port_t aport;
	domid_t partner_id;
	/* Set once the hypervisor has accepted the ring. */
	bool registered;
	argo_recv_data_cb recv_cb;
	argo_priv_put_cb priv_put;
	/* Opaque owner, passed back to recv_cb. Pinned for the ring's life. */
	void *priv;

};

/*
 * Latency tracing hooks.
 *
 * Every one of these compiles to nothing without
 * CONFIG_XEN_ARGO_LATENCY_TRACE, so call sites stay free of #ifdef.
 */

/*
 * Ring handle primitives.
 */
void argo_ring_handle_get(struct argo_ring_hnd *h);
void argo_ring_handle_put(struct argo_ring_hnd *h);
struct argo_ring_hnd *argo_ring_handle_alloc(domid_t domain, unsigned int port,
					     argo_recv_data_cb recv_cb,
					     argo_priv_put_cb priv_put,
					     void *priv);
size_t argo_ring_has_data(const struct argo_ring_hnd *h);
size_t argo_ring_has_space(const struct argo_ring_hnd *h);

/*
 * Ring primitives, hypercalls to Xen.
 */
int argo_ring_register(struct argo_ring_hnd *h);
bool argo_ring_exists(domid_t domain, unsigned int port);

/*
 * Ring "send" primitive. send is synchronous, direct hypercall to Xen.
 */
int argo_ring_recv(struct argo_ring_hnd *h, void *buf, size_t len);

#endif /* !_ARGO_RING_H_ */
