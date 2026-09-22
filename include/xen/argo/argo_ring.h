/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ARGO_RING_H_
#define _ARGO_RING_H_

#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include <xen/argo/argo.h>

#ifdef CONFIG_XEN_ARGO_LATENCY_TRACE
#include <linux/ktime.h>
#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/time64.h>

/*
 * Latency tracing.
 *
 * A received byte crosses three contexts before userspace sees it:
 *
 *	Xen event -> argo_interrupt()		hard IRQ
 *	          -> argo_recv_work_fn()	workqueue, process context
 *	          -> sk_data_ready()		socket wakeup
 *
 * and the reply crosses back out through sendv. Timestamping every boundary
 * attributes a slow round trip to one hop instead of leaving it to guesswork.
 *
 * Per-hop log2 histograms are dumped when the ring handle is freed. Logging an
 * individual round trip is off by default: a line on a console costs more than
 * the round trip it describes, so switching it on changes the answer.
 */
#define ARGO_LAT_BUCKETS	16

/* Bucket i covers [2^(i-1), 2^i) us; bucket 0 is everything under 1us. */
static inline unsigned int argo_lat_bucket(u64 ns)
{
	u64 us = ns / NSEC_PER_USEC;

	if (!us)
		return 0;

	return min_t(unsigned int, ilog2(us) + 1, ARGO_LAT_BUCKETS - 1);
}
#endif /* CONFIG_XEN_ARGO_LATENCY_TRACE */

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

struct argo_ring_hnd {
	struct list_head l;
	/* Serialises consumers of ring against each other. */
	spinlock_t ring_lock;
	xen_argo_ring_t *ring;
	unsigned int ring_len;
	struct argo_gfn_array *gfns;
	xen_argo_port_t aport;
	domid_t partner_id;
	argo_recv_data_cb recv_cb;
	/*
	 * TODO: Do better. Opaque, carries the struct vsock_sock or struct
	 * sock that recv_cb needs.
	 */
	void *priv;
	/* Packets waiting for process-context delivery. */
	struct sk_buff_head pending_skbs;
	struct delayed_work recv_work;

#ifdef CONFIG_XEN_ARGO_LATENCY_TRACE
	u64 tx_calls;		/* sendv hypercalls issued */
	u64 tx_eagain;		/* ... that returned -EAGAIN (target ring full) */
	u64 tx_ns;		/* total time spent inside the hypercall */
	u64 tx_ns_max;		/* worst single hypercall */
	u64 rx_wakes;		/* receive worker invocations */
	u64 rx_msgs;		/* messages pulled off the ring */
	u64 rx_enobufs;		/* worker stalls on a full destination socket */
	u64 rx_ns;		/* total time spent building skbs */

	/*
	 * lat_irq_ns is written by the interrupt handler and consumed by the
	 * worker; it holds the *first* kick of a burst, which is the instant
	 * the delay should be measured from. The rest are scratch for the
	 * round trip currently in flight.
	 */
	u64 lat_irq_ns;		/* IRQ saw data (0: no kick outstanding) */
	u64 lat_start_ns;	/* IRQ timestamp of the run in progress */
	u64 lat_work_ns;	/* worker entered */
	u64 lat_ready_ns;	/* about to wake the reader */
	u64 lat_deq_ns;		/* reader reached stream_dequeue() */
	u64 lat_logs;		/* slow round trips logged so far */
	u64 lat_n;		/* deliveries accounted */
	u64 lat_recv_skb[ARGO_LAT_BUCKETS];	/* inside argo_ring_recv_skb() */
	u64 lat_irq_work[ARGO_LAT_BUCKETS];	/* IRQ -> worker entry */
	u64 lat_work_ready[ARGO_LAT_BUCKETS];	/* worker entry -> wakeup */
	/*
	 * Wakeup to reply sendv, and the same interval split at the moment the
	 * reader reaches the transport. The two halves have different owners:
	 * ready->deq is the scheduler getting the reader onto a CPU, deq->sendv
	 * is the application.
	 */
	u64 lat_ready_deq[ARGO_LAT_BUCKETS];	/* wakeup -> reader running */
	u64 lat_deq_send[ARGO_LAT_BUCKETS];	/* reader running -> reply */
	u64 lat_ready_send[ARGO_LAT_BUCKETS];	/* wakeup -> reply (total) */
	u64 lat_sendv[ARGO_LAT_BUCKETS];	/* time inside the hypercall */
#endif
};

/*
 * Latency tracing hooks.
 *
 * Every one of these compiles to nothing without
 * CONFIG_XEN_ARGO_LATENCY_TRACE, so call sites stay free of #ifdef.
 */
#ifdef CONFIG_XEN_ARGO_LATENCY_TRACE

extern bool argo_lat_trace;

static inline u64 argo_lat_now(void)
{
	return argo_lat_trace ? ktime_get_ns() : 0;
}

/* The interrupt handler found data on this ring. */
void argo_lat_note_irq(struct argo_ring_hnd *h);
/* The receive worker started running. */
void argo_lat_note_work(struct argo_ring_hnd *h);
/* One attempt to pull a message off the ring finished, successfully or not. */
void argo_lat_note_recv_skb(struct argo_ring_hnd *h, u64 t0,
			    const struct sk_buff *skb);
/* About to wake the reader: the last point still under the kernel's control. */
void argo_lat_note_ready(struct argo_ring_hnd *h);
/* The reader reached the transport, so it is demonstrably running again. */
void argo_lat_note_dequeue(struct argo_ring_hnd *h);
/* A sendv hypercall returned. */
void argo_lat_note_send(struct argo_ring_hnd *h, u64 t0, int rc);
/* The destination socket was full and the worker parked the message. */
void argo_lat_note_enobufs(struct argo_ring_hnd *h);
/* Print every histogram collected for this ring. */
void argo_lat_dump(const struct argo_ring_hnd *h);

#else /* !CONFIG_XEN_ARGO_LATENCY_TRACE */

static inline u64 argo_lat_now(void) { return 0; }
static inline void argo_lat_note_irq(struct argo_ring_hnd *h) { }
static inline void argo_lat_note_work(struct argo_ring_hnd *h) { }
static inline void argo_lat_note_recv_skb(struct argo_ring_hnd *h, u64 t0,
					  const struct sk_buff *skb) { }
static inline void argo_lat_note_ready(struct argo_ring_hnd *h) { }
static inline void argo_lat_note_dequeue(struct argo_ring_hnd *h) { }
static inline void argo_lat_note_send(struct argo_ring_hnd *h, u64 t0, int rc) { }
static inline void argo_lat_note_enobufs(struct argo_ring_hnd *h) { }
static inline void argo_lat_dump(const struct argo_ring_hnd *h) { }

#endif /* CONFIG_XEN_ARGO_LATENCY_TRACE */

/*
 * Ring handle primitives.
 */
void argo_ring_handle_free(struct argo_ring_hnd *h);
struct argo_ring_hnd *argo_ring_handle_alloc(domid_t domain, unsigned int port,
					     argo_recv_data_cb recv_cb,
					     void *priv);
size_t argo_ring_has_data(const struct argo_ring_hnd *h);
size_t argo_ring_has_space(const struct argo_ring_hnd *h);

/*
 * Ring primitives, hypercalls to Xen.
 */
void argo_ring_unregister(struct argo_ring_hnd *h);
int argo_ring_register(struct argo_ring_hnd *h);
bool argo_ring_exists(domid_t domain, unsigned int port);
domid_t argo_get_local_cid(void);

/*
 * Ring "send" primitive. send is synchronous, direct hypercall to Xen.
 */
int argo_ring_send(struct argo_ring_hnd *h, xen_argo_iov_t *iov,
		   xen_argo_send_addr_t *send, uint32_t msg_type);
int argo_ring_recv(struct argo_ring_hnd *h, void *buf, size_t len);

/*
 * Kick the receive worker for this ring. Used by the interrupt handler when
 * new data lands, and by the reader side once it has freed room in the socket
 * receive queue: ring consumption stops while the destination socket is full,
 * so nothing else would restart it.
 */
void argo_ring_schedule_recv(struct argo_ring_hnd *h, unsigned long delay);

int argo_core_init(irqreturn_t (*argo_vsock_interrupt)(int, void *));
void argo_core_cleanup(void);

#endif /* !_ARGO_RING_H_ */
