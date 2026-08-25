#ifndef _ARGO_RING_H_
# define _ARGO_RING_H_

#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/skbuff.h>
#include <linux/time64.h>

#include <xen/argo/argo.h>

/*
 * Latency instrumentation (temporary).
 *
 * A received byte crosses three contexts before userspace sees it:
 *
 *	Xen event -> argo_interrupt()		hard IRQ
 *	          -> argo_recv_work_fn()	workqueue, process context
 *	          -> sk_data_ready()		socket wakeup
 *
 * and the reply then crosses back out through sendv. Timestamping every
 * boundary attributes a slow round-trip to one specific hop instead of
 * leaving it to guesswork.
 *
 * Per-hop log2 histograms are kept unconditionally - two adds on a path that
 * already does a hypercall - and dumped when the ring handle is freed.
 * Individual round-trips are only logged when a hop crosses
 * argo_lat_thresh_us, so a 1000-iteration ping-pong does not flood dmesg.
 */
#define ARGO_LAT_BUCKETS	16

extern bool argo_lat_trace;
extern unsigned int argo_lat_thresh_us;

/* Bucket i covers [2^(i-1), 2^i) us; bucket 0 is everything under 1us. */
static inline unsigned int argo_lat_bucket(u64 ns)
{
	u64 us = ns / NSEC_PER_USEC;

	if (!us)
		return 0;

	return min_t(unsigned int, ilog2(us) + 1, ARGO_LAT_BUCKETS - 1);
}

/*
 * Ring GFN management.
 */
struct argo_gfn_array {
	size_t n;
	xen_argo_gfn_t gfns[0];
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
	spinlock_t ring_lock;
	xen_argo_ring_t *ring;
	unsigned int ring_len;
	struct argo_gfn_array *gfns;
	xen_argo_port_t aport;
	domid_t partner_id;
	argo_recv_data_cb recv_cb;
	void *priv;	/* TODO: Do better. Opaque to get struct
			   vsock_sock/struct sock to recv_cb */
	struct sk_buff_head pending_skbs;   /* packets waiting for process-context delivery */
	struct delayed_work recv_work;

	/*
	 * TEMPORARY instrumentation, dumped once when the handle is freed.
	 * Remove once the per-message cost is understood.
	 */
	u64 tx_calls;		/* sendv hypercalls issued */
	u64 tx_eagain;		/* ... that returned -EAGAIN (target ring full) */
	u64 tx_ns;		/* total time spent inside the hypercall */
	u64 tx_ns_max;		/* worst single hypercall */
	u64 rx_wakes;		/* recv worker invocations */
	u64 rx_msgs;		/* messages pulled off the ring */
	u64 rx_enobufs;		/* worker stalls on a full destination socket */
	u64 rx_ns;		/* total time spent building skbs */

	/*
	 * Latency tracing, see the comment above ARGO_LAT_BUCKETS.
	 *
	 * lat_irq_ns is written by the interrupt handler and consumed by the
	 * worker; it holds the *first* kick of a burst, which is the instant
	 * the delay should be measured from. The rest are plain scratch for
	 * the round-trip currently in flight.
	 */
	u64 lat_irq_ns;		/* IRQ saw data (0: no kick outstanding) */
	u64 lat_start_ns;	/* IRQ timestamp of the run in progress */
	u64 lat_work_ns;	/* worker entered */
	u64 lat_ready_ns;	/* about to wake the reader */
	u64 lat_logs;		/* slow round-trips logged so far */
	u64 lat_n;		/* deliveries accounted */
	u64 lat_recv_skb[ARGO_LAT_BUCKETS];	/* inside argo_ring_recv_skb() */
	u64 lat_irq_work[ARGO_LAT_BUCKETS];	/* IRQ -> worker entry */
	u64 lat_work_ready[ARGO_LAT_BUCKETS];	/* worker entry -> wakeup */
	u64 lat_ready_send[ARGO_LAT_BUCKETS];	/* wakeup -> reply sendv */
	u64 lat_sendv[ARGO_LAT_BUCKETS];	/* time inside the hypercall */
};

/*
 * Record one receive hand-off. Called from the transport just before it wakes
 * the reader, which is the last point still inside the kernel's control.
 */
void argo_lat_note_ready(struct argo_ring_hnd *h);

/*
 * Ring handle primitives.
 */
void argo_ring_handle_free(struct argo_ring_hnd *h);
struct argo_ring_hnd *argo_ring_handle_alloc(domid_t domain, unsigned int port,
		argo_recv_data_cb recv_cb, void *priv);
inline size_t argo_ring_has_data(const struct argo_ring_hnd *h);
inline size_t argo_ring_has_space(const struct argo_ring_hnd *h);
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
