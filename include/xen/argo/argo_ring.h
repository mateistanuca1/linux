#ifndef _ARGO_RING_H_
# define _ARGO_RING_H_

#include <linux/skbuff.h>

#include <xen/argo/argo.h>

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
};

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
