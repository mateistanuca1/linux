#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>

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

	if (unlikely(len <
		sizeof (struct xen_argo_ring_message_header) +
			ARGO_RING_ALIGN(1) + ARGO_RING_ALIGN(1)))
		return ERR_PTR(-EINVAL);

	if (len > XEN_ARGO_MAX_RING_SIZE)
		return ERR_PTR(-E2BIG);
	if (len != ARGO_RING_ALIGN(len))
		return ERR_PTR(-EINVAL);

	r = vmalloc(sizeof (*r) + len);
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
static struct argo_gfn_array *
argo_gfn_array_alloc(volatile void *ring_ptr, size_t n)
{
	struct argo_gfn_array *ga;
	unsigned char *p = (void*)ring_ptr;
	size_t i;

	ga = kmalloc(sizeof (*ga) + n * sizeof (ga->gfns[0]), GFP_KERNEL);
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
	cancel_work_sync(&h->recv_work);
	skb_queue_purge(&h->pending_skbs);
	list_del(&h->l);

	argo_gfn_array_free(h->gfns);
	argo_ring_free(h->ring);

	kfree(h);
}
EXPORT_SYMBOL_GPL(argo_ring_handle_free);

struct argo_ring_hnd *
argo_ring_handle_alloc(domid_t domain, unsigned int port,
	argo_recv_data_cb recv_cb, void *priv)
{
	struct argo_ring_hnd *h;
	size_t ring_npages;
	int rc;

	h = kmalloc(sizeof (*h), GFP_KERNEL);
	if (!h)
		return ERR_PTR(-ENOMEM);

	h->ring = argo_ring_alloc(ring_len);
	if (IS_ERR(h->ring)) {
		rc = PTR_ERR(h->ring);
		goto fail_alloc;
	}
	h->ring_len = ring_len;
	ring_npages = round_up(
		ARGO_RING_ALIGN(ring_len) + sizeof (xen_argo_ring_t),
		PAGE_SIZE) >> PAGE_SHIFT;

	h->gfns = argo_gfn_array_alloc(h->ring->ring, ring_npages);
	if (IS_ERR(h->gfns)) {
		rc = PTR_ERR(h->gfns);
		goto fail_gfns;
	}

	/* FIXME: ring_lock. */
	spin_lock_init(&h->ring_lock);
	write_lock(&argo_rings_lock);
	list_add_tail(&h->l, &argo_rings);
	skb_queue_head_init(&h->pending_skbs);
	INIT_WORK(&h->recv_work, argo_recv_work_fn);
	write_unlock(&argo_rings_lock);

	h->partner_id = domain;
	h->aport = port;

	h->recv_cb = recv_cb;
	h->priv = priv;

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

	rc = HYPERVISOR_argo_op(XEN_ARGO_OP_unregister_ring,
		&unreg, NULL, 0, 0);
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
	int rc;
	xen_argo_register_ring_t reg = {
		.aport = h->aport,
		.partner_id = h->partner_id,
		.pad = 0,
		.len = h->ring_len,
	};

	rc = HYPERVISOR_argo_op(XEN_ARGO_OP_register_ring,
		&reg, h->gfns->gfns, h->gfns->n, 0);
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
 * Argo ring never fill up completely, so tx == rx means the ring is empty.
 */
inline size_t argo_ring_has_data(const struct argo_ring_hnd *h)
{
	const xen_argo_ring_t *r = h->ring;
	const size_t rx = r->rx_ptr;
	const size_t tx = r->tx_ptr;

	if (rx > tx)
		return h->ring_len - (rx - tx);

	return tx - rx;
}
EXPORT_SYMBOL_GPL(argo_ring_has_data);

static inline size_t argo_ring_has_data_no_wrap(const struct argo_ring_hnd *h)
{
	const xen_argo_ring_t *r = h->ring;
	const size_t rx = r->rx_ptr;
	const size_t tx = r->tx_ptr;

	if (rx > tx)
		return h->ring_len - rx;

	return tx - rx;
}

inline size_t argo_ring_has_space(const struct argo_ring_hnd *h)
{
	return h->ring_len - argo_ring_has_data(h) - ARGO_RING_ALIGN(1);
}
EXPORT_SYMBOL_GPL(argo_ring_has_space);

int argo_ring_recv(struct argo_ring_hnd *h, void *buf, size_t len)
{
	xen_argo_ring_t *r = h->ring;
	unsigned char *p = buf;
	size_t chunk;
	size_t rx = r->rx_ptr;

	if (len > argo_ring_has_data(h)) {
		pr_err("Requested %zuB, but only %zuB available.\n", len, argo_ring_has_data(h));
		return -E2BIG;
	}

	pr_debug("receive %zuB: ring_len:%uB data:%zuB data-no-wrap:%zuB "
		"space-left:%zuB, rx:%zu, tx:%u.\n",
		len, h->ring_len, argo_ring_has_data(h),
		argo_ring_has_data_no_wrap(h),
		argo_ring_has_space(h),
		rx, r->tx_ptr);

	chunk = argo_ring_has_data_no_wrap(h);
	if (len > chunk) {
		memcpy(p, (void*)&r->ring[rx], chunk);
		memcpy(&p[chunk], (void*)&r->ring[0], len - chunk);
	} else
		memcpy(p, (void*)&r->ring[rx], len);

	rx = ARGO_RING_ALIGN(ARGO_RING_ALIGN(rx + len) % h->ring_len);

	mb();	/* rx cannot be set out-of-order, thank you. */
	r->rx_ptr = rx;

	return len;
}
EXPORT_SYMBOL_GPL(argo_ring_recv);



static struct sk_buff* argo_ring_recv_skb(struct argo_ring_hnd* h) {
    const struct xen_argo_ring_message_header* mh;
    struct sk_buff* skb;
    size_t msg_len;
    int rc = 0;

    skb = alloc_skb(sizeof(*mh), GFP_KERNEL);
    if (!skb) {
        pr_err("Failed to allocate skb to receive message header with size %zu.\n", sizeof(*mh));
        return ERR_PTR(-ENOMEM);
    }

    spin_lock(&h->ring_lock);
    argo_ring_recv(h, skb_put(skb, sizeof(*mh)), sizeof(*mh));
    mh = (void*)skb->data;
    msg_len = mh->len - sizeof(*mh);

    if (unlikely(msg_len > argo_ring_has_data(h))) {
        pr_err("Invalid packet, message size exceeds ring capacity.");
        rc = E2BIG;
        goto out;   /* ring deja inconsistent, nu putem drena în siguranță */
    }

    if (msg_len) {
        if (pskb_expand_head(skb, 0, msg_len, GFP_KERNEL)) {
            pr_err("Failed to allocate skb to receive message.");
            rc = ENOMEM;
            goto drain;   /* <-- AICI e schimbarea cheie */
        }
        argo_ring_recv(h, skb_put(skb, msg_len), msg_len);
        
    }

    spin_unlock(&h->ring_lock);
    return skb;

drain:
    /* msg_len a fost deja validat mai sus (< has_data), deci e sigur să
     * consumăm exact atâția bytes din ring, ca rx_ptr să rămână corect. */
    {
        char scratch[128];
        size_t remaining = msg_len;
        while (remaining) {
            size_t chunk = min(remaining, sizeof(scratch));
            argo_ring_recv(h, scratch, chunk);
            remaining -= chunk;
        }
    }
out:
    spin_unlock(&h->ring_lock);
    kfree_skb(skb);
    return ERR_PTR(-rc);
}



int argo_ring_send(struct argo_ring_hnd *h, xen_argo_iov_t *iov,
		xen_argo_send_addr_t *send, uint32_t msg_type)
{
	int rc;
	/* TODO: Message-type is forced to 0 here. */
	rc = HYPERVISOR_argo_op(XEN_ARGO_OP_sendv, send, iov, 1, msg_type);
	if (rc < 0)
		pr_warn("Failed to send packet (%uB) through Argo to dom%u:%u (%d).\n",
			iov[0].iov_len, send->dst.domain_id, send->dst.aport, -rc);

	return rc;
}
EXPORT_SYMBOL_GPL(argo_ring_send);

domid_t argo_get_local_cid(void)
{
    int rc;
    domid_t domid = DOMID_INVALID;
    struct evtchn_alloc_unbound op;
    struct evtchn_status status;
    struct evtchn_close close_op;

    // Step 1: Allocate an unbound event channel
    op.dom = DOMID_SELF;
    op.remote_dom = DOMID_SELF;
    rc = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
    if (rc) {
        printk(KERN_ERR "domid_driver: alloc_unbound failed with rc=%d\n", rc);
        return domid;
    }

    // Step 2: Query the status of the port to find the real DomID
    status.dom = DOMID_SELF;
    status.port = op.port;
    rc = HYPERVISOR_event_channel_op(EVTCHNOP_status, &status);
    if (rc) {
        printk(KERN_ERR "domid_driver: EVTCHNOP_status failed with rc=%d\n", rc);
    } else {
        domid = status.u.unbound.dom;
    }

    // Step 3: Clean up the port
    close_op.port = op.port;
    rc = HYPERVISOR_event_channel_op(EVTCHNOP_close, &close_op);
    if (rc) {
        printk(KERN_WARNING "domid_driver: close_port %d failed rc=%d\n", op.port, rc);
    }

    return domid;
}
EXPORT_SYMBOL_GPL(argo_get_local_cid);
/*
 * Tasklet handling packets reception.
 */

static void argo_recv_work_fn(struct work_struct *work)
{
    struct argo_ring_hnd *h = container_of(work, struct argo_ring_hnd, recv_work);
    struct sk_buff *skb;
    int rc;

    while (argo_ring_has_data(h) >= sizeof(struct xen_argo_ring_message_header)) {
        skb = argo_ring_recv_skb(h);
        if (IS_ERR(skb)) {
            pr_warn("Failed to retrieve packet from Argo ring (%ld).\n", -PTR_ERR(skb));
            break;
        }
        rc = h->recv_cb(h->priv, skb);
        if (rc) {
            pr_warn("Failed to queue received packet, dropping.\n");
            kfree_skb(skb);
        }
    }
}
#if 0
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
#endif
/*
 * IRQ handler scheduling tasklet.
 */

// static irqreturn_t
// argo_interrupt(int irq, void *dev_id)
// {
// 	tasklet_schedule(&argo_event);
// 	return IRQ_HANDLED;
// }

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

	rc = bind_virq_to_irqhandler(VIRQ_ARGO, 0, argo_vsock_interrupt, 0,
		"argo", NULL);
	if (rc < 0)
		return rc;

	argo_irq = rc;
	printk("Domid: %i\n", argo_get_local_cid());

	return 0;
}
EXPORT_SYMBOL_GPL(argo_core_init);

void argo_core_cleanup(void)
{
	if (argo_irq < 0)
		return;

	unbind_from_irqhandler(argo_irq, NULL);
}
EXPORT_SYMBOL_GPL(argo_core_cleanup);

