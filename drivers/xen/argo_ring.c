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
#include <linux/ktime.h>
#include <linux/mmzone.h>
#include <linux/skbuff.h>
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
 * Latency instrumentation. See the comment above ARGO_LAT_BUCKETS in
 * argo_ring.h for what is being measured and why.
 */
bool argo_lat_trace = true;
module_param_named(lat_trace, argo_lat_trace, bool, 0644);
MODULE_PARM_DESC(lat_trace, "Timestamp the receive path (default on)");
EXPORT_SYMBOL_GPL(argo_lat_trace);

/*
 * Zero disables per-round-trip logging, which is the right default: a line on
 * a serial console costs tens of milliseconds and lands in the middle of the
 * path being timed, so switching it on changes the answer. The histograms are
 * free and always collected - read those first, and only set a threshold here
 * to catch the stack of a specific outlier.
 */
unsigned int argo_lat_thresh_us;
module_param_named(lat_thresh_us, argo_lat_thresh_us, uint, 0644);
MODULE_PARM_DESC(lat_thresh_us,
                 "Log a round-trip when a hop exceeds this many us (0: off, default)");
EXPORT_SYMBOL_GPL(argo_lat_thresh_us);

/* Cap on individual slow-path lines, so a pathological run cannot flood. */
static unsigned int argo_lat_max_logs = 200;
module_param_named(lat_max_logs, argo_lat_max_logs, uint, 0644);
MODULE_PARM_DESC(lat_max_logs, "Stop logging after this many slow round-trips");

static void argo_lat_dump(const struct argo_ring_hnd *h, const char *what,
                          const u64 *hist)
{
    char buf[ARGO_LAT_BUCKETS * 12];
    int i, n = 0;

    for (i = 0; i < ARGO_LAT_BUCKETS; i++) {
        if (!hist[i])
            continue;
        n += scnprintf(buf + n, sizeof(buf) - n, " %u:%llu",
                       i ? 1u << (i - 1) : 0, hist[i]);
    }
    if (!n)
        return;

    /* "<us-lower-bound>:<count>", so 4096:37 means 37 samples in 4-8ms. */
    pr_info("ring dom%u:%u %-11s us:count%s\n",
            h->partner_id, h->aport, what, buf);
}

void argo_lat_note_ready(struct argo_ring_hnd *h)
{
    u64 now, d_irq_work, d_work_ready;

    if (!argo_lat_trace)
        return;

    now = ktime_get_ns();
    h->lat_ready_ns = now;
    h->lat_n++;

    /*
     * lat_start_ns is zero when the worker ran without an interrupt behind
     * it - the reader-side kick from stream_dequeue(). Those say nothing
     * about wakeup latency, so only the second hop is accounted.
     */
    d_irq_work = h->lat_start_ns ? h->lat_work_ns - h->lat_start_ns : 0;
    d_work_ready = now - h->lat_work_ns;

    if (h->lat_start_ns)
        h->lat_irq_work[argo_lat_bucket(d_irq_work)]++;
    h->lat_work_ready[argo_lat_bucket(d_work_ready)]++;

    if (argo_lat_thresh_us &&
        (d_irq_work / NSEC_PER_USEC > argo_lat_thresh_us ||
         d_work_ready / NSEC_PER_USEC > argo_lat_thresh_us) &&
        h->lat_logs++ < argo_lat_max_logs)
        pr_info("lat dom%u:%u recv#%llu: irq->work %llu us, "
                "work->ready %llu us\n",
                h->partner_id, h->aport, h->lat_n,
                d_irq_work / NSEC_PER_USEC,
                d_work_ready / NSEC_PER_USEC);
}
EXPORT_SYMBOL_GPL(argo_lat_note_ready);

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

    if (h->tx_calls || h->rx_msgs)
        pr_info("ring dom%u:%u stats: "
                "tx %llu calls (%llu EAGAIN) avg %llu ns max %llu ns | "
                "rx %llu msgs in %llu wakes (%llu msgs/wake), "
                "avg %llu ns, %llu ENOBUFS stalls\n",
                h->partner_id, h->aport,
                h->tx_calls, h->tx_eagain,
                h->tx_calls ? h->tx_ns / h->tx_calls : 0, h->tx_ns_max,
                h->rx_msgs, h->rx_wakes,
                h->rx_wakes ? h->rx_msgs / h->rx_wakes : 0,
                h->rx_msgs ? h->rx_ns / h->rx_msgs : 0,
                h->rx_enobufs);

    if (h->lat_n) {
        argo_lat_dump(h, "recv_skb", h->lat_recv_skb);
        argo_lat_dump(h, "irq->work", h->lat_irq_work);
        argo_lat_dump(h, "work->ready", h->lat_work_ready);
        argo_lat_dump(h, "ready->sendv", h->lat_ready_send);
        argo_lat_dump(h, "sendv", h->lat_sendv);
    }

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

    h = kzalloc(sizeof (*h), GFP_KERNEL);	/* zeroes the stat counters */
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
    skb_queue_head_init(&h->pending_skbs);
    INIT_DELAYED_WORK(&h->recv_work, argo_recv_work_fn);

    h->partner_id = domain;
    h->aport = port;

    h->recv_cb = recv_cb;
    h->priv = priv;

    /* Publish last: the interrupt handler walks this list and will kick
     * the worker as soon as the handle is visible. */
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

static inline size_t argo_ring_has_data_no_wrap(const struct argo_ring_hnd *h)
{
    const xen_argo_ring_t *r = h->ring;
    const size_t rx = READ_ONCE(r->rx_ptr);
    const size_t tx = READ_ONCE(r->tx_ptr);

    if (rx > tx)
        return h->ring_len - rx;

    return tx - rx;
}

inline size_t argo_ring_has_space(const struct argo_ring_hnd *h)
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
    } else
        memcpy(p, (void *)&r->ring[rx], len);
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

    mb();	/* rx cannot be set out-of-order, thank you. */
    WRITE_ONCE(r->rx_ptr, rx);
}

int argo_ring_recv(struct argo_ring_hnd *h, void *buf, size_t len)
{
    if (len > argo_ring_has_data(h)) {
        pr_err("Requested %zuB, but only %zuB available.\n", len,
               argo_ring_has_data(h));
        return -E2BIG;
    }

    pr_debug("receive %zuB: ring_len:%uB data:%zuB data-no-wrap:%zuB "
             "space-left:%zuB, rx:%u, tx:%u.\n",
             len, h->ring_len, argo_ring_has_data(h),
             argo_ring_has_data_no_wrap(h),
             argo_ring_has_space(h),
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
        pr_err("Invalid packet, message size %u out of range (%zuB "
               "available).\n", mh.len, avail);
        err = -EPROTO;	/* ring is inconsistent, cannot resynchronise */
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
    u64 t0, dt;
    int rc;

    /* TODO: Message-type is forced to 0 here. */
    t0 = ktime_get_ns();
    rc = HYPERVISOR_argo_op(XEN_ARGO_OP_sendv, send, iov, 1, msg_type);
    dt = ktime_get_ns() - t0;

    h->tx_calls++;
    h->tx_ns += dt;
    if (dt > h->tx_ns_max)
        h->tx_ns_max = dt;

    if (argo_lat_trace) {
        /*
         * On an echo server this send is the reply to the last thing
         * delivered, so ready->sendv is the userspace turnaround plus
         * the scheduling latency of waking the reader. Consumed once:
         * a send with no delivery behind it is not a turnaround.
         */
        u64 ready = xchg(&h->lat_ready_ns, 0);
        u64 turn = (ready && t0 > ready) ? t0 - ready : 0;

        h->lat_sendv[argo_lat_bucket(dt)]++;
        if (turn)
            h->lat_ready_send[argo_lat_bucket(turn)]++;

        if (argo_lat_thresh_us &&
            (turn / NSEC_PER_USEC > argo_lat_thresh_us ||
             dt / NSEC_PER_USEC > argo_lat_thresh_us) &&
            h->lat_logs++ < argo_lat_max_logs)
            pr_info("lat dom%u:%u send: ready->sendv %llu us, "
                    "sendv %llu us, rc %d\n",
                    h->partner_id, h->aport,
                    turn / NSEC_PER_USEC, dt / NSEC_PER_USEC, rc);
    }

    if (rc == -EAGAIN) {
        h->tx_eagain++;
    } else if (rc < 0) {
        /* -EAGAIN is normal back-pressure, do not log it per message. */
        pr_warn_ratelimited(
            "Failed to send packet (%uB) through Argo to dom%u:%u (%d).\n",
            iov[0].iov_len, send->dst.domain_id, send->dst.aport, -rc);
    }

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
    struct argo_ring_hnd *h = container_of(to_delayed_work(work),
                                           struct argo_ring_hnd, recv_work);
    struct sk_buff *skb;
    int rc;

    h->rx_wakes++;

    if (argo_lat_trace) {
        h->lat_work_ns = ktime_get_ns();
        /*
         * Consume the interrupt timestamp: a kick that arrives while
         * this run is in progress belongs to the *next* run, and
         * xchg() keeps the two from being confused.
         */
        h->lat_start_ns = xchg(&h->lat_irq_ns, 0);
    }

    for (;;) {
        /* An skb the destination socket could not take last time. */
        skb = skb_dequeue(&h->pending_skbs);
        if (!skb) {
            u64 t0 = ktime_get_ns();

            skb = argo_ring_recv_skb(h);
            t0 = ktime_get_ns() - t0;
            h->rx_ns += t0;
            /*
             * The decisive bucket: this brackets the skb
             * allocation, so mass out here means the delay is the
             * page allocator, not the wakeup path around it.
             * Only successful pulls count - every worker run ends
             * on -ENODATA, and those samples otherwise outnumber
             * the real ones two to one and hide the tail.
             */
            if (argo_lat_trace && !IS_ERR(skb))
                h->lat_recv_skb[argo_lat_bucket(t0)]++;
            if (IS_ERR(skb)) {
                rc = PTR_ERR(skb);
                if (rc == -ENOMEM || rc == -ENOBUFS)
                    /* Message still in the ring: retry. */
                    argo_ring_schedule_recv(h,
                                            ARGO_RECV_RETRY_DELAY);
                else if (rc != -ENODATA)
                    pr_err("Ring dom%u:%u unusable (%d), "
                           "stopping receive.\n",
                           h->partner_id, h->aport, -rc);
                break;
            }
            h->rx_msgs++;
        }

        rc = h->recv_cb(h->priv, skb);
        if (rc == -ENOBUFS) {
            h->rx_enobufs++;
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
            pr_warn_ratelimited(
                "Failed to queue received packet, dropping.\n");
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

    /*
     * Per-CPU rather than WQ_UNBOUND: the worker then runs on the CPU that
     * took the interrupt, with the ring still cache-hot, and the wakeup
     * skips the unbound pool's CPU selection. Measured: median irq->work
     * 256-512us -> 128-256us.
     *
     * No WQ_MEM_RECLAIM. It looks right for a path that drains the ring a
     * blocked peer is waiting on, but adding it coincided with 26% of
     * messages taking 16-32ms from interrupt to worker, and its rescuer is
     * driven by a mayday timer that fires at MAYDAY_INITIAL_TIMEOUT - 10ms
     * at HZ=1000, then every 100ms. Left out until that is ruled in or out.
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
    printk("Domid: %i\n", argo_get_local_cid());

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

