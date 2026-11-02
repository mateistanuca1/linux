.. SPDX-License-Identifier: GPL-2.0

========
Xen Argo
========

Argo is an interdomain transport implemented by the Xen hypervisor. A domain
registers a ring with the hypervisor, giving it a port and either a specific
partner domain or the wildcard domain id. Senders address the ring by
``(domain id, port)`` and the hypervisor copies each message into it; the
receiving guest reads the ring directly.

The ring's frames are never mapped into the sending domain, so the two sides
do not share memory. Nothing a peer does to its own pages can be seen by, or
corrupt, the domain it is talking to, which makes the transport usable between
domains that do not trust each other. The cost is that every byte is copied
rather than shared, so Argo trades bulk throughput for a short, predictable
path.

Two guarantees follow from the hypervisor doing the copy synchronously:

* **Delivery.** ``sendv`` either places the whole message in the destination
  ring, or writes nothing and returns an error. There is no in-flight state
  and no partial write.
* **Ordering.** The ring is a FIFO whose producer offset only moves forward,
  under the hypervisor's own lock. Two sends from one domain cannot overlap
  and cannot swap.

Both are guaranteed properties of the hypercall, not something the guest has
to arrange. A transport built on Argo therefore needs no sequence numbers, no
acknowledgements, no retransmission timers and no reassembly. The driver does
have to provide flow control and track connection state - the latter only so
that more than one socket can share a ring, since every sender addressing the
same port lands in the same receive ring.

Linux exposes Argo through ``AF_VSOCK``, so an application uses ordinary
sockets. See :doc:`usage`.

.. toctree::
   :maxdepth: 2

   setup
   usage
