.. SPDX-License-Identifier: GPL-2.0

=============
Enabling Argo
=============

Argo has to be turned on in three places: the hypervisor build, the hypervisor
command line, and the guest kernel.

Hypervisor
==========

Argo is a build-time option in Xen, ``CONFIG_ARGO``, and is disabled by
default at run time. Enable it on the Xen command line::

	argo=1

Wildcard rings
--------------

A ring registered for a specific partner accepts messages only from that
domain. A ring registered with the wildcard partner ``XEN_ARGO_DOMID_ANY``
accepts messages from any domain.

**This driver registers wildcard rings only.** Sockets are bound with
``VMADDR_CID_ANY`` unless the application asks otherwise, and that becomes the
wildcard partner id, so every ring the driver creates is a wildcard ring. A
listening socket needs one in any case: it does not know who will connect.

Registering a wildcard ring is privileged. On a hypervisor using the default
access control policy it is permitted; under an XSM policy the domain needs
the corresponding permission. ``argo=1,mac-permissive=1`` relaxes the check
for every domain, which is convenient on a test machine but grants every
domain the ability to register a ring any other domain may write into.

Diagnosing the hypervisor side
------------------------------

The failure is visible in the return value of the first ring registration:

======================  ============================================
``-ENOSYS``             Xen was built without ``CONFIG_ARGO``
``-ENOTSUPP``           ``argo=1`` was not passed (also other causes)
``-EPERM``              the domain may not register this ring
======================  ============================================

``argo_ring`` logs the hypercall failure, so ``dmesg`` on the guest is the
first place to look when a socket operation fails for no apparent reason.

Guest kernel
============

One symbol to set::

	CONFIG_XEN_ARGO_VSOCKETS=m	net/vmw_vsock/argo_transport.c

It selects ``CONFIG_XEN_ARGO``, the ring layer in ``drivers/xen/argo_ring.c``,
so there is nothing else to enable. Both depend on ``XEN`` and ``X86``: the
hypercall wrapper is x86 only.

Loading
=======

::

	modprobe vmw_vsock_argo_transport

``argo_ring`` is pulled in as a dependency.
