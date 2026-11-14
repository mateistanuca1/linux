.. SPDX-License-Identifier: GPL-2.0

==================
Using Argo sockets
==================

Argo is reached through ``AF_VSOCK``, so an application uses ordinary sockets
and nothing Argo-specific appears in its source.

Addressing
==========

A vsock address is a CID and a port. Under Argo the **CID is the Xen domain
id**, so a guest running as domain 3 is CID 3 and dom0 is CID 0. Ports are
chosen by the application and mean nothing to the hypervisor beyond naming a
ring.

A process can read its own CID with::

	int fd = open("/dev/vsock", O_RDONLY);
	unsigned int cid;

	ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid);

Because the CID is the domain id, a domain can address itself. The vsock core
routes that through the loopback transport by default, which never reaches
Argo. To exercise Argo against your own domain - useful for testing a service
without a second guest - set ``VMADDR_FLAG_NO_LOCAL`` in the address::

	addr.svm_cid   = cid;		/* this domain's own id */
	addr.svm_flags = VMADDR_FLAG_NO_LOCAL;

Without the flag nothing changes, and other transports are unaffected.

Stream sockets
==============

Server::

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid    = VMADDR_CID_ANY,
		.svm_port   = 1234,
	};
	int s = socket(AF_VSOCK, SOCK_STREAM, 0);

	bind(s, (struct sockaddr *)&addr, sizeof(addr));
	listen(s, 16);

	int c = accept(s, NULL, NULL);

Client, connecting to domain 3::

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid    = 3,
		.svm_port   = 1234,
	};
	int s = socket(AF_VSOCK, SOCK_STREAM, 0);

	connect(s, (struct sockaddr *)&addr, sizeof(addr));

``read()``, ``write()``, ``poll()`` and ``shutdown()`` behave as they do on any
stream socket. The listening socket registers one ring and every connection
accepted on it shares that ring, so a server does not consume a ring per
client.

Datagram sockets
================

``SOCK_DGRAM`` works the same way, with ``sendto()`` and ``recvfrom()``. Each
bound socket registers a ring of its own. A datagram is one message: the
hypervisor copies it whole or not at all, so a short read cannot happen.

Limits and behaviour
====================

Two sizes matter and they are not the same thing.

The **socket receive watermark** is ``vsk->buffer_size``, the vsock default of
256 KiB, settable per socket with ``SO_VM_SOCKETS_BUFFER_SIZE``. It bounds how
much received data may sit in the socket queue before the transport stops
draining the ring.

The **ring** is 128 pages, 512 KiB, a compile-time constant
(``ARGO_RING_LEN``). It is the buffer the hypervisor copies into and is
allocated when the ring is registered, which happens in ``bind()``,
``listen()`` or ``connect()``. ``SO_VM_SOCKETS_BUFFER_SIZE`` does not size it;
a single message must fit in it.

**Back pressure** is the hypervisor's. When the destination ring is full
``sendv`` returns ``-EAGAIN``; a blocking socket retries until the message
fits or ``SO_SNDTIMEO`` expires, and a non-blocking one returns ``EAGAIN`` to
the caller. On the receive side the transport stops draining once the socket
queue is over the watermark, which leaves the message in the ring and blocks
the sender rather than queueing without bound.

**No credit exchange.** ``poll()`` reporting ``POLLOUT`` means the local side
may attempt a send, not that the peer has room; the real answer comes from the
send itself.
