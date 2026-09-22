/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_XEN_ARGO_H
#define _ASM_X86_XEN_ARGO_H

#include <asm/xen/hypercall.h>

/*
 * Argo is the only hypercall taking five arguments, which is why
 * _hypercall5() exists.
 */
static inline int __must_check
HYPERVISOR_argo_op(int cmd, void *arg1, void *arg2, uint32_t arg3,
		   uint32_t arg4)
{
	int ret;

	__xen_stac();
	ret = _hypercall5(int, argo_op, cmd, arg1, arg2, arg3, arg4);
	__xen_clac();

	return ret;
}

#endif /* _ASM_X86_XEN_ARGO_H */
