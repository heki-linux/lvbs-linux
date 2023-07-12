// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/vsm.h>
#include <linux/tick.h>
#include <linux/module.h>
#include <asm/mshyperv.h>
#include <asm/fpu/internal.h>
#include "mshv.h"

/*
 * mshv_vtl_call_params : Strcture to parse in parameters from VTL0
 * _a0 : Service Id
 * _a1-_a3: Optional and depends on the requested service
 */
struct mshv_vtl_call_params {
	u64 _a0;
	u64 _a1;
	u64 _a2;
	u64 _a3;
};

struct mshv_vtl_call_params vtl_params;

static union hv_register_vsm_page_offsets mshv_vsm_page_offsets;

static void mshv_vsm_vtl_return(void);

static void mshv_vsm_handle_entry(struct mshv_vtl_call_params *vtl_params)
{
	switch (vtl_params->_a0) {
	case VSM_PROTECT_MEMORY:
		pr_err("%s : VSM_PROTECT_MEMORY\n", __func__);
		break;
	case VSM_LOCK_CRS:
		pr_err("%s : VSM_LOCK_CRS\n", __func__);
		break;
	default:
		pr_err("%s : Wrong service id\n", __func__);
		break;
	}
	mshv_vsm_vtl_return();
}

static void mshv_vsm_vtl_return(void)
{
	unsigned long irq_flags;
	u64 hypercall_addr;

	hypercall_addr = (u64)((u8 *)hv_hypercall_pg + mshv_vsm_page_offsets.vtl_return_offset);

	/* Ordering is important. Suspedn tick before disabling interrupts */
	tick_suspend_local();
	local_irq_save(irq_flags);
	kernel_fpu_begin_mask(0);
	asm __volatile__ (      \
                "mov $0xABDCEF20, %%r9\n"
                "mov $0x00, %%rax\n"
                "mov $0x12, %%rcx\n"
                "vmcall\n" : : :);
	/*
	 *  VTL0 can pass four arguments to VTL1 in registers rdi, rsi, rdx and rbx respectively.
	 *  rbx is also used to pass success or failure back to VTL0.
	 */
	asm __volatile__ (
		"movq %%rdi, %0\n"
		"movq %%rsi, %1\n"
		"movq %%rdx, %2\n"
		"movq %%rbx, %3\n"
		:
		: "m"(vtl_params._a0), "m"(vtl_params._a1), "m"(vtl_params._a2), "m"(vtl_params._a3)
		: "rdi", "rsi", "rdx", "rbx", "memory");
	kernel_fpu_end();
	tick_resume_local();
	local_irq_restore(irq_flags);
	/* Without this interrupt handler is not kick started */
	schedule();
	mshv_vsm_handle_entry(&vtl_params);
}

static int mshv_vtl1_init(void)
{
	pr_info("%s\n", __func__);
	mshv_vsm_vtl_return();
	return 0;
}
module_init(mshv_vtl1_init);
