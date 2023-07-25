// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tick.h>
#include <linux/module.h>
#include <asm/mshyperv.h>
#include <asm/hyperv-tlfs.h>
#include <asm/fpu/internal.h>
#include <asm/mshv_vtl.h>
#include "vsm.h"
#include "mshv.h"
#include <linux/miscdevice.h>
#include <linux/module.h>

struct mshv_vtl_call_params vtl_params={0,0,0,0};
enum vsm_service_ids {
	VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY = 0x1FFF,
	VSM_VTL_CALL_FUNC_ID_LOCK_CR = 0x1FFFF
};

static void mshv_vsm_vtl_return(void);

static void mshv_vsm_handle_entry(struct mshv_vtl_call_params *_vtl_params)
{
	switch (_vtl_params->_a0) {
	case VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY:
		pr_info("%s : VSM_PROTECT_MEMORY\n", __func__);
		pr_info("%s : a0:%llx a1:%llx, a2:%llx,a3:%llx\n", __func__,
			_vtl_params->_a0, _vtl_params->_a1, _vtl_params->_a2,
			_vtl_params->_a3);
		_vtl_params->_a3 = 1;
		break;
	case VSM_VTL_CALL_FUNC_ID_LOCK_CR:
		pr_info("%s : VSM_LOCK_CRS\n", __func__);
		break;
	default:
		pr_err("%s : Wrong service id\n", __func__);
		break;
	}
	mshv_vsm_vtl_return();
}

static void mshv_vsm_interrupt_handle_entry(void)
{
	pr_info("%s\n", __func__);
	mshv_vsm_vtl_return();
}

static void mshv_vsm_intercept_handle_entry(void)
{
	pr_info("%s\n", __func__);
	mshv_vsm_vtl_return();
}

static void mshv_vsm_vtl_return()
{
	unsigned long irq_flags;
	struct hv_vp_assist_page *hvp;

	pr_info("%s : a0:%llx a1:%llx, a2:%llx,a3:%llx\n", __func__,
			vtl_params._a0, vtl_params._a1, vtl_params._a2,vtl_params._a3);
	/* Ordering is important. Suspedn tick before disabling interrupts */
	tick_suspend_local();
	local_irq_save(irq_flags);
	kernel_fpu_begin_mask(0);

	asm __volatile__("movq %0, %%rdi\n"
			 "movq %1, %%rsi\n"
			 "movq %2, %%rdx\n"
			 "movq %3, %%rbx\n"
			 "mov $0x00, %%rax\n"
			 "mov $0x12, %%rcx\n"
			 "vmcall\n"
			 :
			 : "m"(vtl_params._a0), "m"(vtl_params._a1),
			   "m"(vtl_params._a2), "m"(vtl_params._a3)
			 : "rdi", "rsi", "rdx", "rbx", "memory");
	/*
	 *  VTL0 can pass four arguments to VTL1 in registers rdi, rsi, rdx and rbx respectively.
	 *  rbx is also used to pass success or failure back to VTL0.
	 */
	asm __volatile__("movq %%rdi, %0\n"
			 "movq %%rsi, %1\n"
			 "movq %%rdx, %2\n"
			 "movq %%rbx, %3\n"
			 :
			 : "m"(vtl_params._a0), "m"(vtl_params._a1),
			   "m"(vtl_params._a2), "m"(vtl_params._a3)
			 : "rdi", "rsi", "rdx", "rbx", "memory");
	kernel_fpu_end();
	tick_resume_local();
	local_irq_restore(irq_flags);

	/* Without this interrupt handler is not kick started */
	schedule();

	hvp = hv_vp_assist_page[smp_processor_id()];
	switch (hvp->vtl_entry_reason) {
	case HvVtlEntryVtlCall:
		pr_info("MSHV_ENTRY_REASON_LOWER_VTL_CALL\n");
		mshv_vsm_handle_entry(&vtl_params);
		break;

	case HvVtlEntryInterrupt:
		pr_info("MSHV_ENTRY_REASON_INTERRUPT\n");
		mshv_vsm_interrupt_handle_entry();
		break;

	case HvVtlEntryIntercept:
		pr_info("MSHV_ENTRY_REASON_INTERCEPT\n");
		mshv_vsm_intercept_handle_entry();
		break;

	default:
		pr_info("unknown entry reason: %d", hvp->vtl_entry_reason);
		break;
	}

}

static long mshv_vsm_vtl_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	long ret;

	switch (ioctl) {
	case MSHV_VTL_RETURN_TO_LOWER_VTL:
		mshv_vsm_vtl_return();
		break;
	default:
		pr_err("%s: invalid vtl ioctl: %#x\n", __func__, ioctl);
		ret = -ENOTTY;
	}

	return ret;
}

static const struct file_operations mshv_vtl_fops = {
    .owner = THIS_MODULE,
	.unlocked_ioctl = mshv_vsm_vtl_ioctl,
};

static struct miscdevice mshv_vsm_dev = {
	.name = "mshv_vsm_dev",
	.nodename = "mshv_vsm_dev",
	.fops = &mshv_vtl_fops,
	.mode = 0400,
	.minor = MISC_DYNAMIC_MINOR,
};

static int __init mshv_vtl1_init(void)
{
	int ret;

	ret = misc_register(&mshv_vsm_dev);
	if (ret) {
		pr_err("VSM: Could not register mshv_vsm_vtl_ioctl\n");
	}

	return ret;
}

static void __exit mshv_vtl1_exit(void) {
    misc_deregister(&mshv_vsm_dev);
    pr_info("mshv_vsm_dev device unregistered\n");
}

module_init(mshv_vtl1_init);
module_exit(mshv_vtl1_exit);
