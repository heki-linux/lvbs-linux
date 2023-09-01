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

static void mshv_vsm_vtl_return(void);

struct mshv_vtl_call_params vtl_params={0};
enum vsm_service_ids {
	VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY = 0x1FFF,
	VSM_VTL_CALL_FUNC_ID_LOCK_CR = 0x1FFFF
};
char hv_hypercall_input_page[VSM_PAGE_SIZE] __aligned(VSM_PAGE_SIZE);
char hv_hypercall_output_page[VSM_PAGE_SIZE] __aligned(VSM_PAGE_SIZE);

static void *hv_acquire_hypercall_input_page(void)
{
	memset(hv_hypercall_input_page, 0, sizeof(hv_hypercall_input_page));

	return hv_hypercall_input_page;
}

enum hv_status vsm_hv_hypercall(u64 call_code, void *input_page,
	void *output_page, u32 count_of_elements, u32 *elements_processed)
{
	union hv_hypercall_input input = { 0 };
	union hv_hypercall_output output = { 0 };

	input.call_code = call_code;
	input.count_of_elements = count_of_elements;

	output.as_uint64 = hv_do_hypercall(input.as_uint64, input_page,
		output_page);

	if (elements_processed)
		*elements_processed = output.elements_processed;

	return output.call_status;
}

static int hv_modify_vtl_protection_mask(u64 gpa_page_list[],
	size_t *number_of_pages, u32 page_access)
{
	enum hv_status status;
	u64 flags;
	int64_t pages_remaining;
	u32 pages_processed;
	u32 total_pages_processed;
	size_t max_pages_per_request;
	u32 i;
	union hv_input_vtl target_vtl;

	target_vtl.as_uint8 = 1;

	struct hv_input_modify_vtl_protection_mask *hvin;

	/* Check parameters */
	if (!gpa_page_list || !number_of_pages || *number_of_pages >= UINT_MAX)
		return -EINVAL;

	/* Compute the maximum number of pages that can be processed in one go */
	max_pages_per_request = (VSM_PAGE_SIZE - sizeof(*hvin)) / sizeof(u64);

	/* Acquire the input page */
	hvin = hv_acquire_hypercall_input_page();

	/* Fill in the hypercall parameters */
	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->target_vtl = target_vtl;
	hvin->map_flags = page_access;

	/*
	 * Batch-process pages based on the maximum number of pages that can be
	 * processed in a single hypercall
	 */
	pages_processed = 0;
	total_pages_processed = 0;
	pages_remaining = *number_of_pages;

	while (pages_remaining > 0) {
		for (i = 0 ;
			 ((i < max_pages_per_request) &&
				((total_pages_processed + i) < *number_of_pages)) ;
			 i++)
			hvin->gpa_page_list[i] = gpa_page_list[total_pages_processed + i];

		/* Disable interrupts */
		local_irq_save(flags);

		/* Perform the hypercall */
		status = vsm_hv_hypercall(HVCALL_MODIFY_VTL_PROTECTION_MASK, hvin, NULL, i, &pages_processed);

		/* Enable interrupts */
		local_irq_restore(flags);

		/*
		 * Update page accounting for the next iteration, if any
		 *
		 * N.B.: pages_processed is correct even if Hyper-V returned an error.
		 */
		pages_remaining -= pages_processed;
		total_pages_processed += pages_processed;

		pr_info("HVCALL_MODIFY_VTL_PROTECTION_MASK status%d", status);

		/* See how things went */
		if (status != HV_STATUS_SUCCESS)
			break;
	}

	/* Pass results out (valid on error) */
	*number_of_pages = total_pages_processed;

	/* Done */
	return status == HV_STATUS_SUCCESS ? 0 : -EPERM;
}

static int vsm_restrict_memory(u64 start, size_t size, u32 permissions)
{
	int res=-EPERM;
	size_t i;
	size_t page_count;
	u64 *pfns;

	// Assert that the region to protect is page-aligned 
	if (((start % VSM_PAGE_SIZE)) != 0 || ((size % VSM_PAGE_SIZE) != 0))
		return -EPERM;

	// Compute the number of pages to protect 
	page_count = size / VSM_PAGE_SIZE;

	// Set up the list of Page Frame Numbers (PFNs) 
	pfns = kzalloc(page_count * sizeof(*pfns), GFP_KERNEL);
	if (!pfns)
		return -ENOMEM;

	for (i = 0 ; i < page_count ; i++)
		pfns[i] = VSM_PAGE_TO_PFN(VSM_PAGE_AT(start, i));
	
	// Revoke all VTL 0 access rights on these pages 
	res = hv_modify_vtl_protection_mask(pfns, &page_count, permissions);

	// Free the PFN list 
	kfree(pfns);

	return res;
}

static void mshv_vsm_handle_entry(struct mshv_vtl_call_params *_vtl_params)
{
	int ret = 0;
	u32 permissions = 0x00;

	switch (_vtl_params->_a0) {
		case VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY:
			pr_info("%s : VSM_PROTECT_MEMORY\n", __func__);
			pr_info("%s : a0:%lX a1:%lX, a2:%lX,a3:%lX\n", __func__,
				_vtl_params->_a0, _vtl_params->_a1, _vtl_params->_a2,
				_vtl_params->_a3);

			if (_vtl_params->_a3 & HEKI_ATTR_MEM_NOWRITE)
				permissions |= HV_MAP_GPA_READABLE;
			if (_vtl_params->_a3 & HEKI_ATTR_MEM_EXEC)
				permissions |= (HV_MAP_GPA_READABLE | HV_MAP_GPA_EXECUTABLE);

			ret = vsm_restrict_memory(_vtl_params->_a1, _vtl_params->_a2, permissions);
			if (ret)
				pr_info("%s: failed\n",__func__);
			else 
				pr_info("%s: is ok\n",__func__);

			_vtl_params->_a3=ret;	
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
	mshv_vsm_handle_entry(&vtl_params);
}

static int mshv_vtl1_configure_vsm_partition(void)
{
	union hv_input_vtl input_vtl;
	u64 flags;
	enum hv_status status;
	struct hv_input_set_vp_registers *hvin;
	union hv_register_value register_value;
	union hv_vsm_partition_config *vsm_partition_config;
	u32 elements_processed;

	/* Enable and set default VTL protections */
	vsm_partition_config = (union hv_vsm_partition_config *)
		&register_value;
	vsm_partition_config->as_u64 = 0;
	vsm_partition_config->enable_vtl_protection = 1;
	vsm_partition_config->default_vtl_protection_mask =
		HV_MAP_GPA_ACCESS_ALL;

	/* Acquire the input page */
	hvin = hv_acquire_hypercall_input_page();

	/* Fill in the hypercall parameters */
	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->vp_index = HV_VP_INDEX_SELF;
	hvin->input_vtl.as_uint8 = 0;
	hvin->reserved8_z = 0;
	hvin->reserved16_z = 0;
	hvin->elements[0].name = HV_REGISTER_VSM_PARTITION_CONFIG;
	hvin->elements[0].value = register_value;

	/* Disable interrupts */
	local_irq_save(flags);

	/* Perform the hypercall */
	status = vsm_hv_hypercall(HVCALL_SET_VP_REGISTERS, hvin, NULL, 1,
		&elements_processed);

	/* Enable interrupts */
	local_irq_restore(flags);
	return status;
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

	if (mshv_vtl1_configure_vsm_partition()) {
		pr_emerg("%s: VSM configuration failed !!\n", __func__);
		return -EPERM;
	}

	return ret;
}

static void __exit mshv_vtl1_exit(void) {
    misc_deregister(&mshv_vsm_dev);
    pr_info("mshv_vsm_dev device unregistered\n");
}

module_init(mshv_vtl1_init);
module_exit(mshv_vtl1_exit);
