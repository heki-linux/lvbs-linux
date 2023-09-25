// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tick.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <asm/mshyperv.h>
#include <asm/hyperv-tlfs.h>
#include <asm/fpu/internal.h>
#include <asm/mshv_vtl.h>
#include <uapi/asm-generic/hyperv-tlfs.h>
#include "vsm.h"
#include "mshv.h"
#include "hyperv_vmbus.h"

static void mshv_vsm_vtl_return(void);

struct mshv_vtl_call_params vtl_params={0};

enum vsm_service_ids {
	VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY = 0x1FFF,
	VSM_VTL_CALL_FUNC_ID_LOCK_CR = 0x1FFFF
};

struct hv_intercept_message_header {
	u32 vp_index;
	u8 instruction_length;
	u8 intercept_access_type;
	/* ToDo: Define union for this */
	u16 execution_state;
	struct hv_x64_segment_register cs_segment;
	u64 rip;
	u64 rflags;
} __packed;

struct hv_vsm_per_cpu {
	bool event_pending;

	void *synic_message_page;
//	void *synic_event_page;

	struct tasklet_struct handle_intercept;
};

static DEFINE_PER_CPU(struct hv_vsm_per_cpu, vsm_per_cpu);

static int hv_modify_vtl_protection_mask(u64 gpa_page_list[],
	size_t *number_of_pages, u32 page_access)
{
	struct hv_input_modify_vtl_protection_mask *hvin;
	u64 status, pages_processed, total_pages_processed;
	unsigned long flags;
	size_t max_pages_per_request;
	int i;

	/* Check parameters */
	if (!gpa_page_list || !number_of_pages || *number_of_pages >= UINT_MAX)
		return -EINVAL;

	/* Compute the maximum number of pages that can be processed in one go */
	max_pages_per_request = (VSM_PAGE_SIZE - sizeof(*hvin)) / sizeof(u64);

	/* Disable interrupts */
	local_irq_save(flags);

	/* Acquire the input page */
	hvin = (struct hv_input_modify_vtl_protection_mask *)(*this_cpu_ptr(hyperv_pcpu_input_arg));

	/* Fill in the hypercall parameters */
	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->target_vtl.as_uint8 = 1;
	hvin->map_flags = page_access;

	/*
	 * Batch-process pages based on the maximum number of pages that can be
	 * processed in a single hypercall
	 */
	pages_processed = 0;
	total_pages_processed = 0;

	while (total_pages_processed < *number_of_pages) {
		for (i = 0; ((i < max_pages_per_request) &&
			     ((total_pages_processed + i) < *number_of_pages)); i++)
			hvin->gpa_page_list[i] = gpa_page_list[total_pages_processed + i];

		/* Perform the hypercall */
		status = hv_do_rep_hypercall(HVCALL_MODIFY_VTL_PROTECTION_MASK, i, 0, hvin, NULL);

		/*
		 * Update page accounting for the next iteration, if any
		 * N.B.: pages_processed is correct even if Hyper-V returned an error.
		 */
		pages_processed = hv_repcomp(status);
		total_pages_processed += pages_processed;

		/* See how things went */
		if (!hv_result_success(status))
			break;
	}

	/* Pass results out (valid on error) */
	*number_of_pages = total_pages_processed;

	/* Enable interrupts */
	local_irq_restore(flags);

	/* Done */
	return hv_result(status);
}

static int vsm_restrict_memory(u64 start, size_t size, u32 permissions)
{
	int res = -EPERM;
	size_t page_count, i;
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

/*
 * These placeholders are overridden by arch specific code on
 * architectures that need special setup of the stimer0 IRQ because
 * they don't support per-cpu IRQs (such as x86/x64).
 */
void __weak hv_setup_vsm_handler(void (*handler)(void))
{
}

void __weak hv_remove_vsm_handler(void)
{
}

static void mshv_vsm_isr(void)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);
	void *synic_message_page;
	struct hv_message *msg;
	u32 message_type;

	synic_message_page = per_cpu->synic_message_page;
	if (unlikely(!synic_message_page)) {
		pr_err("%s Error!!\n\n", __func__);
		return;
	}

	msg = (struct hv_message *)synic_message_page + HV_SYNIC_INTERCEPTION_SINT_INDEX;
	message_type = READ_ONCE(msg->header.message_type);

	if (message_type == HVMSG_NONE)
		return;

	per_cpu->event_pending = true;
	tasklet_schedule(&per_cpu->handle_intercept);
}

static void mshv_vsm_handle_intercept(unsigned long data)
{
	struct hv_vsm_per_cpu *per_cpu = (void *)data;
	void *page_addr = per_cpu->synic_message_page;
	struct hv_message *msg = (struct hv_message *)page_addr + HV_SYNIC_INTERCEPTION_SINT_INDEX;
	struct hv_intercept_message_header *hdr;
	struct hv_register_assoc *reg_assoc;
	union hv_input_vtl input_vtl;
	u32 message_type = READ_ONCE(msg->header.message_type);
	int ret;

	if (message_type == HVMSG_NONE)
		/* We should not be here. Message corruption?? */
		goto clear_event;

	hdr = (struct hv_intercept_message_header *)msg->u.payload;

	if (cmpxchg(&msg->header.message_type, message_type, HVMSG_NONE) != message_type)
		goto clear_event;

	reg_assoc = kmalloc(sizeof(*reg_assoc), GFP_ATOMIC);

	reg_assoc->name = HV_X64_REGISTER_RIP;
	reg_assoc->value.reg64 = hdr->rip + hdr->instruction_length;
	input_vtl.target_vtl = 0;
	input_vtl.use_target_vtl = 1;

	ret = hv_call_set_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
				       1, input_vtl, reg_assoc);
	if (ret)
		pr_err("%s: Error advancing instruction pointer of VTL0\n", __func__);
	kfree(reg_assoc);

	/* ToDo: Error handling of reg_assoc */

	if (msg->header.message_flags.msg_pending)
		hv_set_register(REG_EOM, 0);
clear_event:
	/* Should interrupts be disabled ?? */
	per_cpu->event_pending = false;
}

static void mshv_vsm_lock_crs(void)
{
	struct hv_register_assoc *reg_assoc;
	union hv_cr_intercept_control ctrl, ctrl1;
	union hv_input_vtl input_vtl;
	int ret;

	ctrl.as_u64 = 0;
	ctrl.cr4_write = 1;

	/* ToDo: Error Handling for kmalloc */
	reg_assoc = kmalloc(2 * sizeof(*reg_assoc), GFP_KERNEL);
	reg_assoc[0].name = HV_REGISTER_CR_INTERCEPT_CONTROL;
	reg_assoc[0].value.reg64 = ctrl.as_u64;
	reg_assoc[1].name = HV_REGISTER_CR_INTERCEPT_CR4_MASK;
	reg_assoc[1].value.reg64 = 0xffffffff;
	input_vtl.as_uint8 = 0;
	ret = hv_call_set_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
				       2, input_vtl, reg_assoc);
	/* ToDo: Error Handling */

	/* To Do: Remove */
	reg_assoc[0].value.reg64 = 0xff;
	reg_assoc[1].value.reg64 = 0x0;
	ctrl1.as_u64 = 0xff;
	ret = hv_call_get_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
				       2, input_vtl, reg_assoc);
	ctrl1.as_u64 = reg_assoc[0].value.reg64;
	kfree(reg_assoc);
}

static void mshv_vsm_handle_entry(struct mshv_vtl_call_params *_vtl_params)
{
	int ret = 0;
	u32 permissions = 0x00;

	switch (_vtl_params->_a0) {
		case VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY:
			pr_info("%s : VSM_PROTECT_MEMORY\n", __func__);
			pr_info("%s : a0:%llx a1:%llx, a2:%llx, a3:%llx\n", __func__,
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
			mshv_vsm_lock_crs();
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
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);

	while (per_cpu->event_pending)
		schedule();

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

	/* Ordering is important. Suspend tick before disabling interrupts */
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

static int mshv_vsm_configure_partition(void)
{
	union hv_vsm_partition_config config;
	struct hv_register_assoc reg_assoc;
	union hv_input_vtl input_vtl;

	config.as_u64 = 0;
	config.default_vtl_protection_mask = HV_MAP_GPA_PERMISSIONS_MASK;
	config.enable_vtl_protection = 1;
//	config.zero_memory_on_reset = 1;
//	config.intercept_vp_startup = 1;
//	config.intercept_cpuid_unimplemented = 1;

/*	if (mshv_vsm_capabilities.intercept_page_available) {
		pr_debug("%s: using intercept page", __func__);
		config.intercept_page = 1;
	}
*/
	reg_assoc.name = HV_REGISTER_VSM_PARTITION_CONFIG;
	reg_assoc.value.reg64 = config.as_u64;
	input_vtl.as_uint8 = 0;

	return hv_call_set_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
					1, input_vtl, &reg_assoc);
}

static int mshv_vsm_per_cpu_init(unsigned int cpu)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);

	memset(per_cpu, 0, sizeof(*per_cpu));

	per_cpu->synic_message_page = (void *)get_zeroed_page(GFP_ATOMIC);
	if (!per_cpu->synic_message_page) {
		pr_err("%s: Unable to allocate SYNIC message page\n", __func__);
		return -ENOMEM;
	}
	// ToDo: Handle nested ?
	/* Set the message page */
	hv_synic_enable_page(HV_REGISTER_SIMP, &per_cpu->synic_message_page);
//	hv_synic_enable_page(HV_REGISTER_SIEFP, &hv_cpu->synic_event_page);

	/* Enable tasklet to handle the intercepts */
	tasklet_init(&per_cpu->handle_intercept, mshv_vsm_handle_intercept,
		     (unsigned long)per_cpu);

	/* ToDo: per-cpu interrupt enabling for supported architectures like arm64 */
	/* Unmask SINT0 so that the cpu can receive intercepts from Hyper-V */
	hv_synic_unmask_sint(HV_REGISTER_SINT0 + HV_SYNIC_INTERCEPTION_SINT_INDEX,
			     HYPERVISOR_CALLBACK_VECTOR);
	/* Enable the global synic bit */
	hv_synic_enable_sctrl(HV_REGISTER_SCONTROL);
	return 0;
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
	int ret = 0;

	ret = misc_register(&mshv_vsm_dev);
	if (ret) {
		pr_err("VSM: Could not register mshv_vsm_vtl_ioctl\n");
		return ret;
	}

	if (mshv_vsm_configure_partition()) {
		pr_emerg("%s: VSM configuration failed !!\n", __func__);
		return -EPERM;
	}

	/* ToDo : per-cpu interrupt enabling for supported architectures like arm64 */
	hv_setup_vsm_handler(mshv_vsm_isr);

	/* Initialize hyper-v per cpu context */
	// ToDo: Introduce clean up function
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "hyperv/vsm:init",
				mshv_vsm_per_cpu_init, NULL);

	if (ret < 0)
		/* ToDo: free the synic message page and kill the tasklet */
		hv_remove_vsm_handler();
	/*
	 * Conscious choice not to call misc_deregister during error exit so that system
	 * can go back to VTL0 even in case of errors
	 */
	return ret;
}

static void __exit mshv_vtl1_exit(void) {
    misc_deregister(&mshv_vsm_dev);
    pr_info("mshv_vsm_dev device unregistered\n");
}

module_init(mshv_vtl1_init);
module_exit(mshv_vtl1_exit);
