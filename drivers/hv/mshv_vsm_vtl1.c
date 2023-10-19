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
#include <linux/kthread.h>
#include <asm/mshyperv.h>
#include <asm/hyperv-tlfs.h>
#include <asm/fpu/internal.h>
#include <asm/mshv_vtl.h>
#include <uapi/asm-generic/hyperv-tlfs.h>
#include <asm/desc.h>
#include <asm/realmode.h>
#include <asm/mpspec.h>
#include <asm/cpu.h>
#include "vsm.h"
#include "mshv.h"
#include "hyperv_vmbus.h"

extern unsigned int setup_max_cpus;

enum vsm_service_ids {
	VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY = 0x1FFF,
	VSM_VTL_CALL_FUNC_ID_LOCK_CR = 0x1FFFF,
	VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL = 0x1FFFD
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
	struct mshv_vtl_call_params vtl_params;
	bool event_pending;

	void *synic_message_page;
//	void *synic_event_page;

	struct tasklet_struct handle_intercept;
	struct mshv_cpu_context cpu_context;
	struct task_struct *vsm_task;
	bool vtl1_enabled;
};

static DEFINE_PER_CPU(struct hv_vsm_per_cpu, vsm_per_cpu);

/* Remove when we enable AssertVirtualInterrupt  */
extern struct boot_params boot_params;
extern unsigned long initial_code;
extern unsigned long initial_stack;
void start_secondary(void *unused);
struct task_struct *idle_thread_get(unsigned int cpu);

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

typedef void (*secondary_startup_64_fn)(void*, void*);
unsigned int vsm_cpu_up = 1; // VBS: Remove when we enable AssertVirtualInterrupt
static void mshv_vsm_ap_entry(void)
{
	/* VBS: Remove when we enable AssertVirtualInterrupt */
	struct task_struct *idle = idle_thread_get(vsm_cpu_up);
	idle->thread.sp = (unsigned long)task_pt_regs(idle);
	early_gdt_descr.address = (unsigned long)get_cpu_gdt_rw(vsm_cpu_up);
	initial_code = (unsigned long)start_secondary;
	initial_stack  = idle->thread.sp;
	initial_gs = per_cpu_offset(vsm_cpu_up);
	vsm_cpu_up++;

	((secondary_startup_64_fn)secondary_startup_64)(&boot_params, &boot_params);
}

static inline void mshv_store_gdt(struct desc_ptr *dtr)
{
	asm volatile("sgdt %0" : "=m" (*dtr));
}

static inline void mshv_store_idt(struct desc_ptr *dtr)
{
	asm volatile("sidt %0" : "=m" (*dtr));
}

static inline u64 mshv_system_desc_base(struct ldttss_desc *desc)
{
	return ((u64)desc->base3 << 32) |
		   ((u64)desc->base2 << 24) |
		   (desc->base1 << 16) |
		   desc->base0;
}

static inline u32 mshv_system_desc_limit(struct ldttss_desc *desc)
{
	return ((u32)desc->limit1 << 16) | (u32)desc->limit0;
}

static u64 mshv_vsm_enable_ap_vtl(u32 target_vp_index)
{
	u64 status;
	struct hv_enable_vp_vtl initial_vp_context;

	struct desc_ptr gdt_ptr;
	struct desc_ptr idt_ptr;

	struct ldttss_desc *tss;
	struct ldttss_desc *ldt;
	struct desc_struct *gdt;

	u64 rsp = current->thread.sp;
	u64 rip = (u64)&mshv_vsm_ap_entry;

	mshv_store_gdt(&gdt_ptr);
	mshv_store_idt(&idt_ptr);

	gdt = (struct desc_struct *)((void *)(gdt_ptr.address));
	tss = (struct ldttss_desc *)(gdt + GDT_ENTRY_TSS);
	ldt = (struct ldttss_desc *)(gdt + GDT_ENTRY_LDT);

	memset(&initial_vp_context, 0, sizeof(initial_vp_context));

	initial_vp_context.partition_id = HV_PARTITION_ID_SELF;
	initial_vp_context.vp_index = target_vp_index;
	initial_vp_context.target_vtl.target_vtl = HV_VTL_SECURE;

	initial_vp_context.vp_context.rip = rip;
	initial_vp_context.vp_context.rsp = rsp;
	initial_vp_context.vp_context.rflags = 0x0000000000000002;
	initial_vp_context.vp_context.efer = __rdmsr(MSR_EFER);
	initial_vp_context.vp_context.cr0 = native_read_cr0();
	initial_vp_context.vp_context.cr3 = __native_read_cr3();
	initial_vp_context.vp_context.cr4 = native_read_cr4();
	initial_vp_context.vp_context.msr_cr_pat = __rdmsr(MSR_IA32_CR_PAT);

	initial_vp_context.vp_context.idtr.limit = idt_ptr.size;
	initial_vp_context.vp_context.idtr.base = idt_ptr.address;
	initial_vp_context.vp_context.gdtr.limit = gdt_ptr.size;
	initial_vp_context.vp_context.gdtr.base = gdt_ptr.address;

	/* Non-system desc (64bit), long, code, present */
	initial_vp_context.vp_context.cs.selector = __KERNEL_CS;
	initial_vp_context.vp_context.cs.base = 0;
	initial_vp_context.vp_context.cs.limit = 0xffffffff;
	initial_vp_context.vp_context.cs.attributes = 0xa09b;
	/* Non-system desc (64bit), data, present, granularity, default */
	initial_vp_context.vp_context.ss.selector = __KERNEL_DS;
	initial_vp_context.vp_context.ss.base = 0;
	initial_vp_context.vp_context.ss.limit = 0xffffffff;
	initial_vp_context.vp_context.ss.attributes = 0xc093;

	/* System desc (128bit), present, LDT */
	initial_vp_context.vp_context.ldtr.selector = GDT_ENTRY_LDT * 8;
	initial_vp_context.vp_context.ldtr.base = mshv_system_desc_base(ldt);
	initial_vp_context.vp_context.ldtr.limit = mshv_system_desc_limit(ldt);
	initial_vp_context.vp_context.ldtr.attributes = 0x82;

	/* System desc (128bit), present, TSS, 0x8b - busy, 0x89 -- default */
	initial_vp_context.vp_context.tr.selector = GDT_ENTRY_TSS * 8;
	initial_vp_context.vp_context.tr.base = mshv_system_desc_base(tss);
	initial_vp_context.vp_context.tr.limit = mshv_system_desc_limit(tss);
	initial_vp_context.vp_context.tr.attributes = 0x8b;

	status = hv_do_hypercall(HVCALL_ENABLE_VP_VTL, &initial_vp_context, NULL);

	if (status != HV_STATUS_SUCCESS && status != HV_STATUS_VTL_ALREADY_ENABLED)
		pr_err("HVCALL_ENABLE_VP_VTL failed: error %#llx\n", status);

	return status;
}

static u64 mshv_vsm_hotadd_n_enable_aps(unsigned int vsm_cpus)
{
	u64 status = 0;
	unsigned int cpu, present, possible = num_possible_cpus(), online = num_online_cpus(),
		total_cpus_enabled = 0, new_total_cpus = 0;
	struct hv_vsm_per_cpu *per_cpu;
	int ret, i;

	if (!vsm_cpus) {
		pr_err("%s: Invalid parameter. vsm_cpus cannot be 0.\n", __func__);
		return 1;
	}

	if (vsm_cpus > possible-online)
	{
		pr_info("%s: Requested to enable %u CPUs, but there are only %u possible CPUs that are not already online. Will enable %u CPUs instead.",
			__func__, vsm_cpus, possible - online, possible - online);
		vsm_cpus = possible - online;
	}
	
	new_total_cpus = vsm_cpus + online;

	if (new_total_cpus > setup_max_cpus) {
		pr_err("%s: Adding %u CPUs exceeds the maximum number of CPUs (%u)", __func__, vsm_cpus, setup_max_cpus);
		return -1;
	}

	/* Add, initialize and register new Present CPUs */
	for (i = 0; i < new_total_cpus; i++) {
		if (!(cpu_present(i))) {
			ret = generic_processor_info(i, boot_cpu_apic_version);

			if (ret != i)
			{
				pr_err("%s: Failed adding CPU%d. Error code: %d", __func__, i, ret);
				return -1;
			}

			ret = arch_register_cpu(i);

			if (ret)
			{
				pr_err("%s: Failed registering CPU%d. Error code: %d", __func__, i, ret);
				return -1;
			}
		}
	}

	present = num_present_cpus();

	if (!(present-online)) {
		pr_info("%s: Nothing to do. VTL1 kernel has no present CPUs that are not already online.\n",
			__func__);
		return status;
	}

	if (vsm_cpus > present-online)
	{
		pr_info("%s: Requested to enable %u CPUs, but there are only %u present CPUs that are not already online. Will enable %u CPUs instead.",
			__func__, vsm_cpus, present - online, present - online);
		vsm_cpus = present - online;
	}

	/* Loop through present Processors, skip online processors */
	for_each_present_cpu(cpu) {
		if (!cpu_online(cpu)) {
			per_cpu = per_cpu_ptr(&vsm_per_cpu, cpu);
			if (per_cpu->vtl1_enabled)
			{
				pr_info("%s: CPU%u is already enabled for VTL1. Will skip to next CPU",
				__func__, cpu);
				continue;
			}

			status = mshv_vsm_enable_ap_vtl((u32) cpu);

			if (status) {
				pr_err("%s: Failed to enable VTL1 for CPU%u", __func__, cpu);
				return status;
			}

			per_cpu->vtl1_enabled = true;

			/* if we reached the number CPUs that VTL0 requested to enable in VTL1, stop */
			total_cpus_enabled++;
			if (total_cpus_enabled == vsm_cpus)
				break;
		}
	}

	if (total_cpus_enabled < vsm_cpus)
	{
		pr_err("%s: Enabled %u CPUs instead of %u", __func__, total_cpus_enabled, vsm_cpus);
		return -1;
	}

	return status;
}

static void mshv_vsm_handle_entry(struct mshv_vtl_call_params *_vtl_params)
{
	int ret = 0;
	u64 status;
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
		case VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL:
			pr_info("%s : VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL\n", __func__);
			status = mshv_vsm_hotadd_n_enable_aps(_vtl_params->_a1);
			if (status)
				pr_info("%s: failed\n",__func__);
			else
				pr_info("%s: is ok\n",__func__);

			_vtl_params->_a3=status;
			break;
		default:
			pr_err("%s : Wrong service id\n", __func__);
			break;
	}
}

static void mshv_vsm_interrupt_handle_entry(void)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);

	while (per_cpu->event_pending)
		schedule();
}

/* DO NOT MODIFY THIS FUNCTION WITHOUT DISASSEMBLING AND SEEING WHAT IS GOING ON */
static void __mshv_vsm_vtl_return(void)
{
	register struct mshv_cpu_context *cpu_context asm ("rax");
	register u64 r8 asm("r8");
	register u64 r9 asm("r9");
	register u64 r10 asm("r10");
	register u64 r11 asm("r11");
	register u64 r12 asm("r12");
	register u64 r13 asm("r13");
	register u64 r14 asm("r14");
	register u64 r15 asm("r15");

	/*
	 * All VTL0 registers are saved and restored. The only exception for now is VTL0
	 * rax and rcx. This is a non-issue if the entry reason is HvVtlEntryVtlCall since VTL0
	 * will take care of saving an restoring rax and rcx. However if the entry reason is
	 * HvVtlEntryInterrupt, VTL0 rax and rcx are lost. Only way to fix this is to implement
	 * the jump into hypercall page for return to VTL0. The first part before vmcall restores
	 * all VTL0 registers and the part after vmcall saves. For registers r8-r15 the compiler
	 * translates the following c code into write of value in cpu_context->r# to actual cpu
	 * register r# prior to vmcall and save the content of cpu register r# into cpu_context->r#
	 * post vmcall.
	 *		 register u64 r# asm("r#");
	 *		 r# = cpu_context->r#;
	 *		 asm __volatile(some instruction
	 *				some instruction
	 *				vmcall
	 *				some instruction
	 *				some instruction
	 *				: +r(r#)
	 *				:
	 *				:);
	 *		cpu_context->r# = r#;
	 * For registers rdx, rbx, rdi and rsi the complier again translates the following c code
	 * into restoring and saving of these registers from/tp corresponding cpu_context-># across
	 * the vmcall.
	 *		 asm __volatile(some instruction
	 *				some instruction
	 *				vmcall
	 *				some instruction
	 *				some instruction
	 *				: "+d"(cpu_context->rdx), "+b"(cpu_context->rbx),
	 *				  "+S"(cpu_context->rsi), "+D"(cpu_context->rdi)
	 *				:
	 *				:);
	 * rbp alone requires explicit restore and save which is performed in the inline
	 * assembly code below.
	 *
	 * Regarding VTL1 registers only VTL1 rbp and rax are saved and restored. rax is
	 * saved and restored so as to preserve pointer to cpu_context across vmcall. rbp
	 * is weird since sometimes it gets used before the exit of __mshv_vsm_vtl_return
	 * and not saving and restoring can lead to crashes
	 * There is very little happening in this function post vmcall, just minimal saving
	 * of VTL0 context into cpu_context which is stored in rax. Technically no other
	 * VTL1 register gets used in this function post vmcall. As per x64 function calling
	 * conventions registers rbx, rbp and r12-r15 are callee saved and hence the compiler
	 * automatically saves and restores them across the boundary of a function call i.e.
	 * when __mshv_vsm_vtl_return exits these registers are restored. Rest of the registers
	 * are caller saved and the caller of __mshv_vsm_vtl_return takes care of saving and
	 * restoring. Thus no other VTL1 register needs explicit saving and restoring.
	 */
	cpu_context = &this_cpu_ptr(&vsm_per_cpu)->cpu_context;

	asm __volatile__("pushq %%rbp\n"	// Save VTL1 rbp
			 "pushq %%rax\n"	// Push VTL1 rax i.e. save *cpu_context
			 :
			 : "a"(cpu_context)
			 : );
	r8 = cpu_context->r8;
	r9 = cpu_context->r9;
	r10 = cpu_context->r10;
	r11 = cpu_context->r11;
	r12 = cpu_context->r12;
	r13 = cpu_context->r13;
	r14 = cpu_context->r14;
	r15 = cpu_context->r15;
	asm __volatile__("movq %0, %%rbp\n"	// Load rbp with saved VTL0 rbp
			 "movq $0x00, %%rax\n"
			 "movq $0x12, %%rcx\n"
			 "vmcall\n"
			 "pushq %%rax\n"	// Push VTL0 rax into stack
			 "pushq %%rcx\n"	// Push VTL0 rcx into stack to align at 16 bytes
			 "movq 16(%%rsp), %%rax\n" // Restore rax to *cpu_context
			 "movq %%rbp, %0\n"	// Save VTL0 rbp
			 "popq %1\n"	// Save VTL0 rcx
			 "popq %2\n"	// Save VTL0 rax
			 "movq 8(%%rsp), %%rbp\n"	// Restore VTL1 rbp
			 "addq $16, %%rsp\n"	// Restore VTL1 stack to prior condition
			 : "+m"(cpu_context->rbp), "=m"(cpu_context->rcx), "=m"(cpu_context->rax),
			   "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11), "+r"(r12), "+r"(r13),
			   "+r"(r14), "+r"(r15), "+d"(cpu_context->rdx), "+b"(cpu_context->rbx),
			   "+S"(cpu_context->rsi), "+D"(cpu_context->rdi)
			 : "a"(cpu_context)
			 : );
	cpu_context->r8 = r8;
	cpu_context->r9 = r9;
	cpu_context->r10 = r10;
	cpu_context->r11 = r11;
	cpu_context->r12 = r12;
	cpu_context->r13 = r13;
	cpu_context->r14 = r14;
	cpu_context->r15 = r15;
}

static int mshv_vsm_vtl_return(void *unused)
{
	unsigned long irq_flags;
	struct hv_vp_assist_page *hvp;
	struct hv_vsm_per_cpu *per_cpu;
	struct mshv_cpu_context *cpu_context;
	struct mshv_vtl_call_params *vtl_params;

	while (true) {
		/* Ordering is important. Suspend tick before disabling interrupts */
		tick_suspend_local();
		local_irq_save(irq_flags);
		kernel_fpu_begin_mask(0);

		__mshv_vsm_vtl_return();

		kernel_fpu_end();
		tick_resume_local();
		local_irq_restore(irq_flags);

		/* Without this interrupt handler is not kick started */
		schedule();
		hvp = hv_vp_assist_page[smp_processor_id()];
		switch (hvp->vtl_entry_reason) {
		case HvVtlEntryVtlCall:
			/*
			 *  VTL0 can pass four arguments to VTL1 in registers rdi,
			 *  rsi, rdx and rbx respectively. rbx is also used to pass
			 *  success or failure back to VTL0.
			 */
			per_cpu = this_cpu_ptr(&vsm_per_cpu);
			cpu_context = &per_cpu->cpu_context;
			vtl_params = &per_cpu->vtl_params;

			vtl_params->_a0 = cpu_context->rdi;
			vtl_params->_a1 = cpu_context->rsi;
			vtl_params->_a2 = cpu_context->rdx;
			vtl_params->_a3 = cpu_context->r8;
			pr_info("CPU%u: MSHV_ENTRY_REASON_LOWER_VTL_CALL\n", smp_processor_id());
			mshv_vsm_handle_entry(vtl_params);
			cpu_context->rdi = vtl_params->_a0;
			cpu_context->rsi = vtl_params->_a1;
			cpu_context->rdx = vtl_params->_a2;
			cpu_context->r8 =  vtl_params->_a3;
			break;
		case HvVtlEntryInterrupt:
			pr_info("CPU%u: MSHV_ENTRY_REASON_INTERRUPT\n", smp_processor_id());
			mshv_vsm_interrupt_handle_entry();
			break;
		default:
			pr_info("CPU%u: Unknown entry reason: %d", smp_processor_id(), hvp->vtl_entry_reason);
			break;
		}
	}
	return 0;
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
	per_cpu->vsm_task = kthread_create(mshv_vsm_vtl_return, NULL, "vsm_task");
	kthread_bind(per_cpu->vsm_task, cpu);

	return 0;
}

static bool enable_ioctl = true;
static long mshv_vsm_vtl_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	long ret = 0;
	struct hv_vsm_per_cpu *per_cpu;

	switch (ioctl) {
	case MSHV_VTL_RETURN_TO_LOWER_VTL:
		if (enable_ioctl) {
			enable_ioctl = false; // IOCTL is used only once

			/*
			* Schedule the main kthread that will deal with entry/exit from VTL1 and
			* put the init process to sleep.
			*/
			per_cpu = this_cpu_ptr(&vsm_per_cpu);
			wake_up_process(per_cpu->vsm_task);
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule();
		}
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
