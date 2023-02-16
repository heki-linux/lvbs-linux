#include <asm/apic.h>
#include <asm/boot.h>
#include <asm/realmode.h>
#include <asm/mshyperv.h>
#include <linux/hyperv.h>
#include <linux/panic_notifier.h>
#include <linux/version.h>

extern struct boot_params boot_params;
static struct real_mode_header hv_mshv_real_mode_header;

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

typedef void (*secondary_startup_64_fn)(void*, void*);
static void mshv_ap_entry(void)
{
	/*
	 * TODO remove this ugly hack.
	 * This is to win the race against irq_affinity_online_cpu.
	 */
	static int cpu_count = 1;
	u64 msr_vp_index;

	rdmsrl(HV_X64_MSR_VP_INDEX, msr_vp_index);
	hv_vp_index[cpu_count++] = msr_vp_index;

	((secondary_startup_64_fn)secondary_startup_64)(&boot_params, &boot_params);
}

static void mshv_bringup_vpcu(u32 target_vp_index, u64 eip_ignored)
{
	u64 status;
	struct hv_enable_vp_vtl initial_vp_context;

	struct desc_ptr gdt_ptr;
	struct desc_ptr idt_ptr;

	struct ldttss_desc *tss;
	struct ldttss_desc *ldt;
	struct desc_struct *gdt;

	u64 rsp = initial_stack;
	u64 rip = (u64)&mshv_ap_entry;

	mshv_store_gdt(&gdt_ptr);
	mshv_store_idt(&idt_ptr);

	gdt = (struct desc_struct *)((void *)(gdt_ptr.address));
	tss = (struct ldttss_desc *)(gdt + GDT_ENTRY_TSS);
	ldt = (struct ldttss_desc *)(gdt + GDT_ENTRY_LDT);

	memset(&initial_vp_context, 0, sizeof(initial_vp_context));

	initial_vp_context.partition_id = HV_PARTITION_ID_SELF;
	initial_vp_context.vp_index = target_vp_index;
	initial_vp_context.target_vtl.target_vtl = HV_VTL_MGMT;

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
		panic("HVCALL_ENABLE_VP_VTL failed: error %#llx\n", status);

	status = hv_do_hypercall(HVCALL_START_VP, &initial_vp_context, NULL);

	if (status != HV_STATUS_SUCCESS)
		panic("HVCALL_START_VP failed: error %#llx\n", status);
}

static int hv_mshv_apicid_to_vp_id(u32 apic_id)
{
	u64 control;
	u64 status;
	unsigned long irq_flags;
	struct hv_get_vp_from_apic_id_in *input;
	u32 *output;

	local_irq_save(irq_flags);

	input = (struct hv_get_vp_from_apic_id_in*)(*this_cpu_ptr(hyperv_pcpu_input_arg));
	memset(input, 0, sizeof(*input));
	input->partition_id = HV_PARTITION_ID_SELF;
	input->apic_ids[0] = apic_id;

	output = (u32*)(*this_cpu_ptr(hyperv_pcpu_output_arg));

	control = HV_HYPERCALL_REP_COMP_1 | HVCALL_GET_VP_ID_FROM_APIC_ID;
	status = hv_do_hypercall(control, input, output);

	local_irq_restore(irq_flags);

	if (!hv_result_success(status)) {
		pr_err("failed to get vp id from apic id %d, status %#llx\n", apic_id, status);
		return -1;
	}

	return output[0];
}

static int hv_mshv_wakeup_secondary_cpu(int apicid, unsigned long start_eip)
{
	int vp_id;

	pr_debug("Bringing up VCPU with APIC id %d in VTL2...\n", apicid);
	vp_id = hv_mshv_apicid_to_vp_id(apicid);

	/*
	 * This is a hard error when booting. Various fundamental parts have failed
	 * in concert to let this happen. If the code nevertheless got this far, fail
	 * here not to make the evidence trail colder.
	 * Another argument for the panic is that the VMM requires all VPs to start in
	 * VTL2.
	 */
	if (vp_id < 0)
		panic("Couldn't find VCPU with APIC id %d\n", apicid);
	if (vp_id > ms_hyperv.max_vp_index)
		panic("Invalid VCPU id %d for APIC id %d\n", vp_id, apicid);

	mshv_bringup_vpcu(vp_id, start_eip);
	pr_debug("Waiting for VCPU %d to come up...\n", vp_id);

	return 0;
}

static int __init mshv_vtl2_early_init(void)
{
	/*
	 * `boot_cpu_has` returns the runtime feature support,
	 * and here is the earliest it can be used.
	 */
	if (boot_cpu_has(X86_FEATURE_XSAVE))
		panic("XSAVE has to be disabled as it is not supported by this module.\n"
			  "Please add 'noxsave' to the kernel command line.\n");

	real_mode_header = &hv_mshv_real_mode_header;
	apic->wakeup_secondary_cpu = hv_mshv_wakeup_secondary_cpu;

	return 0;
}
early_initcall(mshv_vtl2_early_init);
