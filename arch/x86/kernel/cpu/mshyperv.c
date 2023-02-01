// SPDX-License-Identifier: GPL-2.0-only
/*
 * HyperV  Detection code.
 *
 * Copyright (C) 2010, Novell, Inc.
 * Author : K. Y. Srinivasan <ksrinivasan@novell.com>
 */

#include <linux/types.h>
#include <linux/time.h>
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/hardirq.h>
#include <linux/efi.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kexec.h>
#include <linux/i8253.h>
#include <linux/random.h>
#include <linux/memblock.h>
#include <linux/crash_dump.h>
#include <asm/processor.h>
#include <asm/hypervisor.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>
#include <asm/desc.h>
#include <asm/idtentry.h>
#include <asm/irq_regs.h>
#include <asm/i8259.h>
#include <asm/apic.h>
#include <asm/timer.h>
#include <asm/reboot.h>
#include <asm/nmi.h>
#include <clocksource/hyperv_timer.h>
#include <asm/numa.h>
#include <asm/e820/api.h>

/* Is Linux running as the root partition? */
bool hv_root_partition;
/* Is Linux running on nested Microsoft Hypervisor */
bool hv_nested;
struct ms_hyperv_info ms_hyperv;

#if IS_ENABLED(CONFIG_HYPERV)
static void (*mshv_handler)(void);
static void (*vmbus_handler)(void);
static void (*hv_stimer0_handler)(void);
static void (*hv_kexec_handler)(void);
static void (*hv_crash_handler)(struct pt_regs *regs);

DEFINE_IDTENTRY_SYSVEC(sysvec_hyperv_callback)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(irq_hv_callback_count);
	if (mshv_handler)
		mshv_handler();

	if (vmbus_handler)
		vmbus_handler();

	if (ms_hyperv.hints & HV_DEPRECATING_AEOI_RECOMMENDED)
		ack_APIC_irq();

	set_irq_regs(old_regs);
}

DEFINE_IDTENTRY_SYSVEC(sysvec_hyperv_nested_vmbus_intr)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(irq_hv_callback_count);

	if (vmbus_handler)
		vmbus_handler();

	if (ms_hyperv.hints & HV_DEPRECATING_AEOI_RECOMMENDED)
		ack_APIC_irq();

	set_irq_regs(old_regs);
}

void hv_setup_mshv_irq(void (*handler)(void))
{
	mshv_handler = handler;
}

void hv_remove_mshv_irq(void)
{
	mshv_handler = NULL;
}

void hv_setup_vmbus_handler(void (*handler)(void))
{
	vmbus_handler = handler;
}

void hv_remove_vmbus_handler(void)
{
	/* We have no way to deallocate the interrupt gate */
	vmbus_handler = NULL;
}

/*
 * Routines to do per-architecture handling of stimer0
 * interrupts when in Direct Mode
 */
DEFINE_IDTENTRY_SYSVEC(sysvec_hyperv_stimer0)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(hyperv_stimer0_count);
	if (hv_stimer0_handler)
		hv_stimer0_handler();
	add_interrupt_randomness(HYPERV_STIMER0_VECTOR);
	ack_APIC_irq();

	set_irq_regs(old_regs);
}

/* For x86/x64, override weak placeholders in hyperv_timer.c */
void hv_setup_stimer0_handler(void (*handler)(void))
{
	hv_stimer0_handler = handler;
}

void hv_remove_stimer0_handler(void)
{
	/* We have no way to deallocate the interrupt gate */
	hv_stimer0_handler = NULL;
}

void hv_setup_kexec_handler(void (*handler)(void))
{
	hv_kexec_handler = handler;
}

void hv_remove_kexec_handler(void)
{
	hv_kexec_handler = NULL;
}

void hv_setup_crash_handler(void (*handler)(struct pt_regs *regs))
{
	hv_crash_handler = handler;
}

void hv_remove_crash_handler(void)
{
	hv_crash_handler = NULL;
}

#ifdef CONFIG_KEXEC_CORE
static void hv_machine_shutdown(void)
{
	if (kexec_in_progress && hv_kexec_handler)
		hv_kexec_handler();

	/*
	 * Call hv_cpu_die() on all the CPUs, otherwise later the hypervisor
	 * corrupts the old VP Assist Pages and can crash the kexec kernel.
	 */
	if (kexec_in_progress && hyperv_init_cpuhp > 0)
		cpuhp_remove_state(hyperv_init_cpuhp);

	/* The function calls stop_other_cpus(). */
	native_machine_shutdown();

	/* Disable the hypercall page when there is only 1 active CPU. */
	if (kexec_in_progress)
		hyperv_cleanup();
}

static void hv_machine_crash_shutdown(struct pt_regs *regs)
{
	if (hv_crash_handler)
		hv_crash_handler(regs);

	/* The function calls crash_smp_send_stop(). */
	native_machine_crash_shutdown(regs);

	/* Disable the hypercall page when there is only 1 active CPU. */
	hyperv_cleanup();
}
#endif /* CONFIG_KEXEC_CORE */
#endif /* CONFIG_HYPERV */

static uint32_t  __init ms_hyperv_platform(void)
{
	u32 eax;
	u32 hyp_signature[3];

	if (!boot_cpu_has(X86_FEATURE_HYPERVISOR))
		return 0;

	cpuid(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS,
	      &eax, &hyp_signature[0], &hyp_signature[1], &hyp_signature[2]);

	if (eax < HYPERV_CPUID_MIN || eax > HYPERV_CPUID_MAX ||
	    memcmp("Microsoft Hv", hyp_signature, 12))
		return 0;

	/* HYPERCALL and VP_INDEX MSRs are mandatory for all features. */
	eax = cpuid_eax(HYPERV_CPUID_FEATURES);
	if (!(eax & HV_MSR_HYPERCALL_AVAILABLE)) {
		pr_warn("x86/hyperv: HYPERCALL MSR not available.\n");
		return 0;
	}
	if (!(eax & HV_MSR_VP_INDEX_AVAILABLE)) {
		pr_warn("x86/hyperv: VP_INDEX MSR not available.\n");
		return 0;
	}

	return HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS;
}

static unsigned char hv_get_nmi_reason(void)
{
	return 0;
}

#ifdef CONFIG_X86_LOCAL_APIC
/*
 * Prior to WS2016 Debug-VM sends NMIs to all CPUs which makes
 * it difficult to process CHANNELMSG_UNLOAD in case of crash. Handle
 * unknown NMI on the first CPU which gets it.
 */
static int hv_nmi_unknown(unsigned int val, struct pt_regs *regs)
{
	static atomic_t nmi_cpu = ATOMIC_INIT(-1);

	if (!unknown_nmi_panic)
		return NMI_DONE;

	if (atomic_cmpxchg(&nmi_cpu, -1, raw_smp_processor_id()) != -1)
		return NMI_HANDLED;

	return NMI_DONE;
}
#endif

static unsigned long hv_get_tsc_khz(void)
{
	unsigned long freq;

	rdmsrl(HV_X64_MSR_TSC_FREQUENCY, freq);

	return freq / 1000;
}

#if defined(CONFIG_SMP) && IS_ENABLED(CONFIG_HYPERV)
static void __init hv_smp_prepare_boot_cpu(void)
{
	native_smp_prepare_boot_cpu();
#if defined(CONFIG_X86_64) && defined(CONFIG_PARAVIRT_SPINLOCKS)
	hv_init_spinlocks();
#endif
}

static int apicids[NR_CPUS] __initdata;

/* find the next smallest apicid in the unsorted array of size NR_CPUS */
static int __init next_smallest_apicid(int apicids[], int curr)
{
	int i, found = INT_MAX;

	for (i = 0; i < NR_CPUS; i++) {
		if (apicids[i] <= curr)
			continue;

		if (apicids[i] < found)
			found = apicids[i];
	}

	return found;
}

/*  
 * On a 4 core, single node, with HT, linux numbers cpus as: 
 *     [0]c0 ht0   [1]c1 ht0   [2]c2 ht0   [3]c3 ht0
 *     [4]c0 ht1   [5]c1 ht1   [6]c2 ht1   [7]c3 ht1
 *
 * On a 4 core, two nodes, with HT, linux numbers cpus as: 
 *     [0]n0 c0 h0    [1]n1 c0 ht0  [2]n0 c3 ht0 ......
 *
 * MSHV wants vcpus/vpidxs: [0]c0 ht0, [1]c0 ht1, [2]c1 ht0, [3]c1 ht1 ....
 * for the default core scheduler. classic scheduler doesn't care.
 * The requirement means linux cpu numbers and vcpu index won't
 * match. The driver uses hv_vp_index[] for that indirection.
 *
 * Other requirements are:
 *  - LPs must be added in only lpindex order, with any lapic ids for any lp
 *  - VPs can be created in any vp index order as long as the HT siblings 
 *    match.
 *
 * To achieve above, we add LPs in order of apic ids.
 */
static void __init hv_smp_prepare_cpus(unsigned int max_cpus)
{
#ifdef CONFIG_X86_64
	s16 node = 0;
	int i, lpidx, ret, ccpu = raw_smp_processor_id();
#endif
	native_smp_prepare_cpus(max_cpus);

#ifdef CONFIG_X86_64
	BUG_ON(ccpu != 0);

	for (i = 0; i < NR_CPUS; i++)
		apicids[i] = INT_MAX;

	for_each_present_cpu(i) {
		if (i == 0)
			continue;

		BUG_ON(cpu_physical_id(i) == INT_MAX);
		apicids[i] = cpu_physical_id(i);
	}

	i = next_smallest_apicid(apicids, 0);
	for (lpidx = 1; i != INT_MAX; lpidx++) {
#ifdef CONFIG_NUMA
		node = __apicid_to_node[i];
		if (node == NUMA_NO_NODE)
			node = 0;
#endif

		/* params: node num, lp index, apic id */
		ret = hv_call_add_logical_proc(node, lpidx, i);
		BUG_ON(ret);

		i = next_smallest_apicid(apicids, i);
	}

	/*
	 * We should only call this hypercall once we have added all the logical
	 * processors to the root partition.
	 *
	 * This is a strict requirement for CVM because without this hypercall
	 * MSHV won't expose support for launching SEV-SNP enabled guest.
	 *
	 * We can also invoke this hypercall for non-CVM usecase as well. There
	 * is no side effect because of this hypercall.
	 */
	ret = hv_call_notify_all_processors_started();
	WARN_ON(ret);

	lpidx = 1;	   /* skip BSP cpu 0 */
	for_each_present_cpu(i) {
		if (i == 0)
			continue;

		/* params: node num, domid, vp index, lp index */
		ret = hv_call_create_vp(numa_cpu_node(i), 
					hv_current_partition_id, lpidx, lpidx);
		BUG_ON(ret);
		lpidx++;
	}

#endif /* #ifdef CONFIG_X86_64 */
}
#endif /* #if defined(CONFIG_SMP) && IS_ENABLED(CONFIG_HYPERV) */

#define HV_MAX_RESVD_RANGES 32
static int hv_resvd_ranges[HV_MAX_RESVD_RANGES] =
				{[0 ... HV_MAX_RESVD_RANGES-1] = -1};
static struct resource hv_mshv_res[HV_MAX_RESVD_RANGES];

/*
 * parse eg "hyperv_resvd=3,7,20" where 3, 7, and 20 are indexes into the e820
 * table for ranges that are reserved by the loader for the hypervisor
 */
static int __init hv_parse_hyperv_resvd(char *arg)
{
	int idx, max = ARRAY_SIZE(hv_resvd_ranges);
	int i = 0;

	if (is_kdump_kernel())
		return 0;

	if (hv_resvd_ranges[0] != -1) {
		pr_err("Hyper-V: multile hyperv_resvd not supported\n");
		return 0;
	}

	while (get_option(&arg, &idx)) {
		if (i >= max) {
			pr_err("Hyper-V: resvd ranges tbl full %d\n", idx);
			break;
		}

		hv_resvd_ranges[i++] = idx;
	}

	return 0;
}
early_param("hyperv_resvd", hv_parse_hyperv_resvd);

/*
 * Reserve memory that the hypervisor is using early on. The ranges are marked
 * reserved by a custom bootloader, change that to usable and reserve that
 * range. Note, the bootloader sanitizes the e820 before passing on here.
 */
static void __init hv_resv_mshv_memory(void)
{
	u64 start, end, size;
	int i, idx, max = ARRAY_SIZE(hv_resvd_ranges);

	for (i = 0; i < max && hv_resvd_ranges[i] != -1; i++) {

		idx = hv_resvd_ranges[i];
		if (idx < 0 || idx >= e820_table->nr_entries) {
			pr_info("Hyper-V: invalid resvd idx %d\n", idx);
			continue;
		}

		start = e820_table->entries[idx].addr;
		size = e820_table->entries[idx].size;
		end = start + size - 1;

		memblock_reserve(start, size);
		e820_table->entries[idx].type = E820_TYPE_RAM;
		pr_info("Hyper-V reserve [mem %#018Lx-%#018Lx]\n", start, end);

		hv_mshv_res[i].name = "Hypervisor Code and Data";
		hv_mshv_res[i].flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM;
		hv_mshv_res[i].start = start;
		hv_mshv_res[i].end = end;
	}
}

/* this cannot be done during platform init, hence called from hyperv_init() */
void __init hv_mark_resources(void)
{
	int i, max = ARRAY_SIZE(hv_mshv_res);

	for (i = 0; i < max && hv_mshv_res[i].end; i++)
		insert_resource(&iomem_resource, &hv_mshv_res[i]);
}

#ifdef CONFIG_HYPERV_VTL
static struct legacy_pic vtl2_pic;

static void __init hv_vtl2_apic_intr_mode_select(void)
{
	apic_intr_mode = APIC_SYMMETRIC_IO;
}

static void hv_vtl2_get_wallclock(struct timespec64 *now)
{
	now->tv_sec = now->tv_nsec = 0;
}

static int hv_vtl2_set_wallclock(const struct timespec64 *now)
{
	return -EINVAL;
}

static int vtl2_pic_probe(void)
{
	null_legacy_pic.probe();
	return vtl2_pic.nr_legacy_irqs;
}

static void __init hv_vtl2_init_platform(void)
{
	pr_info("Initializing Hyper-V MSHV\n");

	x86_init.irqs.intr_mode_select = hv_vtl2_apic_intr_mode_select;
	x86_init.irqs.pre_vector_init = x86_init_noop;
	x86_init.timers.timer_init = x86_init_noop;

	x86_platform.get_wallclock = hv_vtl2_get_wallclock;
	x86_platform.set_wallclock = hv_vtl2_set_wallclock;
	x86_platform.get_nmi_reason = hv_get_nmi_reason;

	x86_platform.legacy.i8042 = X86_LEGACY_I8042_PLATFORM_ABSENT;
	x86_platform.legacy.rtc = 0;
	x86_platform.legacy.warm_reset = 0;
	x86_platform.legacy.reserve_bios_regions = 0;
	x86_platform.legacy.devices.pnpbios = 0;
	/*
	 * Do not try to access the PIC (even if it is there).
	 * Reserve 1 IRQ so that PCI MSIs to not get allocated to virq 0,
	 * which is not generally considered a valid IRQ by Linux (and so
	 * causes various problems).
	 */
	vtl2_pic = null_legacy_pic;
	vtl2_pic.nr_legacy_irqs = 1;
	vtl2_pic.probe = vtl2_pic_probe;
	legacy_pic = &vtl2_pic;
}
#endif

static void __init ms_hyperv_init_platform(void)
{
	int hv_max_functions_eax;
	int hv_host_info_eax;
	int hv_host_info_ebx;
	int hv_host_info_ecx;
	int hv_host_info_edx;

#ifdef CONFIG_PARAVIRT
	pv_info.name = "Hyper-V";
#endif

	/*
	 * Extract the features and hints
	 */
	ms_hyperv.features = cpuid_eax(HYPERV_CPUID_FEATURES);
	ms_hyperv.priv_high = cpuid_ebx(HYPERV_CPUID_FEATURES);
	ms_hyperv.misc_features = cpuid_edx(HYPERV_CPUID_FEATURES);
	ms_hyperv.hints    = cpuid_eax(HYPERV_CPUID_ENLIGHTMENT_INFO);

	hv_max_functions_eax = cpuid_eax(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS);

	pr_info("Hyper-V: privilege flags low 0x%x, high 0x%x, hints 0x%x, misc 0x%x\n",
		ms_hyperv.features, ms_hyperv.priv_high, ms_hyperv.hints,
		ms_hyperv.misc_features);

	ms_hyperv.max_vp_index = cpuid_eax(HYPERV_CPUID_IMPLEMENT_LIMITS);
	ms_hyperv.max_lp_index = cpuid_ebx(HYPERV_CPUID_IMPLEMENT_LIMITS);

	pr_debug("Hyper-V: max %u virtual processors, %u logical processors\n",
		 ms_hyperv.max_vp_index, ms_hyperv.max_lp_index);

	/*
	 * Check CPU management privilege.
	 *
	 * To mirror what Windows does we should extract CPU management
	 * features and use the ReservedIdentityBit to detect if Linux is the
	 * root partition. But that requires negotiating CPU management
	 * interface (a process to be finalized).
	 *
	 * For now, use the privilege flag as the indicator for running as
	 * root.
	 */
	if (cpuid_ebx(HYPERV_CPUID_FEATURES) & HV_CPU_MANAGEMENT) {
		hv_root_partition = true;
		pr_info("Hyper-V: running as root partition\n");

		/* very first thing, reserve exclusive hypervisor memory */
		hv_resv_mshv_memory();
	}

	if (ms_hyperv.hints & HV_X64_HYPERV_NESTED) {
		hv_nested = true;
		pr_info("Hyper-V: Linux running on a nested hypervisor\n");
	}

	/*
	 * Extract host information.
	 */
	if (hv_max_functions_eax >= HYPERV_CPUID_VERSION) {
		hv_host_info_eax = cpuid_eax(HYPERV_CPUID_VERSION);
		hv_host_info_ebx = cpuid_ebx(HYPERV_CPUID_VERSION);
		hv_host_info_ecx = cpuid_ecx(HYPERV_CPUID_VERSION);
		hv_host_info_edx = cpuid_edx(HYPERV_CPUID_VERSION);

		pr_info("Hyper-V Host Build:%d-%d.%d-%d-%d.%d\n",
			hv_host_info_eax, hv_host_info_ebx >> 16,
			hv_host_info_ebx & 0xFFFF, hv_host_info_ecx,
			hv_host_info_edx >> 24, hv_host_info_edx & 0xFFFFFF);
	}

	if (ms_hyperv.features & HV_ACCESS_FREQUENCY_MSRS &&
	    ms_hyperv.misc_features & HV_FEATURE_FREQUENCY_MSRS_AVAILABLE) {
		x86_platform.calibrate_tsc = hv_get_tsc_khz;
		x86_platform.calibrate_cpu = hv_get_tsc_khz;
	}

	if (ms_hyperv.priv_high & HV_ISOLATION) {
		ms_hyperv.isolation_config_a = cpuid_eax(HYPERV_CPUID_ISOLATION_CONFIG);
		ms_hyperv.isolation_config_b = cpuid_ebx(HYPERV_CPUID_ISOLATION_CONFIG);

		pr_info("Hyper-V: Isolation Config: Group A 0x%x, Group B 0x%x\n",
			ms_hyperv.isolation_config_a, ms_hyperv.isolation_config_b);
	}

	if (hv_max_functions_eax >= HYPERV_CPUID_NESTED_FEATURES) {
		ms_hyperv.nested_features =
			cpuid_eax(HYPERV_CPUID_NESTED_FEATURES);
		pr_info("Hyper-V: Nested features: 0x%x\n",
			ms_hyperv.nested_features);
	}

#ifdef CONFIG_X86_LOCAL_APIC
	if (ms_hyperv.features & HV_ACCESS_FREQUENCY_MSRS &&
	    ms_hyperv.misc_features & HV_FEATURE_FREQUENCY_MSRS_AVAILABLE) {
		/*
		 * Get the APIC frequency.
		 */
		u64	hv_lapic_frequency;

		rdmsrl(HV_X64_MSR_APIC_FREQUENCY, hv_lapic_frequency);
		hv_lapic_frequency = div_u64(hv_lapic_frequency, HZ);
		lapic_timer_period = hv_lapic_frequency;
		pr_info("Hyper-V: LAPIC Timer Frequency: %#x\n",
			lapic_timer_period);
	}

	register_nmi_handler(NMI_UNKNOWN, hv_nmi_unknown, NMI_FLAG_FIRST,
			     "hv_nmi_unknown");
#endif

#ifdef CONFIG_X86_IO_APIC
	no_timer_check = 1;
#endif

#if IS_ENABLED(CONFIG_HYPERV) && defined(CONFIG_KEXEC_CORE)
	machine_ops.shutdown = hv_machine_shutdown;
	machine_ops.crash_shutdown = hv_machine_crash_shutdown;
#endif
	if (ms_hyperv.features & HV_ACCESS_TSC_INVARIANT) {
		/*
		 * Writing to synthetic MSR 0x40000118 updates/changes the
		 * guest visible CPUIDs. Setting bit 0 of this MSR  enables
		 * guests to report invariant TSC feature through CPUID
		 * instruction, CPUID 0x800000007/EDX, bit 8. See code in
		 * early_init_intel() where this bit is examined. The
		 * setting of this MSR bit should happen before init_intel()
		 * is called.
		 */
		wrmsrl(HV_X64_MSR_TSC_INVARIANT_CONTROL, 0x1);
		setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE);
	}

	/*
	 * Generation 2 instances don't support reading the NMI status from
	 * 0x61 port.
	 */
	if (efi_enabled(EFI_BOOT))
		x86_platform.get_nmi_reason = hv_get_nmi_reason;

	/*
	 * Hyper-V VMs have a PIT emulation quirk such that zeroing the
	 * counter register during PIT shutdown restarts the PIT. So it
	 * continues to interrupt @18.2 HZ. Setting i8253_clear_counter
	 * to false tells pit_shutdown() not to zero the counter so that
	 * the PIT really is shutdown. Generation 2 VMs don't have a PIT,
	 * and setting this value has no effect.
	 */
	i8253_clear_counter_on_shutdown = false;

#if IS_ENABLED(CONFIG_HYPERV)
	/*
	 * Setup the hook to get control post apic initialization.
	 */
	x86_platform.apic_post_init = hyperv_init;
	hyperv_setup_mmu_ops();
	/* Setup the IDT for hypervisor callback */
	alloc_intr_gate(HYPERVISOR_CALLBACK_VECTOR, asm_sysvec_hyperv_callback);

	/* Setup the IDT for reenlightenment notifications */
	if (ms_hyperv.features & HV_ACCESS_REENLIGHTENMENT) {
		alloc_intr_gate(HYPERV_REENLIGHTENMENT_VECTOR,
				asm_sysvec_hyperv_reenlightenment);
	}

	/* Setup the IDT for stimer0 */
	if (ms_hyperv.misc_features & HV_STIMER_DIRECT_MODE_AVAILABLE) {
		alloc_intr_gate(HYPERV_STIMER0_VECTOR,
				asm_sysvec_hyperv_stimer0);
	}

# ifdef CONFIG_SMP
	smp_ops.smp_prepare_boot_cpu = hv_smp_prepare_boot_cpu;
	if (hv_root_partition)
		smp_ops.smp_prepare_cpus = hv_smp_prepare_cpus;
# endif

	/*
	 * Hyper-V doesn't provide irq remapping for IO-APIC. To enable x2apic,
	 * set x2apic destination mode to physical mode when x2apic is available
	 * and Hyper-V IOMMU driver makes sure cpus assigned with IO-APIC irqs
	 * have 8-bit APIC id.
	 */
# ifdef CONFIG_X86_X2APIC
	if (x2apic_supported())
		x2apic_phys = 1;
# endif

	/* Register Hyper-V specific clocksource */
	hv_init_clocksource();
#ifdef CONFIG_HYPERV_VTL
	hv_vtl2_init_platform();
#endif
#endif
	/*
	 * TSC should be marked as unstable only after Hyper-V
	 * clocksource has been initialized. This ensures that the
	 * stability of the sched_clock is not altered.
	 */
	if (!(ms_hyperv.features & HV_ACCESS_TSC_INVARIANT))
		mark_tsc_unstable("running on Hyper-V");
}

static bool __init ms_hyperv_x2apic_available(void)
{
	return x2apic_supported();
}

/*
 * If ms_hyperv_msi_ext_dest_id() returns true, hyperv_prepare_irq_remapping()
 * returns -ENODEV and the Hyper-V IOMMU driver is not used; instead, the
 * generic support of the 15-bit APIC ID is used: see __irq_msi_compose_msg().
 *
 * Note: for a VM on Hyper-V, the I/O-APIC is the only device which
 * (logically) generates MSIs directly to the system APIC irq domain.
 * There is no HPET, and PCI MSI/MSI-X interrupts are remapped by the
 * pci-hyperv host bridge.
 *
 * Note: for a Hyper-V root partition, this will always return false.
 * The hypervisor doesn't expose these HYPERV_CPUID_VIRT_STACK_* cpuids by
 * default, they are implemented as intercepts by the Windows Hyper-V stack.
 * Even a nested root partition (L2 root) will not get them because the
 * nested (L1) hypervisor filters them out.
 */
static bool __init ms_hyperv_msi_ext_dest_id(void)
{
	u32 eax;

	eax = cpuid_eax(HYPERV_CPUID_VIRT_STACK_INTERFACE);
	if (eax != HYPERV_VS_INTERFACE_EAX_SIGNATURE)
		return false;

	eax = cpuid_eax(HYPERV_CPUID_VIRT_STACK_PROPERTIES);
	return eax & HYPERV_VS_PROPERTIES_EAX_EXTENDED_IOAPIC_RTE;
}

const __initconst struct hypervisor_x86 x86_hyper_ms_hyperv = {
	.name			= "Microsoft Hyper-V",
	.detect			= ms_hyperv_platform,
	.type			= X86_HYPER_MS_HYPERV,
	.init.x2apic_available	= ms_hyperv_x2apic_available,
	.init.msi_ext_dest_id	= ms_hyperv_msi_ext_dest_id,
	.init.init_platform	= ms_hyperv_init_platform,
};
