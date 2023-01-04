// SPDX-License-Identifier: GPL-2.0

/*
 * Architecture neutral utility routines for interacting with
 * Hyper-V. This file is specifically for code that must be
 * built-in to the kernel image when CONFIG_HYPERV is set
 * (vs. being in a module) because it is called from architecture
 * specific code under arch/.
 *
 * Copyright (C) 2021, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#include <linux/types.h>
#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/bitfield.h>
#include <linux/cpumask.h>
#include <linux/panic_notifier.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/dma-map-ops.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>

/*
 * hv_root_partition and ms_hyperv are defined here with other Hyper-V
 * specific globals so they are shared across all architectures and are
 * built only when CONFIG_HYPERV is defined.  But on x86,
 * ms_hyperv_init_platform() is built even when CONFIG_HYPERV is not
 * defined, and it uses these two variables.  So mark them as __weak
 * here, allowing for an overriding definition in the module containing
 * ms_hyperv_init_platform().
 */
bool __weak hv_root_partition;
EXPORT_SYMBOL_GPL(hv_root_partition);

bool __weak hv_nested;
EXPORT_SYMBOL_GPL(hv_nested);

struct ms_hyperv_info __weak ms_hyperv;
EXPORT_SYMBOL_GPL(ms_hyperv);

u32 *hv_vp_index;
EXPORT_SYMBOL_GPL(hv_vp_index);

u32 hv_max_vp_index;
EXPORT_SYMBOL_GPL(hv_max_vp_index);

void  __percpu **hyperv_pcpu_input_arg;
EXPORT_SYMBOL_GPL(hyperv_pcpu_input_arg);

void  __percpu **hyperv_pcpu_output_arg;
EXPORT_SYMBOL_GPL(hyperv_pcpu_output_arg);

/*
 * Per-cpu array holding the tail pointer for the SynIC event ring buffer
 * for each SINT.
 *
 * We cannot maintain this in mshv driver because the tail pointer should
 * persist even if the mshv driver is unloaded.
 */
u8 __percpu **hv_synic_eventring_tail;
EXPORT_SYMBOL_GPL(hv_synic_eventring_tail);

/*
 * Hyper-V specific initialization and shutdown code that is
 * common across all architectures.  Called from architecture
 * specific initialization functions.
 */

void __init hv_common_free(void)
{
	kfree(hv_vp_index);
	hv_vp_index = NULL;

	free_percpu(hyperv_pcpu_output_arg);
	hyperv_pcpu_output_arg = NULL;

	free_percpu(hyperv_pcpu_input_arg);
	hyperv_pcpu_input_arg = NULL;
}

int __init hv_common_init(void)
{
	int i;

	/*
	 * Hyper-V expects to get crash register data or kmsg when
	 * crash enlightment is available and system crashes. Set
	 * crash_kexec_post_notifiers to be true to make sure that
	 * calling crash enlightment interface before running kdump
	 * kernel.
	 */
	if (ms_hyperv.misc_features & HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE)
		crash_kexec_post_notifiers = true;

	/*
	 * Allocate the per-CPU state for the hypercall input arg.
	 * If this allocation fails, we will not be able to setup
	 * (per-CPU) hypercall input page and thus this failure is
	 * fatal on Hyper-V.
	 */
	hyperv_pcpu_input_arg = alloc_percpu(void  *);
	BUG_ON(!hyperv_pcpu_input_arg);

	hyperv_pcpu_output_arg = alloc_percpu(void *);
	BUG_ON(!hyperv_pcpu_output_arg);

	if (hv_root_partition) {
		hv_synic_eventring_tail = alloc_percpu(u8 *);
		BUG_ON(hv_synic_eventring_tail == NULL);
	}

	hv_vp_index = kmalloc_array(num_possible_cpus(), sizeof(*hv_vp_index),
				    GFP_KERNEL);
	if (!hv_vp_index) {
		hv_common_free();
		return -ENOMEM;
	}

	for (i = 0; i < num_possible_cpus(); i++)
		hv_vp_index[i] = VP_INVAL;

	return 0;
}

/*
 * Hyper-V specific initialization and die code for
 * individual CPUs that is common across all architectures.
 * Called by the CPU hotplug mechanism.
 */

int hv_common_cpu_init(unsigned int cpu)
{
	void **inputarg, **outputarg;
	u8 **synic_eventring_tail;
	u64 msr_vp_index;
	gfp_t flags;

	/* hv_cpu_init() can be called with IRQs disabled from hv_resume() */
	flags = irqs_disabled() ? GFP_ATOMIC : GFP_KERNEL;

	inputarg = (void **)this_cpu_ptr(hyperv_pcpu_input_arg);
	*inputarg = kmalloc(2 * HV_HYP_PAGE_SIZE, flags);
	if (!(*inputarg))
		return -ENOMEM;

	outputarg = (void **)this_cpu_ptr(hyperv_pcpu_output_arg);
	*outputarg = (char *)(*inputarg) + HV_HYP_PAGE_SIZE;

	if (hv_root_partition) {
		synic_eventring_tail = (u8 **)this_cpu_ptr(hv_synic_eventring_tail);
		*synic_eventring_tail = kcalloc(HV_SYNIC_SINT_COUNT, sizeof(u8),
						flags);

		if (unlikely(!*synic_eventring_tail)) {
			kfree(*inputarg);
			return -ENOMEM;
		}
	}

	msr_vp_index = hv_get_register(HV_REGISTER_VP_INDEX);

	hv_vp_index[cpu] = msr_vp_index;

	if (msr_vp_index > hv_max_vp_index)
		hv_max_vp_index = msr_vp_index;

	return 0;
}

int hv_common_cpu_die(unsigned int cpu)
{
	unsigned long flags;
	void **inputarg, **outputarg;
	u8 **synic_eventring_tail;
	void *mem;

	local_irq_save(flags);

	inputarg = (void **)this_cpu_ptr(hyperv_pcpu_input_arg);
	mem = *inputarg;
	*inputarg = NULL;

	outputarg = (void **)this_cpu_ptr(hyperv_pcpu_output_arg);
	*outputarg = NULL;

	if (hv_root_partition) {
		synic_eventring_tail = (u8 **)this_cpu_ptr(hv_synic_eventring_tail);
		kfree(*synic_eventring_tail);
		*synic_eventring_tail = NULL;
	}

	local_irq_restore(flags);

	kfree(mem);

	return 0;
}

/* Bit mask of the extended capability to query: see HV_EXT_CAPABILITY_xxx */
bool hv_query_ext_cap(u64 cap_query)
{
	/*
	 * The address of the 'hv_extended_cap' variable will be used as an
	 * output parameter to the hypercall below and so it should be
	 * compatible with 'virt_to_phys'. Which means, it's address should be
	 * directly mapped. Use 'static' to keep it compatible; stack variables
	 * can be virtually mapped, making them incompatible with
	 * 'virt_to_phys'.
	 * Hypercall input/output addresses should also be 8-byte aligned.
	 */
	static u64 hv_extended_cap __aligned(8);
	static bool hv_extended_cap_queried;
	u64 status;

	/*
	 * Querying extended capabilities is an extended hypercall. Check if the
	 * partition supports extended hypercall, first.
	 */
	if (!(ms_hyperv.priv_high & HV_ENABLE_EXTENDED_HYPERCALLS))
		return false;

	/* Extended capabilities do not change at runtime. */
	if (hv_extended_cap_queried)
		return hv_extended_cap & cap_query;

	status = hv_do_hypercall(HV_EXT_CALL_QUERY_CAPABILITIES, NULL,
				 &hv_extended_cap);

	/*
	 * The query extended capabilities hypercall should not fail under
	 * any normal circumstances. Avoid repeatedly making the hypercall, on
	 * error.
	 */
	hv_extended_cap_queried = true;
	if (!hv_result_success(status)) {
		pr_err("Hyper-V: Extended query capabilities hypercall failed 0x%llx\n",
		       status);
		return false;
	}

	return hv_extended_cap & cap_query;
}
EXPORT_SYMBOL_GPL(hv_query_ext_cap);

void hv_setup_dma_ops(struct device *dev, bool coherent)
{
	/*
	 * Hyper-V does not offer a vIOMMU in the guest
	 * VM, so pass 0/NULL for the IOMMU settings
	 */
	arch_setup_dma_ops(dev, 0, 0, NULL, coherent);
}
EXPORT_SYMBOL_GPL(hv_setup_dma_ops);

/*
 * Default function to read the Hyper-V reference counter, independent
 * of whether Hyper-V enlightened clocks/timers are being used. But on
 * architectures where it is used, Hyper-V enlightenment code in
 * hyperv_timer.c may override this function.
 */
static u64 __hv_read_ref_counter(void)
{
	return hv_get_register(HV_REGISTER_TIME_REF_COUNT);
}

u64 (*hv_read_reference_counter)(void) = __hv_read_ref_counter;
EXPORT_SYMBOL_GPL(hv_read_reference_counter);

/* These __weak functions provide default "no-op" behavior and
 * may be overridden by architecture specific versions. Architectures
 * for which the default "no-op" behavior is sufficient can leave
 * them unimplemented and not be cluttered with a bunch of stub
 * functions in arch-specific code.
 */

bool __weak hv_is_isolation_supported(void)
{
	return false;
}
EXPORT_SYMBOL_GPL(hv_is_isolation_supported);

void __weak hv_setup_vmbus_handler(void (*handler)(void))
{
}
EXPORT_SYMBOL_GPL(hv_setup_vmbus_handler);

void __weak hv_remove_vmbus_handler(void)
{
}
EXPORT_SYMBOL_GPL(hv_remove_vmbus_handler);

void __weak hv_setup_mshv_irq(void (*handler)(void))
{
}
EXPORT_SYMBOL_GPL(hv_setup_mshv_irq);

void __weak hv_remove_mshv_irq(void)
{
}
EXPORT_SYMBOL_GPL(hv_remove_mshv_irq);

void __weak hv_setup_kexec_handler(void (*handler)(void))
{
}
EXPORT_SYMBOL_GPL(hv_setup_kexec_handler);

void __weak hv_remove_kexec_handler(void)
{
}
EXPORT_SYMBOL_GPL(hv_remove_kexec_handler);

void __weak hv_setup_crash_handler(void (*handler)(struct pt_regs *regs))
{
}
EXPORT_SYMBOL_GPL(hv_setup_crash_handler);

void __weak hv_remove_crash_handler(void)
{
}
EXPORT_SYMBOL_GPL(hv_remove_crash_handler);

void __weak hyperv_cleanup(void)
{
}
EXPORT_SYMBOL_GPL(hyperv_cleanup);

int hv_call_create_vp(int node, u64 partition_id, u32 vp_index, u32 flags)
{
	struct hv_create_vp *input;
	u64 status;
	unsigned long irq_flags;
	int ret = HV_STATUS_SUCCESS;

	/* Root VPs don't seem to need pages deposited */
	if (partition_id != hv_current_partition_id) {
		/* The value 90 is empirically determined. It may change. */
		ret = hv_call_deposit_pages(node, partition_id, 90);
		if (ret)
			return ret;
	}

	do {
		local_irq_save(irq_flags);

		input = *this_cpu_ptr(hyperv_pcpu_input_arg);

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->flags = flags;
		input->subnode_type = HvSubnodeAny;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_CREATE_VP, input, NULL);
		local_irq_restore(irq_flags);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status)) {
				pr_err("%s: vcpu %u, lp %u, %s\n", __func__,
				       vp_index, flags, hv_status_to_string(status));
				ret = hv_status_to_errno(status);
			}
			break;
		}
		ret = hv_call_deposit_pages(node, partition_id, 1);

	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_create_vp);

/*
 * See struct hv_deposit_memory. The first u64 is partition ID, the rest
 * are GPAs.
 */
#define HV_DEPOSIT_MAX (HV_HYP_PAGE_SIZE / sizeof(u64) - 1)

/* Deposits exact number of pages. Must be called with interrupts enabled.  */
int hv_call_deposit_pages(int node, u64 partition_id, u32 num_pages)
{
	struct page **pages, *page;
	int *counts;
	int num_allocations;
	int i, j, page_count;
	int order;
	u64 status;
	int ret;
	u64 base_pfn;
	struct hv_deposit_memory *input_page;
	unsigned long flags;

	if (num_pages > HV_DEPOSIT_MAX)
		return -E2BIG;
	if (!num_pages)
		return 0;

	/* One buffer for page pointers and counts */
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	pages = page_address(page);

	counts = kcalloc(HV_DEPOSIT_MAX, sizeof(int), GFP_KERNEL);
	if (!counts) {
		free_page((unsigned long)pages);
		return -ENOMEM;
	}

	/* Allocate all the pages before disabling interrupts */
	i = 0;

	while (num_pages) {
		/* Find highest order we can actually allocate */
		order = 31 - __builtin_clz(num_pages);

		while (1) {
			pages[i] = alloc_pages_node(node, GFP_KERNEL, order);
			if (pages[i])
				break;
			if (!order) {
				ret = -ENOMEM;
				num_allocations = i;
				goto err_free_allocations;
			}
			--order;
		}

		split_page(pages[i], order);
		counts[i] = 1 << order;
		num_pages -= counts[i];
		i++;
	}
	num_allocations = i;

	local_irq_save(flags);

	input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

	input_page->partition_id = partition_id;

	/* Populate gpa_page_list - these will fit on the input page */
	for (i = 0, page_count = 0; i < num_allocations; ++i) {
		base_pfn = page_to_pfn(pages[i]);
		for (j = 0; j < counts[i]; ++j, ++page_count)
			input_page->gpa_page_list[page_count] = base_pfn + j;
	}
	status = hv_do_rep_hypercall(HVCALL_DEPOSIT_MEMORY,
				     page_count, 0, input_page, NULL);
	local_irq_restore(flags);
	if (!hv_result_success(status)) {
		pr_err("Failed to deposit pages: %s\n", hv_status_to_string(status));
		ret = hv_status_to_errno(status);
		goto err_free_allocations;
	}

	ret = 0;
	goto free_buf;

err_free_allocations:
	for (i = 0; i < num_allocations; ++i) {
		base_pfn = page_to_pfn(pages[i]);
		for (j = 0; j < counts[i]; ++j)
			__free_page(pfn_to_page(base_pfn + j));
	}

free_buf:
	free_page((unsigned long)pages);
	kfree(counts);
	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_deposit_pages);

/*
 * Corresponding sleep states have to be initialized, in order a subsequent
 * HVCALL_ENTER_SLEEP_STATE call to succeed. Currently only S5 state as per
 * ACPI 6.4 chapter 7.4.2 is relevant, while S1, S2 and S3 can be supported.
 */
static int hv_initialize_sleep_states(void)
{
	u64 status;
	unsigned long flags;
	struct hv_input_set_system_property *in;

	local_irq_save(flags);
	in = (struct hv_input_set_system_property *)(*this_cpu_ptr(
		hyperv_pcpu_input_arg));

	in->property_id = HV_SYSTEM_PROPERTY_SLEEP_STATE;
	in->set_sleep_state_info.sleep_state = HV_SLEEP_STATE_S5;
	in->set_sleep_state_info.pm1a_slp_typ = HV_SLEEP_STATE_S5;
	in->set_sleep_state_info.pm1b_slp_typ = 0;

	status = hv_do_hypercall(HVCALL_SET_SYSTEM_PROPERTY, in, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n",
			__func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

static int hv_call_enter_sleep_state(u32 sleep_state)
{
	u64 status;
	unsigned long flags;
	struct hv_input_enter_sleep_state *in;

	local_irq_save(flags);
	in = (struct hv_input_enter_sleep_state *)(*this_cpu_ptr(
		hyperv_pcpu_input_arg));
	in->sleep_state = (enum hv_sleep_state)sleep_state;

	status = hv_do_hypercall(HVCALL_ENTER_SLEEP_STATE, in, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n",
			__func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

static int hv_reboot_notifier_handler(struct notifier_block *this, unsigned long code, void *another)
{
	int ret = 0;

	if (SYS_HALT == code || SYS_POWER_OFF == code)
		ret = hv_call_enter_sleep_state(HV_SLEEP_STATE_S5);

	return ret ? NOTIFY_DONE : NOTIFY_OK;
}

static struct notifier_block hv_reboot_notifier = {
	.notifier_call	= hv_reboot_notifier_handler,
};

int hv_sleep_notifiers_register(void)
{
	int ret;

	ret = hv_initialize_sleep_states();
	if (!ret) {
		ret = register_reboot_notifier(&hv_reboot_notifier);
		if (ret)
			pr_err("%s: cannot register reboot notifier %d\n",
				__func__, ret);
	}

	return ret;
}
