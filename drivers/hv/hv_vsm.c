// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *
 */

#include <linux/types.h>
#include <linux/irqflags.h>
#include <linux/hv_vsm.h>
#include <linux/heki.h>
#include <linux/kvm_host.h>

#include "hv_vsm.h"

static void hv_vsm_hv_do_vtlcall(struct vtlcall_param *args)
{
	struct cpumask orig_mask;
	unsigned long flags = 0;

	// VBS TODO: Remove when we enable SMP support
	cpumask_copy(&orig_mask, current->cpus_ptr);
	set_cpus_allowed_ptr(current, cpumask_of(0));

	local_irq_save(flags);
	hv_vsm_vtl_call(args);
	local_irq_restore(flags);

	set_cpus_allowed_ptr(current, &orig_mask);
}

#ifdef CONFIG_HEKI
static int hv_vsm_protect_ranges(struct heki_pa_range *ranges, int num_ranges)
{
	if (hv_vsm_boot_success) {
		struct vtlcall_param args = {0};
		int i;
		struct heki_pa_range *pa_range;
		gpa_t gpa_start, gpa_end;
		size_t size;

		args.a0 = VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY;

		for (i = 0; i < num_ranges; i++) {
			pa_range = &ranges[i];
			gpa_start = gfn_to_gpa(pa_range->gfn_start);
			gpa_end = gfn_to_gpa(pa_range->gfn_end);
			size = gpa_end - gpa_start;

			args.a1 = gpa_start;
			args.a2 = size;
			args.a3 = pa_range->attributes;

			hv_vsm_hv_do_vtlcall(&args);
		}
		return 0;
	} else {
		return -ENOTSUPP;
	}
}

static int hv_vsm_lock_crs(void)
{
	if (hv_vsm_boot_success) {
		struct vtlcall_param args = {0};

		args.a0 = VSM_VTL_CALL_FUNC_ID_LOCK_CR;

		hv_vsm_hv_do_vtlcall(&args);

		return 0;
	} else {
		return -ENOTSUPP;
	}
}

struct heki_hypervisor hyperv_heki_hypervisor = {
	.protect_ranges = hv_vsm_protect_ranges,
	.lock_crs = hv_vsm_lock_crs,
};

void __init hv_vsm_init_heki(void)
{
	heki.hypervisor = &hyperv_heki_hypervisor;
}
#endif
