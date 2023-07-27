// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common code
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/cache.h>
#include <linux/heki.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "heki-guest: " fmt

static bool heki_enabled __ro_after_init = true;

struct heki heki = {};

struct heki_pa_range *heki_alloc_pa_ranges(struct heki_va_range *va_ranges,
					   int num_ranges)
{
	struct heki_pa_range *pa_ranges, *pa_range;
	struct heki_va_range *va_range;
	u64 attributes;
	size_t size;
	int i;

	size = PAGE_ALIGN(sizeof(struct heki_pa_range) * num_ranges);
	pa_ranges = alloc_pages_exact(size, GFP_KERNEL);
	if (!pa_ranges)
		return NULL;

	for (i = 0; i < num_ranges; i++) {
		va_range = &va_ranges[i];
		pa_range = &pa_ranges[i];

		pa_range->gfn_start = PFN_DOWN(__pa_symbol(va_range->va_start));
		pa_range->gfn_end = PFN_UP(__pa_symbol(va_range->va_end)) - 1;
		pa_range->attributes = va_range->attributes;

		/*
		 * WARNING:
		 * Leaks addresses, should only be kept for development.
		 */
		attributes = pa_range->attributes;
		pr_warn("Configuring GFN 0x%llx-0x%llx with %s\n",
			pa_range->gfn_start, pa_range->gfn_end,
			(attributes & HEKI_ATTR_MEM_NOWRITE) ? "[nowrite]" :
							       "");
	}

	return pa_ranges;
}

void heki_free_pa_ranges(struct heki_pa_range *pa_ranges, int num_ranges)
{
	size_t size;

	size = PAGE_ALIGN(sizeof(struct heki_pa_range) * num_ranges);
	free_pages_exact(pa_ranges, size);
}

void __init heki_early_init(void)
{
	if (!heki_enabled) {
		pr_warn("Disabled\n");
		return;
	}
	pr_warn("Enabled\n");

	heki_arch_init();
}

void heki_late_init(void)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	int ret;

	if (!heki_enabled)
		return;

	if (!heki.static_ranges) {
		pr_warn("Architecture did not initialize static ranges\n");
		return;
	}

	/*
	 * Hypervisor support will be added in the future. When it is, the
	 * hypervisor will be used to protect guest kernel memory and
	 * control registers.
	 */

	if (!hypervisor) {
		/* This happens for kernels running on bare metal as well. */
		pr_warn("No hypervisor support\n");
		goto out;
	}

	/* Protects statically defined sections in the host page table. */
	ret = hypervisor->protect_ranges(heki.static_ranges,
					 heki.num_static_ranges);
	if (WARN(ret, "Failed to protect static sections: %d\n", ret))
		goto out;
	pr_warn("Static sections protected\n");

	/*
	 * Locks control registers so a compromised guest cannot change
	 * them.
	 */
	ret = hypervisor->lock_crs();
	if (WARN(ret, "Failed to lock control registers: %d\n", ret))
		goto out;
	pr_warn("Control registers locked\n");

out:
	heki_free_pa_ranges(heki.static_ranges, heki.num_static_ranges);
	heki.static_ranges = NULL;
	heki.num_static_ranges = 0;
}

static int __init heki_parse_config(char *str)
{
	if (strtobool(str, &heki_enabled))
		pr_warn("Invalid option string for heki: '%s'\n", str);
	return 1;
}

__setup("heki=", heki_parse_config);
