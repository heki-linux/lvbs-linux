/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Headers
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef __HEKI_H__
#define __HEKI_H__

#ifdef CONFIG_HEKI

#include <linux/kvm_types.h>

/* Heki attributes for memory pages. */
/* clang-format off */
#define HEKI_ATTR_MEM_NOWRITE		(1ULL << 0)
#define HEKI_ATTR_MEM_EXEC		(1ULL << 1)
/* clang-format on */

/*
 * heki_va_range is used to specify a virtual address range within the kernel
 * address space along with their attributes.
 */
struct heki_va_range {
	void *va_start;
	void *va_end;
	u64 attributes;
};

/*
 * heki_pa_range is passed to the VMM or hypervisor so it can be processed by
 * the VMM or the hypervisor based on range attributes. Examples of ranges:
 *
 *	- a range whose permissions need to be set in the host page table
 *	- a range that contains information needed for authentication
 *
 * When an array of these is passed to the Hypervisor or VMM, the array
 * must be in physically contiguous memory.
 */
struct heki_pa_range {
	gfn_t gfn_start;
	gfn_t gfn_end;
	u64 attributes;
};

/*
 * A hypervisor that supports Heki will instantiate this structure to
 * provide hypervisor specific functions for Heki.
 */
struct heki_hypervisor {
	int (*protect_ranges)(struct heki_pa_range *ranges, int num_ranges);
	int (*lock_crs)(void);
};

/*
 * If the architecture supports Heki, it will initialize static_ranges in
 * early boot.
 *
 * If the active hypervisor supports Heki, it will plug its heki_hypervisor
 * pointer into this heki structure.
 */
struct heki {
	struct heki_pa_range *static_ranges;
	int num_static_ranges;
	struct heki_hypervisor *hypervisor;
};

extern struct heki heki;

void heki_early_init(void);
void heki_arch_init(void);
void heki_late_init(void);

struct heki_pa_range *heki_alloc_pa_ranges(struct heki_va_range *va_ranges,
					   int num_ranges);
void heki_free_pa_ranges(struct heki_pa_range *pa_ranges, int num_ranges);

#else /* !CONFIG_HEKI */

static inline void heki_early_init(void)
{
}
static inline void heki_late_init(void)
{
}

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
