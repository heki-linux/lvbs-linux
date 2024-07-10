/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Definitions
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef __HEKI_H__
#define __HEKI_H__

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/slab.h>

/*
 * This structure contains a guest memory range and its attributes (e.g.,
 * permissions (RWX)).
 */
struct heki_range {
	unsigned long va;
	phys_addr_t pa;
	phys_addr_t epa;
	unsigned long attributes;
};

/*
 * Guest ranges are passed to the VMM or hypervisor so they can be authenticated
 * and their permissions can be set in the host page table. When an array of
 * these is passed to the Hypervisor or VMM, the array must be in physically
 * contiguous memory.
 *
 * This struct occupies one page. In each page, an array of guest ranges can
 * be passed. A guest request to the VMM/Hypervisor may contain a list of
 * these structs (linked by "next_pa").
 */
struct heki_page {
	struct heki_page *next;
	phys_addr_t next_pa;
	unsigned long nranges;
	struct heki_range ranges[];
};

/*
 * The ranges contain VTL0 pages. VTL0 pages are mapped into VTL1 address space
 * so VTL1 can access VTL0 memory at va.
 */
struct heki_mem {
	void			*va;
	unsigned long		size;
	long			offset;
	struct heki_range	*ranges;
	unsigned long		nranges;
};

#endif /* __HEKI_H__ */
