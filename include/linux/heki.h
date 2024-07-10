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
 *
 * Each module section (text, data, etc) is represented by a heki_mem. Module
 * sections are reconstructed in VTL1 and compared with the corresponding
 * VTL0 sections. Reconstruction involves module symbol resolution and module
 * relocation. These steps involve symbol addresses. To make the reconstruction
 * simpler, we map the VTL1 module sections at the same virtual addresses as
 * their corresponding sections in VTL0. We call this identity mapping. This
 * keeps the addresses the same in VTL0 and VTL1. A VTL1 section is accessed
 * at ranges->va since that is the starting va for the section.
 */
struct heki_mem {
	void			*va;
	unsigned long		size;
	long			offset;
	struct heki_range	*ranges;
	unsigned long		nranges;
	struct page		**pages;
	bool			retain;
};

enum heki_kdata_type {
	HEKI_MODULE_CERTS,
	HEKI_KERNEL_INFO,
	HEKI_KERNEL_DATA,
	HEKI_KDATA_MAX,
};

/*
 * Attribute value for module ELF that does not conflict with any of the
 * values in enum mod_mem_type.
 */
#define MOD_ELF		MOD_MEM_NUM_TYPES

/* This is created for each guest module in the host. */
struct heki_mod {
	struct list_head node;
	struct heki_range *ranges;
	char name[MODULE_NAME_LEN];
	long token;
	struct heki_mem mem[MOD_ELF + 1];
	struct module *mod;
};

#define HEKI_MODULE_RESERVE_SIZE	0x40000000UL

struct heki_kinfo {
	struct kernel_symbol *ksymtab_start;
	struct kernel_symbol *ksymtab_end;
	struct kernel_symbol *ksymtab_gpl_start;
	struct kernel_symbol *ksymtab_gpl_end;
};

#endif /* __HEKI_H__ */
