// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   
 */

#ifndef _HV_VSM_BOOT_H
#define _HV_VSM_BOOT_H

/* ToDo : Clean this file and move appropriate stuff into vsm.h and hv_vsm_boot.c. Delete this file */

#include <asm-generic/memory_model.h>
#include <linux/mm.h>

#ifndef u128
#define u128 __uint128_t
#endif  // u128

#define VSM_FIRST_CODE_PAGE    0
#define VSM_ISRS_CODE_PAGE     2816
#define VSM_GDT_PAGE           4081
#define VSM_IDT_PAGE           4082
#define VSM_TSS_PAGE           4083
#define VSM_PML4E_PAGE         4084
#define VSM_PDPE_PAGE          4085
#define VSM_PDE_PAGE           4086
#define VSM_PTE_0_PAGE         4087
#define VSM_KERNEL_STACK_PAGE  4095  // 4Kb stack

/*
 * Initial memory that will be mapped for secure kernel.
 * Secure Kernel memory can be larger than this.
 */
#define SK_INITIAL_MAP_SIZE	(16 * 1024 * 1024)

/* Defines the page size */
#define VSM_PAGE_SHIFT  12

/* Computed page size */
#define VSM_PAGE_SIZE  (((uint32_t)1) << VSM_PAGE_SHIFT)

/* Number of entries in a page table (all levels) */
#define VSM_ENTRIES_PER_PT	512

#define PAGE_AT(addr, idx) ((addr) + (idx) * VSM_PAGE_SIZE)

/* Compute the address of the next page with the given base */
#define NEXT_PAGE(addr) PAGE_AT((addr), 1)

/* Locations of configuration bits in page table entries (all levels) */
#define VSM_PAGE_BIT_PRESENT	0
#define VSM_PAGE_BIT_RW			1
#define VSM_PAGE_BIT_USER		2
#define VSM_PAGE_BIT_PWT		3
#define VSM_PAGE_BIT_PCD		4
#define VSM_PAGE_BIT_ACCESSED	5
#define VSM_PAGE_BIT_DIRTY		6
#define VSM_PAGE_BIT_PAT		7
#define VSM_PAGE_BIT_GLOBAL		8
#define VSM_PAGE_BIT_NX			63

/* Shifts to compute page table mapping (See AMD APM Vol 2, 5.3) */
#define VSM_PD_TABLE_SHIFT      21
#define VSM_PDP_TABLE_SHIFT     30
#define VSM_PML4_TABLE_SHIFT    39

/* Computed values for each configuration bit */
#define VSM_PAGE_PRESENT	(1 << VSM_PAGE_BIT_PRESENT)
#define VSM_PAGE_RW			(1 << VSM_PAGE_BIT_RW)
#define VSM_PAGE_USER		(1 << VSM_PAGE_BIT_USER)
#define VSM_PAGE_PWT		(1 << VSM_PAGE_BIT_PWT)
#define VSM_PAGE_PCD		(1 << VSM_PAGE_BIT_PCD)
#define VSM_PAGE_ACCESSED	(1 << VSM_PAGE_BIT_ACCESSED)
#define VSM_PAGE_DIRTY		(1 << VSM_PAGE_BIT_DIRTY)
#define VSM_PAGE_PAT		(1 << VSM_PAGE_BIT_PAT)
#define VSM_PAGE_GLOBAL		(1 << VSM_PAGE_BIT_GLOBAL)
#define VSM_PAGE_NX		(1 << VSM_PAGE_BIT_NX)

/* Useful combinations of bit configurations */
#define VSM_PAGE_OPTEE \
	(VSM_PAGE_PRESENT | VSM_PAGE_RW)
#define VSM_PAGE_PTE_OPTEE \
	(VSM_PAGE_OPTEE | VSM_PAGE_ACCESSED | VSM_PAGE_DIRTY)

#define HV_VTL1_ENABLE_BIT	BIT(1)
#define HV_VTL1			0x1

/* Compute the VA for a given PA for initial VTL1 loading. Assumes identity mapping */
#define VSM_VA_FROM_PA(pa) (pa)

/* 
 * Built in phys_to_virt converts kernel logical addresses to PAs.
 * These convert kernel virtual address to PAs and vice versa.
 */
#define VSM_NON_LOGICAL_PHYS_TO_VIRT(pa) ((pa) - vsm_skm_pa + vsm_skm_va)
#define VSM_NON_LOGICAL_VIRT_TO_PHYS(va) ((va) - vsm_skm_va + vsm_skm_pa)

/* Given VA, get index into the page table at a given level */
#define VSM_GET_PML4_INDEX_FROM_VA(va) (((va) >> VSM_PML4_TABLE_SHIFT) & 0x1FF)
#define VSM_GET_PDP_INDEX_FROM_VA(va) (((va) >> VSM_PDP_TABLE_SHIFT) & 0x1FF)
#define VSM_GET_PD_INDEX_FROM_VA(va) (((va) >> VSM_PD_TABLE_SHIFT) & 0x1FF)

#define CR0_PE				0x00000001		// protection enable
#define CR0_MP				0x00000002		// math present
#define CR0_EM				0x00000004		// emulate math coprocessor
#define CR0_TS				0x00000008		// task switched
#define CR0_ET				0x00000010		// extension type (80387)
#define CR0_NE				0x00000020		// numeric error
#define CR0_WP				0x00010000		// write protect
#define CR0_AM				0x00040000		// alignment mask
#define CR0_NW				0x20000000		// not write-through
#define CR0_CD				0x40000000		// cache disable
#define CR0_PG				0x80000000		// paging

#define CR4_VME				0x00000001		// V86 mode extensions
#define CR4_PVI				0x00000002		// Protected mode virtual interrupts
#define CR4_TSD				0x00000004		// Time stamp disable
#define CR4_DE				0x00000008		// Debugging Extensions
#define CR4_PSE				0x00000010		// Page size extensions
#define CR4_PAE				0x00000020		// Physical address extensions
#define CR4_MCE				0x00000040		// Machine check enable
#define CR4_PGE				0x00000080		// Page global enable
#define CR4_PCE				0x00000100		// Performance monitor counter enable
#define CR4_FXSR			0x00000200		// FXSR used by OS
#define CR4_XMMEXCPT		0x00000400		// XMMI used by OS
#define CR4_UMIP			0x00000800		// User Mode Instruction Prevention (UMIP) enable
#define CR4_LA57			0x00001000		// 5-level paging enable (57 bit linear address)
#define CR4_VMXE			0x00002000		// VMX enable
#define CR4_SMXE			0x00004000		// SMX enable
#define CR4_RDWRFSGSBASE	0x00010000		// RDWR FSGS Base enable = bit 16
#define CR4_PCIDE			0x00020000		// PCID enable
#define CR4_XSAVE			0x00040000		// XSAVE/XRSTOR enable
#define CR4_SMEP			0x00100000		// SMEP enable
#define CR4_SMAP			0x00200000		// SMAP enable
#define CR4_CET				0x00800000		// CET enable

#define MSR_SCE				0x00000001		// system call enable
#define MSR_LME				0x00000100		// long mode enable
#define MSR_LMA				0x00000400		// long mode active
#define MSR_NXE				0x00000800		// no execute enable
#define MSR_SVME			0x00001000		// secure virtual machine enable
#define MSR_FFXSR			0x00004000		// fast floating save/restore

#define MSR_PAT				0x277			// page attributes table

/* Intel SDM Vol 3A, 11.12.2 (IA32_PAT MSR) */
enum {
	PAT_UC = 0,        /* uncached */
	PAT_WC = 1,        /* Write combining */
	PAT_WT = 4,        /* Write Through */
	PAT_WP = 5,        /* Write Protected */
	PAT_WB = 6,        /* Write Back (default) */
	PAT_UC_MINUS = 7,  /* UC, but can be overridden by MTRR */
};

/* Compute a given PAT entry for a given caching mode name */
#define VSM_PAT(x, y)	((u64)PAT_ ## y << ((x) * 8))

/* The type field for an interrupt gate */
#define VSM_GATE_TYPE_INT	((u64)0xE)

/* AMD APM Vol 2, Table 4.6 */
#define VSM_SYSTEM_SEGMENT_TYPE_LDT				0x2
#define VSM_SYSTEM_SEGMENT_TYPE_TSS				0x9
#define VSM_SYSTEM_SEGMENT_TYPE_BUSY_TSS		0xB
#define VSM_SYSTEM_SEGMENT_TYPE_CALL_GATE		0xC
#define VSM_SYSTEM_SEGMENT_TYPE_INTERRUPT_GATE	0xE
#define VSM_SYSTEM_SEGMENT_TYPE_TRAP_GATE		0xF

/* Intel SDM Vol 3A, Table 3-1 */
#define VSM_CODE_SEGMENT_TYPE_EXECUTE_READ_ACCESSED		0xB
#define VSM_DATA_SEGMENT_TYPE_READ_WRITE_ACCESSED		0x3

/* Format of a Code Segment (long mode) */
union vsm_code_seg_desc {
	u64 as_u64;

	struct {
		u64 lo : 40;
		u64 flags_lo : 8;
		u64 flags_hi : 8;
		u64 hi : 8;
	} bytes __packed;

	struct {
		u64 seglim_lo : 16;
		u64 addr_lo : 24;
		u64 a : 1;
		u64 r : 1;
		u64 c : 1;
		u64 mbo1 : 1;
		u64 mbo2 : 1;
		u64 dpl : 2;
		u64 p : 1;
		u64 seglim_hi : 4;
		u64 avl : 1;
		u64 l : 1;
		u64 d : 1;
		u64 g : 1;
		u64 addr_hi : 8;
	} __packed;
};

/* Format of a Data Segment (long mode) */
union vsm_data_seg_desc {
	u64 as_u64;

	struct {
		u64 lo : 40;
		u64 flags_lo : 8;
		u64 flags_hi : 8;
		u64 hi : 8;
	} bytes __packed;

	struct {
		u64 seglim_lo : 16;
		u64 addr_lo : 24;
		u64 a : 1;
		u64 w : 1;
		u64 e : 1;
		u64 mbz1 : 1;
		u64 mbo1 : 1;
		u64 dpl : 2;
		u64 p : 1;
		u64 seglim_hi : 4;
		u64 avl : 1;
		u64 ign1 : 1;
		u64 db : 1;
		u64 g : 1;
		u64 addr_hi : 8;
	} __packed;
};

/* Format of a System Segment (long mode) */
union vsm_sys_seg_desc {
	struct {
		u64 lo : 40;
		u64 flags_lo : 8;
		u64 flags_hi : 8;
		u64 mid;
		u8 hi;
	} __packed bytes; // Packed attribute must be first.

	struct {
		u64 seglim_lo : 16;
		u64 addr_lo : 24;
		u64 type : 4;
		u64 mbz1 : 1;
		u64 dpl : 2;
		u64 p : 1;
		u64 seglim_hi : 4;
		u64 avl : 1;
		u64 ign1 : 2;
		u64 g : 1;
		u64 addr_hi : 40;
		u32 ign2;
	} __packed;
};

/* Format of a Call-Gate Segment (long mode) */
union vsm_call_gate_seg_desc {
	struct {
		u64 toff_lo : 16;
		u64 tsel : 16;
		u64 ign1 : 8;
		u64 type : 4;
		u64 mbz1 : 1;
		u64 dpl : 2;
		u64 p : 1;
		u64 toff_hi : 48;
		u64 ign2 : 8;
		u64 mbz2 : 5;
		u64 ign3 : 19;
	} __packed;
};

/* Format of a Interrupt- and Trap-Gate Segment (long mode) */
union vsm_int_trap_gate_seg_desc {
	struct {
		u64 toff_lo : 16;
		u64 tsel : 16;
		u64 ist : 3;
		u64 ign1 : 5;
		u64 type : 4;
		u64 mbz1 : 1;
		u64 dpl : 2;
		u64 p : 1;
		u64 toff_hi : 48;
		u64 ign2 : 32;
	} __packed;
};

/* Format of the Task State Segment (long mode) */
union vsm_tss {
	u32 reserved1;

	u64 rsp0;
	u64 rsp1;
	u64 rsp2;

	u64 reserved2;

	u64 ist[7];

	u64 reserved3;
	u8  reserved4;

	u8 io_bitmap_base;
} __packed;

/* A type for the Global Descriptor Table (GDT) */
typedef void vsm_gdt_t;

/* Make Code Segment Descriptor */
#define MAKE_CSD(_seglim_lo, _addr_lo, _a, _r, _c, _dpl, _p, _seglim_hi, _avl, _l, _d, _g, _addr_hi) \
	(union vsm_code_seg_desc) {		\
		.seglim_lo = (_seglim_lo),	\
		.addr_lo = (_addr_lo),		\
		.a = (_a),					\
		.r = (_r),					\
		.c = (_c),					\
		.mbo1 = 1,					\
		.mbo2 = 1,					\
		.dpl = (_dpl),				\
		.p = (_p),					\
		.seglim_hi = (_seglim_hi),	\
		.avl = (_avl),				\
		.l = (_l),					\
		.d = (_d),					\
		.g = (_g)					\
	}

/* Make Code Segment Descriptor (long mode) */
#define MAKE_CSD_LM(_c, _dpl, _p, _avl) \
	MAKE_CSD(0, 0, 0, 0, (_c), (_dpl), (_p), 0, (_avl), 1, 0, 0, 0)

/* Make Data Segment Descriptor */
#define MAKE_DSD(_seglim_lo, _addr_lo, _a, _w, _e, _dpl, _p, _seglim_hi, _avl, _db, _g, _addr_hi) \
	(union vsm_data_seg_desc)  {	\
		.seglim_lo = (_seglim_lo),	\
		.addr_lo = (_addr_lo),		\
		.a = (_a),					\
		.w = (_w),					\
		.e = (_e),					\
		.mbz1 = 0,					\
		.mbo1 = 1,					\
		.dpl = (_dpl),				\
		.p = (_p),					\
		.seglim_hi = (_seglim_hi),	\
		.avl = (_avl),				\
		.ign1 = 0,					\
		.db = (_db),				\
		.g = (_g),					\
		.addr_hi = (_addr_hi)		\
	}

/* Make Data Segment Descriptor (long mode) */
#define MAKE_DSD_LM(_p, _avl) \
	MAKE_DSD(0, 0, 0, 0, 0, 0, (_p), 0, (_avl), 0, 0, 0)

/* Make System Segment Descriptor  */
#define MAKE_SSD(_seglim_lo, _addr_lo, _type, _dpl, _p, _seglim_hi, _avl, _g, _addr_hi) \
	(union vsm_sys_seg_desc) {		\
		.seglim_lo = (_seglim_lo),	\
		.addr_lo = (_addr_lo),		\
		.type = (_type),			\
		.mbz1 = 0,					\
		.dpl = (_dpl),				\
		.p = (_p),					\
		.seglim_hi = (_seglim_hi),	\
		.avl = (_avl),				\
		.g = (_g),					\
		.addr_hi = (_addr_hi),		\
		.ign2 = 0					\
	};

/* Make a Segment Selector */
#define MAKE_SELECTOR(rpl, ti, si) \
	(u16)(((si) << 3) | ((ti) << 2) | (rpl))

#endif /* _HV_VSM_BOOT_H */
