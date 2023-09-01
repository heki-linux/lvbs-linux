/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (c) 2023, Microsoft Corporation.
 */
#ifndef _VSM_H
#define _VSM_H

/* Heki attributes for memory pages. */
#define HEKI_ATTR_MEM_NOWRITE		(1ULL << 0)
#define HEKI_ATTR_MEM_EXEC		(1ULL << 1)

/*
 * mshv_vtl_call_params : Strcture to parse in parameters from VTL0
 * _a0 : Service Id
 * _a1-_a3: Optional and depends on the requested service
 */
struct mshv_vtl_call_params {
	u64 _a0;
	u64 _a1;
	u64 _a2;
	u64 _a3;
};

/* Defines the page size */
#define VSM_PAGE_SHIFT  12

/* Computed page size */
#define VSM_PAGE_SIZE  (((u32)1) << VSM_PAGE_SHIFT)

/* Number of entries in a page table (all levels) */
#define VSM_ENTRIES_PER_PT  512

/* Compute the address of the page at the given index with the given base */
#define VSM_PAGE_AT(addr, idx)  ((addr) + (idx) * VSM_PAGE_SIZE)

/* Compute the address of the next page with the given base */
#define VSM_NEXT_PAGE(addr)  VSM_PAGE_AT((addr), 1)

/* Compute the page frame number (PFN) from a page address */
#define VSM_PAGE_TO_PFN(addr)  ((addr) / VSM_PAGE_SIZE)

/* This indicates the reason why a VTL was entered */
enum hv_vtl_entry_reason {
	/* This reason is reserved and is not used */
	HvVtlEntryReserved  = 0,

	/* Indicates entry due to a VTL call from a lower VTL */
	HvVtlEntryVtlCall   = 1,

	/* Indicates entry due to an interrupt targeted to the VTL */
	HvVtlEntryInterrupt = 2,

	/* Indicates entry due to an intercept targeted to the VTL */
	HvVtlEntryIntercept = 3
};
struct hv_input_modify_vtl_protection_mask {
	u64 partition_id;
	u32 map_flags;
	union hv_input_vtl target_vtl;
	u8 reserved8_z;
	u16 reserved16_z;
	__aligned(8) u64 gpa_page_list[];
};

/* Internal structure of the hypercall input value (i.e., the control) */
union hv_hypercall_input {
	u64 as_uint64;

	/* TLFS 3.7 */
	struct {
		u32 call_code         : 16;
		u32 is_fast           : 1;
		u32 reserved1         : 14;
		u32 is_nested         : 1;
		u32 count_of_elements : 12;
		u32 reserved2         : 4;
		u32 rep_start_index   : 12;
		u32 reserved3         : 4;
	};
};

/* Internal structure of the hypercall output value (i.e., RAX, upon return) */
union hv_hypercall_output {
	u64 as_uint64;

	/* TLFS 3.8 */
	struct {
		u16 call_status;
		u16 reserved1;
		u32 elements_processed : 12;
		u32 reserved2          : 20;
	};
};

struct hv_input_set_vp_registers {
	u64 partition_id;
	u32 vp_index;
	union hv_input_vtl input_vtl;
	u8 reserved8_z;
	u16 reserved16_z;
	__aligned(8) struct hv_register_assoc elements[1];
};

#endif /* _VSM_H */
