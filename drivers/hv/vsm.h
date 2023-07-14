/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (c) 2023, Microsoft Corporation.
 */
#ifndef _VSM_H
#define _VSM_H

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

#endif /* _VSM_H */
