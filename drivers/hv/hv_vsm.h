// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   
 */

#ifndef _HV_VSM_H
#define _HV_VSM_H

struct vtlcall_param { // TODO: Tailored for OP-TEE. Might change when we move to arch-agnostic.
	u32	a0;
	u32	a1;
	u32	a2;
	u32	a3;
} __packed;

void hv_vsm_vtl_call(struct vtlcall_param *args);
#endif /* _HV_VSM_H */
