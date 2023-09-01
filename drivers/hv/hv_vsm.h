// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   
 */

#ifndef _HV_VSM_H
#define _HV_VSM_H

#define VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY	0x1FFF
#define VSM_VTL_CALL_FUNC_ID_LOCK_CR		0x1FFFF

extern bool hv_vsm_boot_success;

struct vtlcall_param { // TODO: Tailored for OP-TEE. Might change when we move to arch-agnostic.
	u64	a0;
	u64	a1;
	u64	a2;
	u64	a3;
} __packed;

void hv_vsm_vtl_call(struct vtlcall_param *args);
#endif /* _HV_VSM_H */
