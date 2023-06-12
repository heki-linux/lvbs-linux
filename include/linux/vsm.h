/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (c) 2023, Microsoft Corporation.
 */

#ifndef _VSM_H
#define _VSM_H

enum vsm_service_ids {
	VSM_PROTECT_MEMORY = 0,
	VSM_LOCK_CRS,
};

void  mshv_vtl1_init(void);

#endif /* _VSM_H */
