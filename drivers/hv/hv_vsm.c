// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   
 */

#include <linux/types.h>
#include <linux/irqflags.h>
#include "hv_vsm.h"

static void hv_vsm_hv_do_vtlcall(void)
{
	unsigned long flags = 0;
	struct vtlcall_param args = {0};

	local_irq_save(flags);
	hv_vsm_vtl_call(&args);
	local_irq_restore(flags);
}
