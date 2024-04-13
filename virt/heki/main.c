// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common code
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>

#include "common.h"

bool heki_enabled __ro_after_init = true;

/*
 * Must be called after kmem_cache_init().
 */
__init void heki_early_init(void)
{
	if (!heki_enabled) {
		pr_warn("Heki is not enabled\n");
		return;
	}
	pr_warn("Heki is enabled\n");
}

static int __init heki_parse_config(char *str)
{
	if (strtobool(str, &heki_enabled))
		pr_warn("Invalid option string for heki: '%s'\n", str);
	return 1;
}
__setup("heki=", heki_parse_config);
