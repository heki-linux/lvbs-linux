// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common code
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>

#include "common.h"

bool heki_enabled __ro_after_init = true;
struct heki heki;

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

	if (!heki.hypervisor) {
		/* This happens for kernels running on bare metal as well. */
		pr_warn("No support for Heki in the active hypervisor\n");
		return;
	}
	pr_warn("Heki is supported by the active Hypervisor\n");
}

/*
 * Must be called after mark_readonly().
 */
void heki_late_init(void)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;

	if (!heki_enabled || !heki.hypervisor)
		return;

	/* Locks control registers so a compromised guest cannot change them. */
	if (WARN_ON(hypervisor->lock_crs()))
		return;

	pr_warn("Control registers locked\n");
}

static int __init heki_parse_config(char *str)
{
	if (strtobool(str, &heki_enabled))
		pr_warn("Invalid option string for heki: '%s'\n", str);
	return 1;
}
__setup("heki=", heki_parse_config);
