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
#include <linux/printk.h>

#ifdef CONFIG_HEKI

/*
 * A hypervisor that supports Heki will instantiate this structure to
 * provide hypervisor specific functions for Heki.
 */
struct heki_hypervisor {
	/* Lock control registers. */
	int (*lock_crs)(void);
};

/*
 * If the active hypervisor supports Heki, it will plug its heki_hypervisor
 * pointer into this heki structure.
 */
struct heki {
	struct heki_hypervisor *hypervisor;
};

extern struct heki heki;
extern bool heki_enabled;

void heki_early_init(void);
void heki_late_init(void);

#else /* !CONFIG_HEKI */

static inline void heki_early_init(void)
{
}
static inline void heki_late_init(void)
{
}

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
