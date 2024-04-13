/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Definitions
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef __HEKI_H__
#define __HEKI_H__

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>

#ifdef CONFIG_HEKI

extern bool heki_enabled;

void heki_early_init(void);

#else /* !CONFIG_HEKI */

static inline void heki_early_init(void)
{
}

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
