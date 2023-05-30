// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/vsm.h>

static void return_to_vtl0(void);

static void handle_entry(void)
{
	pr_err("handle_entry\n");
	return_to_vtl0();
}

static void return_to_vtl0(void)
{
	asm __volatile__ (      \
		"mov $0xABDCEF20, %%r9\n"
		"mov $0x00, %%rax\n"
		"mov $0x12, %%rcx\n"
		"vmcall\n" : : :);
	handle_entry();
}

void  mshv_vtl1_init(void)
{
	pr_err("mshv_vtl1_init\n");
	return_to_vtl0();
}

