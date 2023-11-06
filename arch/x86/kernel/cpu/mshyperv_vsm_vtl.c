// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */
 #include <asm/apic.h>
#include <asm/realmode.h>
#include <asm/fpu/internal.h>

#define VSM_BOOT_SIGNAL 0xDC

static struct real_mode_header hv_mshv_real_mode_header;
u8 *boot_signal;

static int hv_vtl1_wakeup_secondary_cpu(int apicid, unsigned long start_eip)
{
	WRITE_ONCE(boot_signal[apicid], VSM_BOOT_SIGNAL);
	return 0;
}

int mshv_vtl1_init_boot_signal_page(void *shared_data)
{
	if (!shared_data)
		return -EINVAL;

	boot_signal = (u8 *)shared_data;
	/* VTL 0 sets the boot signal for cpu 0 and sends the page across. */
	if (boot_signal[0] != VSM_BOOT_SIGNAL)
		return -EINVAL;
	else
		return 0;
}

static int __init mshv_vtl1_early_init(void)
{
	/*
	 * `boot_cpu_has` returns the runtime feature support,
	 * and here is the earliest it can be used.
	 */
	if (boot_cpu_has(X86_FEATURE_XSAVE))
		panic("XSAVE has to be disabled as it is not supported by this module.\n"
			  "Please add 'noxsave' to the kernel command line.\n");

	real_mode_header = &hv_mshv_real_mode_header;
	apic->wakeup_secondary_cpu = hv_vtl1_wakeup_secondary_cpu;

	return 0;
}
early_initcall(mshv_vtl1_early_init);
