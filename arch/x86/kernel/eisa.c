// SPDX-License-Identifier: GPL-2.0-only
/*
 * EISA specific code
 */
#include <linux/ioport.h>
#include <linux/eisa.h>
#include <linux/io.h>

#include <xen/xen.h>

extern bool hyperv_paravisor_present;

static __init int eisa_bus_probe(void)
{
	void __iomem *p;

	/*
	 * Hyper-V hasn't emulated this MMIO access yet for a TDX VM with
	 * the pavavisor: in such a VM, the "readl(p)" below causes a
	 * soft lockup. Work around the issue for now.
	 */
	if (hyperv_paravisor_present)
		return 0;

	if (xen_pv_domain() && !xen_initial_domain())
		return 0;

	p = ioremap(0x0FFFD9, 4);
	if (p && readl(p) == 'E' + ('I' << 8) + ('S' << 16) + ('A' << 24))
		EISA_bus = 1;
	iounmap(p);
	return 0;
}
subsys_initcall(eisa_bus_probe);
