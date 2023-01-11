
#ifndef LINUX_SECUREKERNEL_CORE_H
#define LINUX_SECUREKERNEL_CORE_H

#include <linux/linkage.h>
#include <linux/elfcore.h>
#include <linux/elf.h>

extern struct resource securek_res;

int __init parse_securekernel(char *cmdline, unsigned long long system_ram,
		unsigned long long *securekernel_size, unsigned long long *securekernel_base);

#endif /* LINUX_SECUREKERNEL_CORE_H */
