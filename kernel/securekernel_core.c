
#include <linux/buildid.h>
#include <linux/securekernel_core.h>
#include <linux/init.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>

#include <asm/page.h>
#include <asm/sections.h>

#include <crypto/sha1.h>

struct resource securek_res = {
	.name  = "vsm",
	.start = 0,
	.end   = 0,
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
	.desc  = IORES_DESC_SECURE_KERNEL
};

/*
 * parsing the "securekernel" commandline
 *
 * this code is intended to be called from architecture specific code
 */


/*
 * That function parses "simple" securekernel command lines like
 *
 *	securekernel=size[@offset]
 *
 * It returns 0 on success and -EINVAL on failure.
 */
static int __init parse_securekernel_simple(char *cmdline,
					   unsigned long long *securekernel_size,
					   unsigned long long *securekernel_base)
{
	char *cur = cmdline;

	*securekernel_size = memparse(cmdline, &cur);
	if (cmdline == cur) {
		pr_warn("securekernel: memory value expected\n");
		return -EINVAL;
	}

	if (*cur == '@')
		*securekernel_base = memparse(cur+1, &cur);
	else if (*cur != ' ' && *cur != '\0') {
		pr_warn("securekernel: unrecognized char: %c\n", *cur);
		return -EINVAL;
	}

	return 0;
}

static __init char *get_last_securekernel(char *cmdline,
			     const char *name)
{
	char *p = cmdline, *sk_cmdline = NULL;

	/* find securekernel and use the last one if there are more */
	p = strstr(p, name);
	while (p) {
		sk_cmdline = p;
		p = strstr(p+1, name);
	}

	if (!sk_cmdline)
		return NULL;

	return sk_cmdline;
}

static int __init __parse_securekernel(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *securekernel_size,
			     unsigned long long *securekernel_base,
			     const char *name)
{
	char	*sk_cmdline;

	BUG_ON(!securekernel_size || !securekernel_base);
	*securekernel_size = 0;
	*securekernel_base = 0;

	sk_cmdline = get_last_securekernel(cmdline, name);

	if (!sk_cmdline)
		return -EINVAL;

	sk_cmdline += strlen(name);

	return parse_securekernel_simple(sk_cmdline, securekernel_size, securekernel_base);
}

/*
 * That function is the entry point for command line parsing and should be
 * called from the arch-specific code.
 */
int __init parse_securekernel(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *securekernel_size,
			     unsigned long long *securekernel_base)
{
	return __parse_securekernel(cmdline, system_ram, securekernel_size, securekernel_base,
					"securekernel=");
}

/*
 * Add a dummy early_param handler to mark securekernel= as a known command line
 * parameter and suppress incorrect warnings in init/main.c.
 */
static int __init parse_securekernel_dummy(char *arg)
{
	return 0;
}
early_param("securekernel", parse_securekernel_dummy);
