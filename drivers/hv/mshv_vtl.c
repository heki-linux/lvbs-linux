// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, Microsoft Corporation.
 *
 * Author:
 *   Saurabh Sengar <ssengar@microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>
#include <linux/tracehook.h>
#include <linux/cpuhotplug.h>
#include <linux/mshv.h>
#include <linux/hyperv.h>
#include <asm/debugreg.h>
#include <asm/fpu/internal.h>
#include <asm/mshyperv.h>
#include <linux/count_zeros.h>
#include <uapi/asm/mtrr.h>

#include "mshv.h"
#include "mshv_eventfd.h"
#include "hyperv_vmbus.h"

MODULE_AUTHOR("Microsoft");
MODULE_LICENSE("GPL");

#define MSHV_ENTRY_REASON_LOWER_VTL_CALL     0x1
#define MSHV_ENTRY_REASON_INTERRUPT          0x2
#define MSHV_ENTRY_REASON_INTERCEPT          0x3

#define MAX_GUEST_MEM_SIZE	BIT_ULL(40)

bool vtl_exist;
static u64 mshv_ram_last_pfn;
static u64 mshv_ram_start_pfn;
static struct device *mem_dev;

struct mshv_poll_file {
	struct file *file;
	wait_queue_entry_t wait;
	wait_queue_head_t *wqh;
	poll_table pt;
	int cpu;
};

struct mshv_vtl {
	u64 id;
	refcount_t ref_count;
};

union hv_register_vsm_capabilities {
	u64 as_uint64;
	struct {
		u64 dr6_shared: 1;
		u64 mbec_vtl_mask: 16;
		u64 deny_lower_vtl_startup: 1;
		u64 supervisor_shadow_stack: 1;
		u64 hardware_hvpt_available: 1;
		u64 software_hvpt_available: 1;
		u64 hardware_hvpt_range_bits: 6;
		u64 intercept_page_available: 1;
		u64 return_action_available: 1;
		u64 reserved: 35;
	} __packed;
};

union hv_register_vsm_page_offsets {
	struct {
		u64 vtl_call_offset : 12;
		u64 vtl_return_offset : 12;
		u64 reserved_mbz : 40;
	};
	u64 as_uint64;
} __packed;

struct mshv_vtl_per_cpu {
	struct mshv_vtl_run *run;
	struct page *hvcall_in_page;
	struct page *hvcall_out_page;
	struct page *reg_page;
};

static struct mutex	mshv_poll_file_lock;
static union hv_register_vsm_page_offsets mshv_vsm_page_offsets;
static union hv_register_vsm_capabilities mshv_vsm_capabilities;

static DEFINE_PER_CPU(struct mshv_poll_file, mshv_poll_file);
static DEFINE_PER_CPU(unsigned long long, num_vtl0_transitions);
static DEFINE_PER_CPU(struct mshv_vtl_per_cpu, mshv_vtl_per_cpu);

struct mshv_vtl_run *mshv_this_run(void)
{
	return *this_cpu_ptr(&mshv_vtl_per_cpu.run);
}

struct mshv_vtl_run *mshv_cpu_run(int cpu)
{
	return *per_cpu_ptr(&mshv_vtl_per_cpu.run, cpu);
}

struct page *mshv_cpu_reg_page(int cpu)
{
	return *per_cpu_ptr(&mshv_vtl_per_cpu.reg_page, cpu);
}

static u64 mshv_get_ram_start_pfn(void)
{
	return mshv_ram_start_pfn;
}

static u64 mshv_get_ram_last_pfn(void)
{
	return mshv_ram_last_pfn;
}

static int mshv_vtl_ioctl_ram_disposition(void __user *arg)
{
	struct mshv_ram_disposition ram_disposition = {
		.start_pfn = mshv_get_ram_start_pfn(),
		.last_pfn = mshv_get_ram_last_pfn()
	};

	if (ram_disposition.start_pfn < (MAX_GUEST_MEM_SIZE >> PAGE_SHIFT) &&
	    ram_disposition.last_pfn < (MAX_GUEST_MEM_SIZE >> PAGE_SHIFT) &&
	    ram_disposition.start_pfn > 0 &&
	    ram_disposition.start_pfn < ram_disposition.last_pfn) {
		return 0;
	}

	if (copy_to_user(arg, &ram_disposition, sizeof(ram_disposition)))
		return -EFAULT;

	return -ENOMEM;
}

static int mshv_vtl_ioctl_add_vtl0_mem(void __user *arg)
{
	struct mshv_ram_disposition vtl0_mem;
	struct dev_pagemap *pgmap;
	void *addr;

	if (copy_from_user(&vtl0_mem, arg, sizeof(vtl0_mem)))
		return -EFAULT;

	if (vtl0_mem.last_pfn <= vtl0_mem.start_pfn) {
		pr_err("%s: range start pfn (%llx) > end pfn (%llx)\n",
		       __func__, vtl0_mem.start_pfn, vtl0_mem.last_pfn);
		return -EFAULT;
	}

	pgmap = kzalloc(sizeof(*pgmap), GFP_KERNEL);
	if (!pgmap)
		return -ENOMEM;

	pgmap->ranges[0].start = PFN_PHYS(vtl0_mem.start_pfn);
	pgmap->ranges[0].end = PFN_PHYS(vtl0_mem.last_pfn) - 1;
	pgmap->nr_range = 1;
	pgmap->type = MEMORY_DEVICE_GENERIC;

	/*
	 * Determine the highest page order that can be used for the range.
	 * This works best when the range is aligned; i.e. start and length.
	 */
	pgmap->vmemmap_shift = count_trailing_zeros(vtl0_mem.start_pfn | vtl0_mem.last_pfn);
	pr_debug("Add VTL0 memory: start: 0x%llx, end_pfn: 0x%llx, page order: %lu\n",
		 vtl0_mem.start_pfn, vtl0_mem.last_pfn, pgmap->vmemmap_shift);

	addr = devm_memremap_pages(mem_dev, pgmap);
	if (IS_ERR(addr)) {
		pr_err("%s: devm_memremap_pages error: %ld\n", __func__, PTR_ERR(addr));
		kfree(pgmap);
		return -EFAULT;
	}

	/* Don't free pgmap, since it has to stick around until the memory
	 * is unmapped, which will never happen as there is no scenario
	 * where VTL0 can be released/shutdown without bringing down VTL2.
	 */
	return 0;
}

static void mshv_cancel(int cpu)
{
	int here = get_cpu();

	if (here != cpu) {
		if (!xchg_relaxed(&mshv_cpu_run(cpu)->cancel, 1))
			smp_send_reschedule(cpu);
	} else {
		WRITE_ONCE(mshv_this_run()->cancel, 1);
	}
	put_cpu();
}

static int mshv_poll_file_wake(wait_queue_entry_t *wait, unsigned int mode, int sync, void *key)
{
	struct mshv_poll_file *poll_file = container_of(wait, struct mshv_poll_file, wait);

	mshv_cancel(poll_file->cpu);
	return 0;
}

static void mshv_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh, poll_table *pt)
{
	struct mshv_poll_file *poll_file = container_of(pt, struct mshv_poll_file, pt);

	WARN_ON(poll_file->wqh);
	poll_file->wqh = wqh;
	add_wait_queue(wqh, &poll_file->wait);
}

static int mshv_vtl_ioctl_set_poll_file(struct mshv_set_poll_file __user *user_input)
{
	struct file *file, *old_file;
	struct mshv_poll_file *poll_file;
	struct mshv_set_poll_file input;

	if (copy_from_user(&input, user_input, sizeof(input)))
		return -EFAULT;

	if (!cpu_online(input.cpu))
		return -EINVAL;

	file = NULL;
	if (input.fd >= 0) {
		file = fget(input.fd);
		if (!file)
			return -EBADFD;
	}

	poll_file = per_cpu_ptr(&mshv_poll_file, input.cpu);

	mutex_lock(&mshv_poll_file_lock);

	if (poll_file->wqh)
		remove_wait_queue(poll_file->wqh, &poll_file->wait);
	poll_file->wqh = NULL;

	old_file = poll_file->file;
	poll_file->file = file;
	poll_file->cpu = input.cpu;

	if (file) {
		init_waitqueue_func_entry(&poll_file->wait, mshv_poll_file_wake);
		init_poll_funcptr(&poll_file->pt, mshv_ptable_queue_proc);
		vfs_poll(file, &poll_file->pt);
	}

	mutex_unlock(&mshv_poll_file_lock);

	if (old_file)
		fput(old_file);

	return 0;
}

static int mshv_vtl_set_reg(struct hv_register_assoc *regs)
{
	u64 reg64;
	enum hv_x64_register_name gpr_name;

	gpr_name = regs->name;
	reg64 = regs->value.reg64;

	switch (gpr_name) {
	case HV_X64_REGISTER_DR0:
		native_set_debugreg(0, reg64);
		break;
	case HV_X64_REGISTER_DR1:
		native_set_debugreg(1, reg64);
		break;
	case HV_X64_REGISTER_DR2:
		native_set_debugreg(2, reg64);
		break;
	case HV_X64_REGISTER_DR3:
		native_set_debugreg(3, reg64);
		break;
	case HV_X64_REGISTER_DR6:
		if (!mshv_vsm_capabilities.dr6_shared)
			goto hypercall;
		native_set_debugreg(6, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_CAP:
		wrmsrl(MSR_MTRRcap, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_DEF_TYPE:
		wrmsrl(MSR_MTRRdefType, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0:
		wrmsrl(MTRRphysBase_MSR(0), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE1:
		wrmsrl(MTRRphysBase_MSR(1), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE2:
		wrmsrl(MTRRphysBase_MSR(2), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE3:
		wrmsrl(MTRRphysBase_MSR(3), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE4:
		wrmsrl(MTRRphysBase_MSR(4), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE5:
		wrmsrl(MTRRphysBase_MSR(5), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE6:
		wrmsrl(MTRRphysBase_MSR(6), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE7:
		wrmsrl(MTRRphysBase_MSR(7), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE8:
		wrmsrl(MTRRphysBase_MSR(8), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE9:
		wrmsrl(MTRRphysBase_MSR(9), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEA:
		wrmsrl(MTRRphysBase_MSR(0xa), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEB:
		wrmsrl(MTRRphysBase_MSR(0xb), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEC:
		wrmsrl(MTRRphysBase_MSR(0xc), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASED:
		wrmsrl(MTRRphysBase_MSR(0xd), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEE:
		wrmsrl(MTRRphysBase_MSR(0xe), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEF:
		wrmsrl(MTRRphysBase_MSR(0xf), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0:
		wrmsrl(MTRRphysMask_MSR(0), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK1:
		wrmsrl(MTRRphysMask_MSR(1), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK2:
		wrmsrl(MTRRphysMask_MSR(2), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK3:
		wrmsrl(MTRRphysMask_MSR(3), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK4:
		wrmsrl(MTRRphysMask_MSR(4), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK5:
		wrmsrl(MTRRphysMask_MSR(5), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK6:
		wrmsrl(MTRRphysMask_MSR(6), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK7:
		wrmsrl(MTRRphysMask_MSR(7), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK8:
		wrmsrl(MTRRphysMask_MSR(8), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK9:
		wrmsrl(MTRRphysMask_MSR(9), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKA:
		wrmsrl(MTRRphysMask_MSR(0xa), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKB:
		wrmsrl(MTRRphysMask_MSR(0xa), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKC:
		wrmsrl(MTRRphysMask_MSR(0xc), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKD:
		wrmsrl(MTRRphysMask_MSR(0xd), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKE:
		wrmsrl(MTRRphysMask_MSR(0xe), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKF:
		wrmsrl(MTRRphysMask_MSR(0xf), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX64K00000:
		wrmsrl(MSR_MTRRfix64K_00000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX16K80000:
		wrmsrl(MSR_MTRRfix16K_80000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX16KA0000:
		wrmsrl(MSR_MTRRfix16K_A0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KC0000:
		wrmsrl(MSR_MTRRfix4K_C0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KC8000:
		wrmsrl(MSR_MTRRfix4K_C8000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KD0000:
		wrmsrl(MSR_MTRRfix4K_D0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KD8000:
		wrmsrl(MSR_MTRRfix4K_D8000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KE0000:
		wrmsrl(MSR_MTRRfix4K_E0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KE8000:
		wrmsrl(MSR_MTRRfix4K_E8000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KF0000:
		wrmsrl(MSR_MTRRfix4K_F0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KF8000:
		wrmsrl(MSR_MTRRfix4K_F8000, reg64);
		break;

	default:
		goto hypercall;
	}

	return 0;

hypercall:
	return 1;
}

static int mshv_vtl_get_reg(struct hv_register_assoc *regs)
{
	u64 *reg64;
	enum hv_x64_register_name gpr_name;

	gpr_name = regs->name;
	reg64 = (u64 *)&regs->value.reg64;

	switch (gpr_name) {
	case HV_X64_REGISTER_DR0:
		*reg64 = native_get_debugreg(0);
		break;
	case HV_X64_REGISTER_DR1:
		*reg64 = native_get_debugreg(1);
		break;
	case HV_X64_REGISTER_DR2:
		*reg64 = native_get_debugreg(2);
		break;
	case HV_X64_REGISTER_DR3:
		*reg64 = native_get_debugreg(3);
		break;
	case HV_X64_REGISTER_DR6:
		if (!mshv_vsm_capabilities.dr6_shared)
			goto hypercall;
		*reg64 = native_get_debugreg(6);
		break;
	case HV_X64_REGISTER_MSR_MTRR_CAP:
		rdmsrl(MSR_MTRRcap, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_DEF_TYPE:
		rdmsrl(MSR_MTRRdefType, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0:
		rdmsrl(MTRRphysBase_MSR(0), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE1:
		rdmsrl(MTRRphysBase_MSR(1), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE2:
		rdmsrl(MTRRphysBase_MSR(2), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE3:
		rdmsrl(MTRRphysBase_MSR(3), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE4:
		rdmsrl(MTRRphysBase_MSR(4), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE5:
		rdmsrl(MTRRphysBase_MSR(5), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE6:
		rdmsrl(MTRRphysBase_MSR(6), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE7:
		rdmsrl(MTRRphysBase_MSR(7), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE8:
		rdmsrl(MTRRphysBase_MSR(8), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE9:
		rdmsrl(MTRRphysBase_MSR(9), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEA:
		rdmsrl(MTRRphysBase_MSR(0xa), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEB:
		rdmsrl(MTRRphysBase_MSR(0xb), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEC:
		rdmsrl(MTRRphysBase_MSR(0xc), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASED:
		rdmsrl(MTRRphysBase_MSR(0xd), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEE:
		rdmsrl(MTRRphysBase_MSR(0xe), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEF:
		rdmsrl(MTRRphysBase_MSR(0xf), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0:
		rdmsrl(MTRRphysMask_MSR(0), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK1:
		rdmsrl(MTRRphysMask_MSR(1), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK2:
		rdmsrl(MTRRphysMask_MSR(2), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK3:
		rdmsrl(MTRRphysMask_MSR(3), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK4:
		rdmsrl(MTRRphysMask_MSR(4), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK5:
		rdmsrl(MTRRphysMask_MSR(5), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK6:
		rdmsrl(MTRRphysMask_MSR(6), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK7:
		rdmsrl(MTRRphysMask_MSR(7), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK8:
		rdmsrl(MTRRphysMask_MSR(8), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK9:
		rdmsrl(MTRRphysMask_MSR(9), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKA:
		rdmsrl(MTRRphysMask_MSR(0xa), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKB:
		rdmsrl(MTRRphysMask_MSR(0xb), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKC:
		rdmsrl(MTRRphysMask_MSR(0xc), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKD:
		rdmsrl(MTRRphysMask_MSR(0xd), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKE:
		rdmsrl(MTRRphysMask_MSR(0xe), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKF:
		rdmsrl(MTRRphysMask_MSR(0xf), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX64K00000:
		rdmsrl(MSR_MTRRfix64K_00000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX16K80000:
		rdmsrl(MSR_MTRRfix16K_80000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX16KA0000:
		rdmsrl(MSR_MTRRfix16K_A0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KC0000:
		rdmsrl(MSR_MTRRfix4K_C0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KC8000:
		rdmsrl(MSR_MTRRfix4K_C8000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KD0000:
		rdmsrl(MSR_MTRRfix4K_D0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KD8000:
		rdmsrl(MSR_MTRRfix4K_D8000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KE0000:
		rdmsrl(MSR_MTRRfix4K_E0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KE8000:
		rdmsrl(MSR_MTRRfix4K_E8000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KF0000:
		rdmsrl(MSR_MTRRfix4K_F0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KF8000:
		rdmsrl(MSR_MTRRfix4K_F8000, *reg64);
		break;

	default:
		goto hypercall;
	}

	return 0;

hypercall:
	return 1;
}

static void mshv_vtl_return(struct mshv_cpu_context *vtl0)
{
	struct hv_vp_assist_page *hvp;
	u64 hypercall_addr;

	register u64 r8 asm("r8");
	register u64 r9 asm("r9");
	register u64 r10 asm("r10");
	register u64 r11 asm("r11");
	register u64 r12 asm("r12");
	register u64 r13 asm("r13");
	register u64 r14 asm("r14");
	register u64 r15 asm("r15");

	hvp = hv_vp_assist_page[smp_processor_id()];

	/*
	 * Process signal event direct set in the run page, if any.
	 */
	if (mshv_vsm_capabilities.return_action_available) {
		u32 offset = READ_ONCE(mshv_this_run()->vtl_ret_action_size);

		WRITE_ONCE(mshv_this_run()->vtl_ret_action_size, 0);

		/*
		 * Hypervisor will take care of clearing out the actions
		 * set in the assist page.
		 */
		memcpy(hvp->vtl_ret_actions,
		       mshv_this_run()->vtl_ret_actions,
		       min_t(u32, offset, sizeof(hvp->vtl_ret_actions)));
	}

	hvp->vtl_ret_x64rax = vtl0->rax;
	hvp->vtl_ret_x64rcx = vtl0->rcx;

	hypercall_addr = (u64)((u8 *)hv_hypercall_pg + mshv_vsm_page_offsets.vtl_return_offset);

	kernel_fpu_begin_mask(0);
	fxrstor(&vtl0->fx_state);
	native_write_cr2(vtl0->cr2);
	r8 = vtl0->r8;
	r9 = vtl0->r9;
	r10 = vtl0->r10;
	r11 = vtl0->r11;
	r12 = vtl0->r12;
	r13 = vtl0->r13;
	r14 = vtl0->r14;
	r15 = vtl0->r15;

	asm __volatile__ (	\
	/* Save rbp pointer to the lower VTL, keep the stack 16-byte aligned */
		"pushq	%%rbp\n"
		"pushq	%%rcx\n"
	/* Restore the lower VTL's rbp */
		"movq	(%%rcx), %%rbp\n"
	/* Load return kind into rcx (HV_VTL_RETURN_INPUT_NORMAL_RETURN == 0) */
		"xorl	%%ecx, %%ecx\n"
	/* Transition to the lower VTL */
		CALL_NOSPEC
	/* Save VTL0's rax and rcx temporarily on 16-byte aligned stack */
		"pushq	%%rax\n"
		"pushq	%%rcx\n"
	/* Restore pointer to lower VTL rbp */
		"movq	16(%%rsp), %%rax\n"
	/* Save the lower VTL's rbp */
		"movq	%%rbp, (%%rax)\n"
	/* Restore saved registers */
		"movq	8(%%rsp), %%rax\n"
		"movq	24(%%rsp), %%rbp\n"
		"addq	$32, %%rsp\n"

		: "=a"(vtl0->rax), "=c"(vtl0->rcx),
		  "+d"(vtl0->rdx), "+b"(vtl0->rbx), "+S"(vtl0->rsi), "+D"(vtl0->rdi),
		  "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11),
		  "+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15)
		: THUNK_TARGET(hypercall_addr), "c"(&vtl0->rbp)
		: "cc", "memory");

	vtl0->r8 = r8;
	vtl0->r9 = r9;
	vtl0->r10 = r10;
	vtl0->r11 = r11;
	vtl0->r12 = r12;
	vtl0->r13 = r13;
	vtl0->r14 = r14;
	vtl0->r15 = r15;
	vtl0->cr2 = native_read_cr2();

	fxsave(&vtl0->fx_state);
	kernel_fpu_end();
}

static bool mshv_process_intercept(void)
{
	struct hv_per_cpu_context *mshv_cpu;
	void *synic_message_page;
	struct hv_message *msg;
	u32 message_type;

	mshv_cpu = this_cpu_ptr(hv_context.cpu_context);
	synic_message_page = mshv_cpu->synic_message_page;
	if (unlikely(!synic_message_page))
		return true;

	msg = (struct hv_message *)synic_message_page + HV_SYNIC_INTERCEPTION_SINT_INDEX;
	message_type = READ_ONCE(msg->header.message_type);
	if (message_type == HVMSG_NONE)
		return true;

	memcpy(mshv_this_run()->exit_message, msg, sizeof(*msg));
	vmbus_signal_eom(msg, message_type);
	return false;
}

static int mshv_vtl_ioctl_return_to_lower_vtl(void)
{
	preempt_disable();
	for (;;) {
		const unsigned long VTL0_WORK = _TIF_SIGPENDING | _TIF_NEED_RESCHED |
						_TIF_NOTIFY_RESUME | _TIF_NOTIFY_SIGNAL;
		unsigned long ti_work;
		u32 cancel;
		unsigned long irq_flags;
		struct hv_vp_assist_page *hvp;
		int ret;

		local_irq_save(irq_flags);
		ti_work = READ_ONCE(current_thread_info()->flags);
		cancel = READ_ONCE(mshv_this_run()->cancel);
		if (unlikely((ti_work & VTL0_WORK) || cancel)) {
			local_irq_restore(irq_flags);
			preempt_enable();
			if (cancel)
				ti_work |= _TIF_SIGPENDING;
			ret = mshv_xfer_to_guest_mode_handle_work(ti_work);
			if (ret)
				return ret;
			preempt_disable();
			continue;
		}

		mshv_vtl_return(&mshv_this_run()->cpu_context);
		local_irq_restore(irq_flags);

		hvp = hv_vp_assist_page[smp_processor_id()];
		this_cpu_inc(num_vtl0_transitions);
		switch (hvp->vtl_entry_reason) {
		case MSHV_ENTRY_REASON_INTERRUPT:
			if (!mshv_vsm_capabilities.intercept_page_available &&
			    likely(!mshv_process_intercept()))
				goto done;
			break;

		case MSHV_ENTRY_REASON_INTERCEPT:
			WARN_ON(!mshv_vsm_capabilities.intercept_page_available);
			memcpy(mshv_this_run()->exit_message, hvp->intercept_message,
			       sizeof(hvp->intercept_message));
			goto done;

		default:
			panic("unknown entry reason: %d", hvp->vtl_entry_reason);
		}
	}

done:
	preempt_enable();
	return 0;
}

static long
mshv_vtl_ioctl_set_regs(struct mshv_vp *vp, void __user *user_args)
{
	struct mshv_vp_registers args;
	struct hv_register_assoc *registers;
	long ret;
	int i;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	if (args.count > MSHV_VP_MAX_REGISTERS)
		return -EINVAL;

	registers = kmalloc_array(args.count,
				  sizeof(*registers),
				  GFP_KERNEL);
	if (!registers)
		return -ENOMEM;

	if (copy_from_user(registers, args.regs,
			   sizeof(*registers) * args.count)) {
		ret = -EFAULT;
		goto free_return;
	}

	for (i = 0; i < args.count; i++) {
		/*
		 * Disallow setting suspend registers to ensure run vp state
		 * is consistent
		 */
		if (registers[i].name == HV_REGISTER_EXPLICIT_SUSPEND ||
		    registers[i].name == HV_REGISTER_INTERCEPT_SUSPEND) {
			pr_err("%s: not allowed to set suspend registers\n",
			       __func__);
			ret = -EINVAL;
			goto free_return;
		}
	}

	ret = mshv_vtl_set_reg(registers);
	if (!ret)
		goto free_return; /* No need of hypercall */
	ret = hv_call_set_vp_registers(vp->index, vp->partition->id,
				       args.count, registers);

free_return:
	kfree(registers);
	return ret;
}

static long
mshv_vtl_ioctl_get_regs(struct mshv_vp *vp, void __user *user_args)
{
	struct mshv_vp_registers args;
	struct hv_register_assoc *registers;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	if (args.count > MSHV_VP_MAX_REGISTERS)
		return -EINVAL;

	registers = kmalloc_array(args.count,
				  sizeof(*registers),
				  GFP_KERNEL);
	if (!registers)
		return -ENOMEM;

	if (copy_from_user(registers, args.regs,
			   sizeof(*registers) * args.count)) {
		ret = -EFAULT;
		goto free_return;
	}

	ret = mshv_vtl_get_reg(registers);
	if (!ret)
		goto copy_args; /* No need of hypercall */
	ret = hv_call_get_vp_registers(vp->index, vp->partition->id,
				       args.count, registers);
	if (ret)
		goto free_return;

copy_args:
	if (copy_to_user(args.regs, registers,
			 sizeof(*registers) * args.count)) {
		ret = -EFAULT;
	}

free_return:
	kfree(registers);
	return ret;
}

static long
mshv_vtl_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	long ret;
	struct mshv_partition *partition;
	struct mshv_vp vp;

	partition = kzalloc(sizeof(*partition), GFP_KERNEL);
	if (!partition)
		return -ENOMEM;

	vp.partition = partition;
	vp.partition->id = HV_PARTITION_ID_SELF;
	vp.index = HV_VP_INDEX_SELF;

	switch (ioctl) {
	case MSHV_INSTALL_INTERCEPT:
		ret = mshv_partition_ioctl_install_intercept(partition, (void __user *)arg);
		break;
	case MSHV_VTL_SET_POLL_FILE:
		ret = mshv_vtl_ioctl_set_poll_file((struct mshv_set_poll_file *)arg);
		break;
	case MSHV_GET_VP_REGISTERS:
		ret = mshv_vtl_ioctl_get_regs(&vp, (void __user *)arg);
		break;
	case MSHV_SET_VP_REGISTERS:
		ret = mshv_vtl_ioctl_set_regs(&vp, (void __user *)arg);
		break;
	case MSHV_VTL_RETURN_TO_LOWER_VTL:
		ret = mshv_vtl_ioctl_return_to_lower_vtl();
		break;
	case MSHV_POST_MESSAGE_DIRECT:
		ret = mshv_partition_ioctl_post_message_direct(partition, (void __user *)arg);
		break;
	case MSHV_ASSERT_INTERRUPT:
		ret = mshv_partition_ioctl_assert_interrupt(partition, (void __user *)arg);
		break;
	case MSHV_TRANSLATE_GVA:
		ret = mshv_vp_ioctl_translate_gva(&vp, (void __user *)arg);
		break;
	case MSHV_VTL_RAM_DISPOSITION:
		ret = mshv_vtl_ioctl_ram_disposition((void __user *)arg);
		break;
	case MSHV_VTL_ADD_VTL0_MEMORY:
		ret = mshv_vtl_ioctl_add_vtl0_mem((void __user *)arg);
		break;
	case MSHV_SIGNAL_EVENT_DIRECT:
		ret = mshv_partition_ioctl_signal_event_direct(partition,
							       (void __user *)arg);
		break;
	default:
		pr_err("%s: invalid vtl ioctl: %#x\n", __func__, ioctl);
		ret = -ENOTTY;
	}

	kfree(partition);
	return ret;
}

static const struct file_operations mshv_vtl_fops = {
	.unlocked_ioctl = mshv_vtl_ioctl,
};

long mshv_ioctl_create_vtl(void __user *user_arg)
{
	struct mshv_vtl *vtl;
	struct file *file;
	int fd;

	if (vtl_exist) {
		pr_err("%s: Multiple VTL creation not supported\n", __func__);
		return -EPERM;
	}
	vtl_exist = true;

	vtl = kzalloc(sizeof(*vtl), GFP_KERNEL);
	if (!vtl)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	file = anon_inode_getfile("mshv_vtl", &mshv_vtl_fops,
				  vtl, O_RDWR);
	if (IS_ERR(file))
		return PTR_ERR(file);
	refcount_set(&vtl->ref_count, 1);

	mutex_init(&mshv_poll_file_lock);
	fd_install(fd, file);

	return fd;
}
