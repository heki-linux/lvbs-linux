// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020, Microsoft Corporation.
 *
 * Authors:
 *   Nuno Das Neves <nudasnev@microsoft.com>
 *   Lillian Grassin-Drake <ligrassi@microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/cpuhotplug.h>
#include <linux/random.h>
#include <linux/mshv.h>
#include <linux/mshv_eventfd.h>
#include <linux/hyperv.h>
#include <linux/nospec.h>
#include <asm/mshyperv.h>

#include "mshv.h"
#include "vfio.h"

MODULE_AUTHOR("Microsoft");
MODULE_LICENSE("GPL");

struct mshv mshv = {};

static int mshv_vp_release(struct inode *inode, struct file *filp);
static long mshv_vp_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);
static struct mshv_partition *mshv_partition_get(struct mshv_partition *partition);
static void mshv_partition_put(struct mshv_partition *partition);
static void mshv_partition_put_no_destroy(struct mshv_partition *partition);
static int mshv_partition_release(struct inode *inode, struct file *filp);
static long mshv_partition_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);
static int mshv_dev_open(struct inode *inode, struct file *filp);
static int mshv_dev_release(struct inode *inode, struct file *filp);
static long mshv_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);
static int mshv_vp_mmap(struct file *file, struct vm_area_struct *vma);
static vm_fault_t mshv_vp_fault(struct vm_fault *vmf);

static const struct vm_operations_struct mshv_vp_vm_ops = {
	.fault = mshv_vp_fault,
};

static const struct file_operations mshv_vp_fops = {
	.release = mshv_vp_release,
	.unlocked_ioctl = mshv_vp_ioctl,
	.llseek = noop_llseek,
	.mmap = mshv_vp_mmap,
};

static const struct file_operations mshv_partition_fops = {
	.release = mshv_partition_release,
	.unlocked_ioctl = mshv_partition_ioctl,
	.llseek = noop_llseek,
};

static const struct file_operations mshv_dev_fops = {
	.owner = THIS_MODULE,
	.open = mshv_dev_open,
	.release = mshv_dev_release,
	.unlocked_ioctl = mshv_dev_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice mshv_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mshv",
	.fops = &mshv_dev_fops,
	.mode = 0600,
};

static long
mshv_vp_ioctl_get_regs(struct mshv_vp *vp, void __user *user_args)
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

	ret = hv_call_get_vp_registers(vp->index, vp->partition->id,
				       args.count, registers);
	if (ret)
		goto free_return;

	if (copy_to_user(args.regs, registers,
			 sizeof(*registers) * args.count)) {
		ret = -EFAULT;
	}

free_return:
	kfree(registers);
	return ret;
}

static long
mshv_vp_ioctl_set_regs(struct mshv_vp *vp, void __user *user_args)
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

	ret = hv_call_set_vp_registers(vp->index, vp->partition->id,
				       args.count, registers);

free_return:
	kfree(registers);
	return ret;
}

/*
 * Explicit guest vCPU suspend is asynchronous by nature (as it is requested by
 * dom0 vCPU for guest vCPU) and thus it can race with "intercept" suspend,
 * done by the hypervisor.
 * "Intercept" suspend leads to asynchronous message delivery to dom0 which
 * should be awaited to keep the VP loop consistent (i.e. no message pending
 * upon VP resume).
 * VP intercept suspend can't be done when the VP is explicitly suspended
 * already, and thus can be only two possible race scenarios:
 *   1. implicit suspend bit set -> explicit suspend bit set -> message sent
 *   2. implicit suspend bit set -> message sent -> explicit suspend bit set
 * Checking for implicit suspend bit set after explicit suspend request has
 * succeeded in either case allows us to reliably identify, if there is a
 * message to receive and deliver to VMM.
 */
static long
mshv_suspend_vp(const struct mshv_vp *vp, bool *message_in_flight)
{
	struct hv_register_assoc explicit_suspend = {
		.name = HV_REGISTER_EXPLICIT_SUSPEND
	};
	struct hv_register_assoc intercept_suspend = {
		.name = HV_REGISTER_INTERCEPT_SUSPEND
	};
	union hv_explicit_suspend_register *es =
		&explicit_suspend.value.explicit_suspend;
	union hv_intercept_suspend_register *is =
		&intercept_suspend.value.intercept_suspend;
	int ret;

	es->suspended = 1;

	ret = hv_call_set_vp_registers(vp->index, vp->partition->id,
				       1, &explicit_suspend);
	if (ret) {
		pr_err("%s: failed to explicitly suspend vCPU#%d in partition %lld\n",
				__func__, vp->index, vp->partition->id);
		return ret;
	}

	ret = hv_call_get_vp_registers(vp->index, vp->partition->id,
				       1, &intercept_suspend);
	if (ret) {
		pr_err("%s: failed to get intercept suspend state vCPU#%d in partition %lld\n",
			__func__, vp->index, vp->partition->id);
		return ret;
	}

	*message_in_flight = is->suspended;

	return 0;
}

/*
 * Caller has to make sure the registers contain cleared
 * HV_REGISTER_INTERCEPT_SUSPEND and HV_REGISTER_EXPLICIT_SUSPEND registers
 * exactly in this order (the hypervisor clears them sequentially) to avoid
 * potential invalid clearing a newly arrived HV_REGISTER_INTERCEPT_SUSPEND
 * after VP is released from HV_REGISTER_EXPLICIT_SUSPEND in case of the
 * opposite order.
 */
static long
mshv_run_vp(struct mshv_vp *vp, void __user *ret_message,
	    struct hv_register_assoc *registers, size_t count)

{
	struct hv_message *msg = vp->run.intercept_message;
	long ret;

	/* Resume VP execution */
	ret = hv_call_set_vp_registers(vp->index, vp->partition->id,
				       count, registers);
	if (ret) {
		pr_err("%s: failed to resume vCPU#%d in partition %lld\n",
		       __func__, vp->index, vp->partition->id);
		return ret;
	}

	ret = wait_event_interruptible(vp->run.suspend_queue,
				       msg->header.message_type != HVMSG_NONE);
	if (ret) {
		bool message_in_flight;

		/*
		 * Otherwise the waiting was interrupted by a signal: suspend
		 * the vCPU explicitly and copy message in flight (if any).
		 */
		ret = mshv_suspend_vp(vp, &message_in_flight);
		if (ret)
			return ret;

		/* Return if no message in flight */
		if (!message_in_flight)
			return -EINTR;

		/* Wait for the message in flight. */
		wait_event(vp->run.suspend_queue,
			   msg->header.message_type != HVMSG_NONE);
	}

	if (copy_to_user(ret_message, vp->run.intercept_message,
			 sizeof(struct hv_message)))
		return -EFAULT;

	/*
	 * Reset the message type to make the wait_event call above work
	 * next time.
	 */
	msg->header.message_type = HVMSG_NONE;

	return 0;
}

static long
mshv_vp_ioctl_run_vp(struct mshv_vp *vp, void __user *ret_message)
{
	struct hv_register_assoc suspend_registers[2] = {
		{ .name = HV_REGISTER_INTERCEPT_SUSPEND },
		{ .name = HV_REGISTER_EXPLICIT_SUSPEND }
	};

	return mshv_run_vp(vp, ret_message,
			   suspend_registers, ARRAY_SIZE(suspend_registers));
}

static long
mshv_vp_ioctl_run_vp_regs(struct mshv_vp *vp,
			  struct mshv_vp_run_registers __user *user_args)
{
	struct hv_register_assoc suspend_registers[2] = {
		{ .name = HV_REGISTER_INTERCEPT_SUSPEND },
		{ .name = HV_REGISTER_EXPLICIT_SUSPEND }
	};
	struct mshv_vp_run_registers run_regs;
	struct hv_message __user *ret_message;
	struct mshv_vp_registers __user *user_regs;
	int i, regs_count;

	if (copy_from_user(&run_regs, user_args, sizeof(run_regs)))
		return -EFAULT;

	ret_message = run_regs.message;
	user_regs = &run_regs.registers;
	regs_count = user_regs->count;

	if (regs_count + ARRAY_SIZE(suspend_registers) > MSHV_VP_MAX_REGISTERS)
		return -EINVAL;

	if (copy_from_user(vp->registers, user_regs->regs,
			   sizeof(*vp->registers) * regs_count))
		return -EFAULT;

	for (i = 0; i < regs_count; i++) {
		/*
		 * Disallow setting suspend registers to ensure run vp state
		 * is consistent
		 */
		if (vp->registers[i].name == HV_REGISTER_EXPLICIT_SUSPEND ||
		    vp->registers[i].name == HV_REGISTER_INTERCEPT_SUSPEND) {
			pr_err("%s: not allowed to set suspend registers\n",
			       __func__);
			return -EINVAL;
		}
	}

	/* Set the last registers to clear suspend */
	memcpy(vp->registers + regs_count,
	       suspend_registers, sizeof(suspend_registers));

	return mshv_run_vp(vp, ret_message, vp->registers,
			   regs_count + ARRAY_SIZE(suspend_registers));
}

static long
mshv_vp_ioctl_get_set_state_pfn(struct mshv_vp *vp,
				struct mshv_vp_state *args,
				bool is_set)
{
	u64 page_count, remaining;
	int completed;
	struct page **pages;
	long ret;
	unsigned long u_buf;

	/* Buffer must be page aligned */
	if (!PAGE_ALIGNED(args->buf_size) ||
	    !PAGE_ALIGNED(args->buf.bytes))
		return -EINVAL;

	if (!access_ok(args->buf.bytes, args->buf_size))
		return -EFAULT;

	/* Pin user pages so hypervisor can copy directly to them */
	page_count = args->buf_size >> HV_HYP_PAGE_SHIFT;
	pages = kcalloc(page_count, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	remaining = page_count;
	u_buf = (unsigned long)args->buf.bytes;
	while (remaining) {
		completed = pin_user_pages_fast(
				u_buf,
				remaining,
				FOLL_WRITE,
				&pages[page_count - remaining]);
		if (completed < 0) {
			pr_err("%s: failed to pin user pages error %i\n",
			       __func__, completed);
			ret = completed;
			goto unpin_pages;
		}
		remaining -= completed;
		u_buf += completed * HV_HYP_PAGE_SIZE;
	}

	if (is_set)
		ret = hv_call_set_vp_state(vp->index,
					   vp->partition->id,
					   args->type, args->xsave,
					   page_count, pages,
					   0, NULL);
	else
		ret = hv_call_get_vp_state(vp->index,
					   vp->partition->id,
					   args->type, args->xsave,
					   page_count, pages,
					   NULL);

unpin_pages:
	unpin_user_pages(pages, page_count - remaining);
	kfree(pages);
	return ret;
}

static long
mshv_vp_ioctl_get_set_state(struct mshv_vp *vp, void __user *user_args, bool is_set)
{
	struct mshv_vp_state args;
	long ret = 0;
	union hv_get_vp_state_out vp_state;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	/* For now just support these */
	if (args.type != HV_GET_SET_VP_STATE_LOCAL_INTERRUPT_CONTROLLER_STATE &&
	    args.type != HV_GET_SET_VP_STATE_XSAVE)
		return -EINVAL;

	/* If we need to pin pfns, delegate to helper */
	if (args.type & HV_GET_SET_VP_STATE_TYPE_PFN)
		return mshv_vp_ioctl_get_set_state_pfn(vp, &args, is_set);

	if (args.buf_size < sizeof(vp_state))
		return -EINVAL;

	if (is_set) {
		if (copy_from_user(
				&vp_state,
				args.buf.lapic,
				sizeof(vp_state)))
			return -EFAULT;

		return hv_call_set_vp_state(vp->index,
					    vp->partition->id,
					    args.type, args.xsave,
					    0, NULL,
					    sizeof(vp_state),
					    (u8 *)&vp_state);
	}

	ret = hv_call_get_vp_state(vp->index,
				   vp->partition->id,
				   args.type, args.xsave,
				   0, NULL,
				   &vp_state);

	if (ret)
		return ret;

	if (copy_to_user(args.buf.lapic,
			 &vp_state.interrupt_controller_state,
			 sizeof(vp_state.interrupt_controller_state)))
		return -EFAULT;

	return 0;
}

static long
mshv_vp_ioctl_translate_gva(struct mshv_vp *vp, void __user *user_args)
{
	long ret;
	struct mshv_translate_gva args;
	u64 gpa;
	union hv_translate_gva_result result;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_translate_virtual_address(
			vp->index,
			vp->partition->id,
			args.flags,
			args.gva,
			&gpa,
			&result);

	if (ret)
		return ret;

	if (copy_to_user(args.result, &result, sizeof(*args.result)))
		return -EFAULT;

	if (copy_to_user(args.gpa, &gpa, sizeof(*args.gpa)))
		return -EFAULT;

	return 0;
}

static long
mshv_vp_ioctl_register_intercept_result(struct mshv_vp *vp, void __user *user_args)
{
	struct mshv_register_intercept_result args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_register_intercept_result(vp->index,
						vp->partition->id,
						args.intercept_type,
						&args.parameters);

	return ret;
}

static long 
mshv_vp_ioctl_get_cpuid_values(struct mshv_vp *vp, void __user *user_args)
{
	struct mshv_get_vp_cpuid_values args;
	union hv_get_vp_cpuid_values_flags flags;
	struct hv_cpuid_leaf_info info;
	union hv_output_get_vp_cpuid_values result;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	flags.use_vp_xfem_xss = 1;
	flags.apply_registered_values = 1;
	flags.reserved = 0;

	memset(&info, 0, sizeof(info));
	info.eax = args.function;
	info.ecx = args.index;

	ret = hv_call_get_vp_cpuid_values(vp->index,
					vp->partition->id,
					flags,
					&info,
					&result);

	if (ret)
		return ret;

	args.eax = result.eax;
	args.ebx = result.ebx;
	args.ecx = result.ecx;
	args.edx = result.edx;
	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static long
mshv_vp_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct mshv_vp *vp = filp->private_data;
	long r = -ENOTTY;

	if (mutex_lock_killable(&vp->mutex))
		return -EINTR;

	switch (ioctl) {
	case MSHV_RUN_VP:
		r = mshv_vp_ioctl_run_vp(vp, (void __user *)arg);
		break;
	case MSHV_RUN_VP_REGISTERS:
		r = mshv_vp_ioctl_run_vp_regs(vp, (void __user *)arg);
		break;
	case MSHV_GET_VP_REGISTERS:
		r = mshv_vp_ioctl_get_regs(vp, (void __user *)arg);
		break;
	case MSHV_SET_VP_REGISTERS:
		r = mshv_vp_ioctl_set_regs(vp, (void __user *)arg);
		break;
	case MSHV_GET_VP_STATE:
		r = mshv_vp_ioctl_get_set_state(vp, (void __user *)arg, false);
		break;
	case MSHV_SET_VP_STATE:
		r = mshv_vp_ioctl_get_set_state(vp, (void __user *)arg, true);
		break;
	case MSHV_TRANSLATE_GVA:
		r = mshv_vp_ioctl_translate_gva(vp, (void __user *)arg);
		break;
	case MSHV_VP_REGISTER_INTERCEPT_RESULT:
		r = mshv_vp_ioctl_register_intercept_result(vp, (void __user *)arg);
		break;
	case MSHV_GET_VP_CPUID_VALUES:
		r = mshv_vp_ioctl_get_cpuid_values(vp, (void __user *)arg);
		break;
	default:
		printk("%s: invalid ioctl: %#x\n", __func__, ioctl);
		break;
	}
	mutex_unlock(&vp->mutex);

	return r;
}

static vm_fault_t mshv_vp_fault(struct vm_fault *vmf)
{
	struct mshv_vp *vp = vmf->vma->vm_file->private_data;

	vmf->page = vp->register_page;
	get_page(vp->register_page);

	return 0;
}

static int mshv_vp_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct mshv_vp *vp = file->private_data;

	if (vma->vm_pgoff != MSHV_VP_MMAP_REGISTERS_OFFSET)
		return -EINVAL;

	if (mutex_lock_killable(&vp->mutex))
		return -EINTR;

	if (!vp->register_page) {
		ret = hv_call_map_vp_state_page(vp->index,
						vp->partition->id,
						&vp->register_page);
		if (ret) {
			mutex_unlock(&vp->mutex);
			return ret;
		}
	}

	mutex_unlock(&vp->mutex);

	vma->vm_ops = &mshv_vp_vm_ops;
	return 0;
}

static int
mshv_vp_release(struct inode *inode, struct file *filp)
{
	struct mshv_vp *vp = filp->private_data;

	/* Rest of VP cleanup happens in destroy_partition() */
	mshv_partition_put(vp->partition);
	return 0;
}

static long
mshv_partition_ioctl_create_vp(struct mshv_partition *partition,
			       void __user *arg)
{
	struct mshv_create_vp args;
	struct mshv_vp *vp;
	struct file *file;
	int fd;
	long ret;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	if (args.vp_index >= MSHV_MAX_VPS)
		return -EINVAL;

	if (partition->vps.array[args.vp_index])
		return -EEXIST;

	vp = kzalloc(sizeof(*vp), GFP_KERNEL);

	if (!vp)
		return -ENOMEM;

	mutex_init(&vp->mutex);
	init_waitqueue_head(&vp->run.suspend_queue);

	vp->run.intercept_message =
		(struct hv_message *)get_zeroed_page(GFP_KERNEL);
	if (!vp->run.intercept_message) {
		ret = -ENOMEM;
		goto free_vp;
	}

	vp->registers = kmalloc_array(MSHV_VP_MAX_REGISTERS,
				      sizeof(*vp->registers), GFP_KERNEL);
	if (!vp->registers) {
		ret = -ENOMEM;
		goto free_message;
	}

	vp->index = args.vp_index;
	vp->partition = mshv_partition_get(partition);
	if (!vp->partition) {
		ret = -EBADF;
		goto free_registers;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto put_partition;
	}

	file = anon_inode_getfile("mshv_vp", &mshv_vp_fops, vp, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto put_fd;
	}

	ret = hv_call_create_vp(
			NUMA_NO_NODE,
			partition->id,
			args.vp_index,
			0 /* Only valid for root partition VPs */
			);
	if (ret)
		goto release_file;

	/* already exclusive with the partition mutex for all ioctls */
	partition->vps.count++;
	partition->vps.array[args.vp_index] = vp;

	fd_install(fd, file);

	return fd;

release_file:
	file->f_op->release(file->f_inode, file);
put_fd:
	put_unused_fd(fd);
put_partition:
	mshv_partition_put(partition);
free_registers:
	kfree(vp->registers);
free_message:
	free_page((unsigned long)vp->run.intercept_message);
free_vp:
	kfree(vp);

	return ret;
}

static long
mshv_partition_ioctl_get_property(struct mshv_partition *partition,
				  void __user *user_args)
{
	struct mshv_partition_property args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_get_partition_property(
					partition->id,
					args.property_code,
					&args.property_value);

	if (ret)
		return ret;

	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static long
mshv_partition_ioctl_set_property(struct mshv_partition *partition,
				  void __user *user_args)
{
	struct mshv_partition_property args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return hv_call_set_partition_property(
			partition->id,
			args.property_code,
			args.property_value);
}

static long
mshv_partition_ioctl_map_memory(struct mshv_partition *partition,
				struct mshv_user_mem_region __user *user_mem)
{
	struct mshv_user_mem_region mem;
	struct mshv_mem_region *region;
	int completed;
	unsigned long remaining, batch_size;
	int i;
	struct page **pages;
	u64 page_count, user_start, user_end, gpfn_start, gpfn_end;
	u64 region_page_count, region_user_start, region_user_end;
	u64 region_gpfn_start, region_gpfn_end;
	long ret = 0;

	/* Check we have enough slots*/
	if (partition->regions.count == MSHV_MAX_MEM_REGIONS) {
		pr_err("%s: not enough memory region slots\n", __func__);
		return -ENOSPC;
	}

	if (copy_from_user(&mem, user_mem, sizeof(mem)))
		return -EFAULT;

	if (!mem.size ||
	    !PAGE_ALIGNED(mem.size) ||
	    !PAGE_ALIGNED(mem.userspace_addr) ||
	    !access_ok(mem.userspace_addr, mem.size))
		return -EINVAL;

	/* Reject overlapping regions */
	page_count = mem.size >> HV_HYP_PAGE_SHIFT;
	user_start = mem.userspace_addr;
	user_end = mem.userspace_addr + mem.size;
	gpfn_start = mem.guest_pfn;
	gpfn_end = mem.guest_pfn + page_count;
	for (i = 0; i < MSHV_MAX_MEM_REGIONS; ++i) {
		region = &partition->regions.slots[i];
		if (!region->size)
			continue;
		region_page_count = region->size >> HV_HYP_PAGE_SHIFT;
		region_user_start = region->userspace_addr;
		region_user_end = region->userspace_addr + region->size;
		region_gpfn_start = region->guest_pfn;
		region_gpfn_end = region->guest_pfn + region_page_count;

		if (!(user_end <= region_user_start) &&
		    !(region_user_end <= user_start)) {
			return -EEXIST;
		}
		if (!(gpfn_end <= region_gpfn_start) &&
		    !(region_gpfn_end <= gpfn_start)) {
			return -EEXIST;
		}
	}

	/* Pin the userspace pages */
	pages = vzalloc(sizeof(struct page *) * page_count);
	if (!pages)
		return -ENOMEM;

	remaining = page_count;
	while (remaining) {
		/*
		 * We need to batch this, as pin_user_pages_fast with the
		 * FOLL_LONGTERM flag does a big temporary allocation
		 * of contiguous memory
		 */
		batch_size = min(remaining, PIN_PAGES_BATCH_SIZE);
		completed = pin_user_pages_fast(
				mem.userspace_addr + (page_count - remaining) * HV_HYP_PAGE_SIZE,
				batch_size,
				FOLL_WRITE | FOLL_LONGTERM,
				&pages[page_count - remaining]);
		if (completed < 0) {
			pr_err("%s: failed to pin user pages error %i\n",
			       __func__,
			       completed);
			ret = completed;
			goto err_unpin_pages;
		}
		remaining -= completed;
	}

	/* Map the pages to GPA pages */
	ret = hv_call_map_gpa_pages(partition->id, mem.guest_pfn,
				    page_count, mem.flags, pages);
	if (ret)
		goto err_unpin_pages;

	/* Install the new region */
	for (i = 0; i < MSHV_MAX_MEM_REGIONS; ++i) {
		if (!partition->regions.slots[i].size) {
			region = &partition->regions.slots[i];
			break;
		}
	}
	region->pages = pages;
	region->size = mem.size;
	region->guest_pfn = mem.guest_pfn;
	region->userspace_addr = mem.userspace_addr;

	partition->regions.count++;

	return 0;

err_unpin_pages:
	unpin_user_pages(pages, page_count - remaining);
	vfree(pages);

	return ret;
}

static long
mshv_partition_ioctl_unmap_memory(struct mshv_partition *partition,
				  struct mshv_user_mem_region __user *user_mem)
{
	struct mshv_user_mem_region mem;
	struct mshv_mem_region *region_ptr;
	int i;
	u64 page_count;
	long ret;

	if (!partition->regions.count)
		return -EINVAL;

	if (copy_from_user(&mem, user_mem, sizeof(mem)))
		return -EFAULT;

	/* Find matching region */
	for (i = 0; i < MSHV_MAX_MEM_REGIONS; ++i) {
		if (!partition->regions.slots[i].size)
			continue;
		region_ptr = &partition->regions.slots[i];
		if (region_ptr->userspace_addr == mem.userspace_addr &&
		    region_ptr->size == mem.size &&
		    region_ptr->guest_pfn == mem.guest_pfn)
			break;
	}

	if (i == MSHV_MAX_MEM_REGIONS)
		return -EINVAL;

	page_count = region_ptr->size >> HV_HYP_PAGE_SHIFT;
	ret = hv_call_unmap_gpa_pages(partition->id, region_ptr->guest_pfn,
				      page_count, 0);
	if (ret)
		return ret;

	unpin_user_pages(region_ptr->pages, page_count);
	vfree(region_ptr->pages);
	memset(region_ptr, 0, sizeof(*region_ptr));
	partition->regions.count--;

	return 0;
}

static long
mshv_partition_ioctl_install_intercept(struct mshv_partition *partition,
				       void __user *user_args)
{
	struct mshv_install_intercept args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return hv_call_install_intercept(
			partition->id,
			args.access_type_mask,
			args.intercept_type,
			args.intercept_parameter);
}

static long
mshv_partition_ioctl_assert_interrupt(struct mshv_partition *partition,
				      void __user *user_args)
{
	struct mshv_assert_interrupt args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return hv_call_assert_virtual_interrupt(
			partition->id,
			args.vector,
			args.dest_addr,
			args.control);
}

static long
mshv_partition_ioctl_ioeventfd(struct mshv_partition *partition,
		void __user *user_args)
{
	struct mshv_ioeventfd args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return mshv_ioeventfd(partition, &args);
}

static long
mshv_partition_ioctl_irqfd(struct mshv_partition *partition,
		void __user *user_args)
{
	struct mshv_irqfd args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return mshv_irqfd(partition, &args);
}
static long mshv_partition_ioctl_get_gpa_access_state(struct mshv_partition *partition,
		void __user *user_args)
{
	struct mshv_get_gpa_pages_access_state args;
	union hv_gpa_page_access_state *states;
	long ret;
	int written = 0;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;


	states = vzalloc(args.count * sizeof(*states));
	if (!states)
		return -ENOMEM;
	ret = hv_call_get_gpa_access_states(partition->id,
				args.count, args.hv_gpa_page_number,
				args.flags, &written, states);
	if (ret)
		goto free_return;

	args.count = written;
	if (copy_to_user(user_args, &args, sizeof(args))) {
		ret = -EFAULT;
		goto free_return;
	}
	if (copy_to_user(args.states, states, sizeof(*states) * args.count))
		ret = -EFAULT;

free_return:
	vfree(states);
	return ret;
}

static long
mshv_partition_ioctl_set_msi_routing(struct mshv_partition *partition,
		void __user *user_args)
{
	struct mshv_msi_routing_entry *entries = NULL;
	struct mshv_msi_routing args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	if (args.nr > MSHV_MAX_MSI_ROUTES)
		return -EINVAL;

	if (args.nr) {
		struct mshv_msi_routing __user *urouting = user_args;

		entries = vmemdup_user(urouting->entries,
				       array_size(sizeof(*entries),
					       args.nr));
		if (IS_ERR(entries))
			return PTR_ERR(entries);
	}
	ret = mshv_set_msi_routing(partition, entries, args.nr);
	kvfree(entries);

	return ret;
}

static long
mshv_partition_ioctl_signal_event_direct(struct mshv_partition *partition,
		void __user *user_args)
{
	struct mshv_signal_event_direct args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_signal_event_direct(args.vp,
					partition->id,
					args.vtl,
					args.sint,
					args.flag,
					&args.newly_signaled);

	if (ret) 
		return ret;
	
	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static long
mshv_partition_ioctl_post_message_direct(struct mshv_partition *partition,
		void __user *user_args)
{
	struct mshv_post_message_direct args;
	u8 message[HV_MESSAGE_SIZE];

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	if (args.length > HV_MESSAGE_SIZE) 
		return -E2BIG;

	memset(&message[0], 0, sizeof(message));
	if (copy_from_user(&message[0], args.message, args.length))
		return -EFAULT;

	return hv_call_post_message_direct(args.vp,
					partition->id,
					args.vtl,
					args.sint,
					&message[0]);
}

static long 
mshv_partition_ioctl_register_deliverabilty_notifications(
		struct mshv_partition *partition, void __user *user_args)
{
	struct mshv_register_deliverabilty_notifications args;
	struct hv_register_assoc hv_reg;
	
	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	memset(&hv_reg, 0, sizeof(hv_reg));
	hv_reg.name = HV_X64_REGISTER_DELIVERABILITY_NOTIFICATIONS;
	hv_reg.value.reg64 = args.flag;

	return hv_call_set_vp_registers(args.vp, partition->id, 1, &hv_reg);
}

static int mshv_device_ioctl_attr(struct mshv_device *dev,
				 int (*accessor)(struct mshv_device *dev,
						 struct mshv_device_attr *attr),
				 unsigned long arg)
{
	struct mshv_device_attr attr;

	if (!accessor)
		return -EPERM;

	if (copy_from_user(&attr, (void __user *)arg, sizeof(attr)))
		return -EFAULT;

	return accessor(dev, &attr);
}

static long mshv_device_ioctl(struct file *filp, unsigned int ioctl,
			      unsigned long arg)
{
	struct mshv_device *dev = filp->private_data;

	switch (ioctl) {
	case MSHV_SET_DEVICE_ATTR:
		return mshv_device_ioctl_attr(dev, dev->ops->set_attr, arg);
	case MSHV_GET_DEVICE_ATTR:
		return mshv_device_ioctl_attr(dev, dev->ops->get_attr, arg);
	case MSHV_HAS_DEVICE_ATTR:
		return mshv_device_ioctl_attr(dev, dev->ops->has_attr, arg);
	default:
		if (dev->ops->ioctl)
			return dev->ops->ioctl(dev, ioctl, arg);

		return -ENOTTY;
	}
}

static int mshv_device_release(struct inode *inode, struct file *filp)
{
	struct mshv_device *dev = filp->private_data;
	struct mshv_partition *partition = dev->partition;

	if (dev->ops->release) {
		mutex_lock(&partition->mutex);
		list_del(&dev->partition_node);
		dev->ops->release(dev);
		mutex_unlock(&partition->mutex);
	}

	mshv_partition_put(partition);
	return 0;
}

static const struct file_operations mshv_device_fops = {
	.unlocked_ioctl = mshv_device_ioctl,
	.release = mshv_device_release,
};

static const struct mshv_device_ops *mshv_device_ops_table[MSHV_DEV_TYPE_MAX];

int mshv_register_device_ops(const struct mshv_device_ops *ops, u32 type)
{
	if (type >= ARRAY_SIZE(mshv_device_ops_table))
		return -ENOSPC;

	if (mshv_device_ops_table[type] != NULL)
		return -EEXIST;

	mshv_device_ops_table[type] = ops;
	return 0;
}

void mshv_unregister_device_ops(u32 type)
{
	if (type >= ARRAY_SIZE(mshv_device_ops_table))
		return;
	mshv_device_ops_table[type] = NULL;
}

static long
mshv_partition_ioctl_create_device(struct mshv_partition *partition,
	void __user *user_args)
{
	long r;
	struct mshv_create_device tmp, *cd;
	struct mshv_device *dev;
	const struct mshv_device_ops *ops;
	int type;

	if (copy_from_user(&tmp, user_args, sizeof(tmp))) {
		r = -EFAULT;
		goto out;
	}

	cd = &tmp;

	if (cd->type >= ARRAY_SIZE(mshv_device_ops_table)) {
		r = -ENODEV;
		goto out;
	}

	type = array_index_nospec(cd->type, ARRAY_SIZE(mshv_device_ops_table));
	ops = mshv_device_ops_table[type];
	if (ops == NULL) {
		r = -ENODEV;
		goto out;
	}

	if (cd->flags & MSHV_CREATE_DEVICE_TEST) {
		r = 0;
		goto out;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL_ACCOUNT);
	if (!dev) {
		r = -ENOMEM;
		goto out;
	}

	dev->ops = ops;
	dev->partition = partition;

	r = ops->create(dev, type);
	if (r < 0) {
		kfree(dev);
		goto out;
	}

	list_add(&dev->partition_node, &partition->devices);

	if (ops->init)
		ops->init(dev);

	mshv_partition_get(partition);
	r = anon_inode_getfd(ops->name, &mshv_device_fops, dev, O_RDWR | O_CLOEXEC);
	if (r < 0) {
		mshv_partition_put_no_destroy(partition);
		list_del(&dev->partition_node);
		ops->destroy(dev);
		goto out;
	}

	cd->fd = r;
	r = 0;

	if (copy_to_user(user_args, &tmp, sizeof(tmp))) {
		r = -EFAULT;
		goto out;
	}
out:
	return r;
}

static void mshv_destroy_devices(struct mshv_partition *partition)
{
	struct mshv_device *dev, *tmp;

	/*
	 * No need to take any lock since at this point nobody else can
	 * reference this partition.
	 */
	list_for_each_entry_safe(dev, tmp, &partition->devices, partition_node) {
		list_del(&dev->partition_node);
		dev->ops->destroy(dev);
	}
}

static long
mshv_partition_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct mshv_partition *partition = filp->private_data;
	long ret;

	if (mutex_lock_killable(&partition->mutex))
		return -EINTR;

	switch (ioctl) {
	case MSHV_MAP_GUEST_MEMORY:
		ret = mshv_partition_ioctl_map_memory(partition,
							(void __user *)arg);
		break;
	case MSHV_UNMAP_GUEST_MEMORY:
		ret = mshv_partition_ioctl_unmap_memory(partition,
							(void __user *)arg);
		break;
	case MSHV_CREATE_VP:
		ret = mshv_partition_ioctl_create_vp(partition,
							(void __user *)arg);
		break;
	case MSHV_INSTALL_INTERCEPT:
		ret = mshv_partition_ioctl_install_intercept(partition,
							(void __user *)arg);
		break;
	case MSHV_ASSERT_INTERRUPT:
		ret = mshv_partition_ioctl_assert_interrupt(partition,
							(void __user *)arg);
		break;
	case MSHV_GET_PARTITION_PROPERTY:
		ret = mshv_partition_ioctl_get_property(partition,
							(void __user *)arg);
		break;
	case MSHV_SET_PARTITION_PROPERTY:
		ret = mshv_partition_ioctl_set_property(partition,
							(void __user *)arg);
		break;
	case MSHV_IRQFD:
		ret = mshv_partition_ioctl_irqfd(partition,
						 (void __user *)arg);
		break;
	case MSHV_IOEVENTFD:
		ret = mshv_partition_ioctl_ioeventfd(partition,
						 (void __user *)arg);
		break;
	case MSHV_SET_MSI_ROUTING:
		ret = mshv_partition_ioctl_set_msi_routing(partition,
							   (void __user *)arg);
		break;
	case MSHV_GET_GPA_ACCESS_STATES:
		ret = mshv_partition_ioctl_get_gpa_access_state(partition,
							   (void __user *)arg);
		break;
	case MSHV_CREATE_DEVICE:
		ret = mshv_partition_ioctl_create_device(partition,
							 (void __user *)arg);
		break;
	case MSHV_SIGNAL_EVENT_DIRECT:
		ret = mshv_partition_ioctl_signal_event_direct(partition,
							 (void __user *)arg);
		break;
	case MSHV_POST_MESSAGE_DIRECT:
		ret = mshv_partition_ioctl_post_message_direct(partition,
							 (void __user *)arg);
		break;
	case MSHV_REGISTER_DELIVERABILITY_NOTIFICATIONS:
		ret = mshv_partition_ioctl_register_deliverabilty_notifications(
			partition, (void __user *)arg);
		break;		
	default:
		ret = -ENOTTY;
	}

	mutex_unlock(&partition->mutex);
	return ret;
}

static void
destroy_partition(struct mshv_partition *partition)
{
	unsigned long flags, page_count;
	struct mshv_vp *vp;
	struct mshv_mem_region *region;
	int i;

	/* Remove from list of partitions */
	spin_lock_irqsave(&mshv.partitions.lock, flags);

	for (i = 0; i < MSHV_MAX_PARTITIONS; ++i) {
		if (mshv.partitions.array[i] == partition)
			break;
	}

	if (i == MSHV_MAX_PARTITIONS) {
		pr_err("%s: failed to locate partition in array\n", __func__);
	} else {
		mshv.partitions.count--;
		mshv.partitions.array[i] = NULL;
	}

	if (!mshv.partitions.count)
		hv_remove_mshv_irq();

	spin_unlock_irqrestore(&mshv.partitions.lock, flags);

	/*
	 * There are no remaining references to the partition,
	 * so the remaining cleanup can be lockless
	 */

	/* Deallocates and unmaps everything including vcpus, GPA mappings etc */
	hv_call_finalize_partition(partition->id);
	/* Withdraw and free all pages we deposited */
	hv_call_withdraw_memory(U64_MAX, NUMA_NO_NODE, partition->id);
	hv_call_delete_partition(partition->id);

	/* Remove vps */
	for (i = 0; i < MSHV_MAX_VPS; ++i) {
		vp = partition->vps.array[i];
		if (!vp)
			continue;
		kfree(vp->registers);
		free_page((unsigned long)vp->run.intercept_message);
		kfree(vp);
	}

	/* Remove regions and unpin the pages */
	for (i = 0; i < MSHV_MAX_MEM_REGIONS; ++i) {
		region = &partition->regions.slots[i];
		if (!region->size)
			continue;
		page_count = region->size >> HV_HYP_PAGE_SHIFT;
		unpin_user_pages(region->pages, page_count);
		vfree(region->pages);
	}

	mshv_destroy_devices(partition);
	mshv_free_msi_routing(partition);
	kfree(partition);
}

static struct
mshv_partition *mshv_partition_get(struct mshv_partition *partition)
{
	if (refcount_inc_not_zero(&partition->ref_count))
		return partition;
	return NULL;
}

static void
mshv_partition_put(struct mshv_partition *partition)
{
	if (refcount_dec_and_test(&partition->ref_count))
		destroy_partition(partition);
}

static void
mshv_partition_put_no_destroy(struct mshv_partition *partition)
{
	WARN_ON(refcount_dec_and_test(&partition->ref_count));
}

static int
mshv_partition_release(struct inode *inode, struct file *filp)
{
	struct mshv_partition *partition = filp->private_data;

	mshv_eventfd_release(partition);

	cleanup_srcu_struct(&partition->irq_srcu);

	mshv_partition_put(partition);

	return 0;
}

static int
add_partition(struct mshv_partition *partition)
{
	unsigned long flags;
	int i, ret = 0;

	spin_lock_irqsave(&mshv.partitions.lock, flags);

	if (mshv.partitions.count >= MSHV_MAX_PARTITIONS) {
		pr_err("%s: too many partitions\n", __func__);
		ret = -ENOSPC;
		goto out_unlock;
	}

	for (i = 0; i < MSHV_MAX_PARTITIONS; ++i) {
		if (!mshv.partitions.array[i])
			break;
	}

	mshv.partitions.count++;
	mshv.partitions.array[i] = partition;

	if (mshv.partitions.count == 1)
		hv_setup_mshv_irq(mshv_isr);

out_unlock:
	spin_unlock_irqrestore(&mshv.partitions.lock, flags);

	return ret;
}

static long
mshv_ioctl_create_partition(void __user *user_arg)
{
	struct mshv_create_partition args;
	struct mshv_partition *partition;
	struct file *file;
	int fd;
	long ret;

	if (copy_from_user(&args, user_arg, sizeof(args)))
		return -EFAULT;

	/* Only support EXO partitions */
	args.flags |= HV_PARTITION_CREATION_FLAG_EXO_PARTITION;

	partition = kzalloc(sizeof(*partition), GFP_KERNEL);
	if (!partition)
		return -ENOMEM;

	mutex_init(&partition->mutex);

	spin_lock_init(&partition->irq_lock);

	INIT_HLIST_HEAD(&partition->irq_ack_notifier_list);

	INIT_LIST_HEAD(&partition->devices);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto free_partition;
	}

	ret = hv_call_create_partition(args.flags,
				       args.partition_creation_properties,
				       &partition->id);
	if (ret)
		goto put_fd;

	ret = hv_call_set_partition_property(
				partition->id,
				HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
				args.synthetic_processor_features.as_uint64[0]);
	if (ret)
		goto delete_partition;

	ret = hv_call_initialize_partition(partition->id);
	if (ret)
		goto delete_partition;

	file = anon_inode_getfile("mshv_partition", &mshv_partition_fops,
				  partition, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto finalize_partition;
	}
	refcount_set(&partition->ref_count, 1);

	ret = add_partition(partition);
	if (ret)
		goto release_file;

	fd_install(fd, file);

	ret = init_srcu_struct(&partition->irq_srcu);
	if (ret)
		goto cleanup_irq_srcu;

	mshv_eventfd_init(partition);

	return fd;

cleanup_irq_srcu:
	cleanup_srcu_struct(&partition->irq_srcu);
release_file:
	file->f_op->release(file->f_inode, file);
finalize_partition:
	hv_call_finalize_partition(partition->id);
delete_partition:
	hv_call_delete_partition(partition->id);
put_fd:
	put_unused_fd(fd);
free_partition:
	kfree(partition);
	return ret;
}

static long
mshv_ioctl_check_extension(void __user *user_arg)
{
	u32 arg;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	switch (arg) {
	case MSHV_CAP_CORE_API_STABLE:
		return 0;
	}

	return -EOPNOTSUPP;
}

static long
mshv_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	switch (ioctl) {
	case MSHV_CHECK_EXTENSION:
		return mshv_ioctl_check_extension((void __user *)arg);
	case MSHV_CREATE_PARTITION:
		return mshv_ioctl_create_partition((void __user *)arg);
	}

	return -ENOTTY;
}

static int
mshv_dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int
mshv_dev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int mshv_cpuhp_online;

static int
__init mshv_init(void)
{
	int ret;

	if (!hv_is_hyperv_initialized())
		return -ENODEV;

	if (!hv_root_partition)
		return -ENODEV;

	ret = misc_register(&mshv_dev);
	if (ret) {
		pr_err("%s: misc device register failed\n", __func__);
		return ret;
	}

	mshv.synic_pages = alloc_percpu(struct hv_synic_pages);
	if (!mshv.synic_pages) {
		pr_err("%s: failed to allocate percpu synic page\n", __func__);
		misc_deregister(&mshv_dev);
		return -ENOMEM;
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mshv_synic",
				mshv_synic_init,
				mshv_synic_cleanup);
	if (ret < 0) {
		pr_err("%s: failed to setup cpu hotplug state: %i\n",
		       __func__, ret);
		return ret;
	}

	mshv_cpuhp_online = ret;
	spin_lock_init(&mshv.partitions.lock);

	if (mshv_irqfd_wq_init())
		mshv_irqfd_wq_cleanup();

	mshv_vfio_ops_init();

	return 0;
}

static void
__exit mshv_exit(void)
{
	mshv_irqfd_wq_cleanup();

	cpuhp_remove_state(mshv_cpuhp_online);
	free_percpu(mshv.synic_pages);

	hv_port_table_fini();

	mshv_vfio_ops_exit();

	misc_deregister(&mshv_dev);
}

module_init(mshv_init);
module_exit(mshv_exit);
