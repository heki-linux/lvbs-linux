// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * The /dev/mshv device.
 * This is the core module mshv_root and mshv_vtl depend on.
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
#include <linux/hyperv.h>
#include <linux/nospec.h>
#include <asm/mshyperv.h>

#include "mshv_eventfd.h"
#include "mshv.h"
#include "vfio.h"

MODULE_AUTHOR("Microsoft");
MODULE_LICENSE("GPL");

static long mshv_ioctl_dummy(void __user *user_arg)
{
	return -ENOTTY;
}

static long mshv_ioctl_dummy2(u32 arg)
{
	return -ENOTTY;
}

static mshv_create_func_t mshv_ioctl_create_vtl = mshv_ioctl_dummy;
static mshv_create_func_t mshv_ioctl_create_partition = mshv_ioctl_dummy;
static mshv_check_ext_func_t mshv_vtl_ioctl_check_extension = mshv_ioctl_dummy2;

void mshv_setup_vtl_func(const mshv_create_func_t create_vtl,
			 const mshv_check_ext_func_t check_ext)
{
	if (!create_vtl) {
		mshv_ioctl_create_vtl = mshv_ioctl_dummy;
		mshv_vtl_ioctl_check_extension = mshv_ioctl_dummy2;
	} else {
		mshv_ioctl_create_vtl = create_vtl;
		mshv_vtl_ioctl_check_extension = check_ext;
	}
}
EXPORT_SYMBOL_GPL(mshv_setup_vtl_func);

void mshv_set_create_partition_func(const mshv_create_func_t func)
{
	if (!func) {
		mshv_ioctl_create_partition = mshv_ioctl_dummy;
	} else {
		mshv_ioctl_create_partition = func;
	}
}
EXPORT_SYMBOL_GPL(mshv_set_create_partition_func);

static int mshv_dev_open(struct inode *inode, struct file *filp);
static int mshv_dev_release(struct inode *inode, struct file *filp);
static long mshv_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);

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
mshv_ioctl_check_extension(void __user *user_arg)
{
	u32 arg;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	switch (arg) {
	case MSHV_CAP_CORE_API_STABLE:
		return 0;
#ifdef CONFIG_HYPERV_VTL
	case MSHV_CAP_REGISTER_PAGE:
	case MSHV_CAP_VTL_RETURN_ACTION:
	case MSHV_CAP_DR6_SHARED:
		return mshv_vtl_ioctl_check_extension(arg);
#endif
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
	case MSHV_CREATE_VTL:
		return mshv_ioctl_create_vtl((void __user *)arg);
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

static int
__init mshv_init(void)
{
	int ret;

	if (!hv_is_hyperv_initialized())
		return -ENODEV;

	ret = misc_register(&mshv_dev);
	if (ret) {
		pr_err("%s: misc device register failed\n", __func__);
		return ret;
	}

	return ret;
}

static void
__exit mshv_exit(void)
{
	misc_deregister(&mshv_dev);
}

module_init(mshv_init);
module_exit(mshv_exit);
