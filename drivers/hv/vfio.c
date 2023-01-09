// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO-MSHV bridge pseudo device
 *
 * Heavily inspired by the VFIO-KVM bridge pseudo device.
 * Copyright (C) 2013 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 */

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>

#include "mshv.h"
#include "mshv_root.h"
#include "vfio.h"


struct mshv_vfio_group {
	struct list_head node;
	struct vfio_group *vfio_group;
};

struct mshv_vfio {
	struct list_head group_list;
	struct mutex lock;
};

static struct vfio_group *mshv_vfio_group_get_external_user(struct file *filep)
{
	struct vfio_group *vfio_group;
	struct vfio_group *(*fn)(struct file *);

	fn = symbol_get(vfio_group_get_external_user);
	if (!fn)
		return ERR_PTR(-EINVAL);

	vfio_group = fn(filep);

	symbol_put(vfio_group_get_external_user);

	return vfio_group;
}

static bool mshv_vfio_external_group_match_file(struct vfio_group *group,
						struct file *filep)
{
	bool ret, (*fn)(struct vfio_group *, struct file *);

	fn = symbol_get(vfio_external_group_match_file);
	if (!fn)
		return false;

	ret = fn(group, filep);

	symbol_put(vfio_external_group_match_file);

	return ret;
}

static void mshv_vfio_group_put_external_user(struct vfio_group *vfio_group)
{
	void (*fn)(struct vfio_group *);

	fn = symbol_get(vfio_group_put_external_user);
	if (!fn)
		return;

	fn(vfio_group);

	symbol_put(vfio_group_put_external_user);
}

static int mshv_vfio_set_group(struct mshv_device *dev, long attr, u64 arg)
{
	struct mshv_vfio *mv = dev->private;
	struct vfio_group *vfio_group;
	struct mshv_vfio_group *mvg;
	int32_t __user *argp = (int32_t __user *)(unsigned long)arg;
	struct fd f;
	int32_t fd;
	int ret;

	switch (attr) {
	case MSHV_DEV_VFIO_GROUP_ADD:
		if (get_user(fd, argp))
			return -EFAULT;

		f = fdget(fd);
		if (!f.file)
			return -EBADF;

		vfio_group = mshv_vfio_group_get_external_user(f.file);
		fdput(f);

		if (IS_ERR(vfio_group))
			return PTR_ERR(vfio_group);

		mutex_lock(&mv->lock);

		list_for_each_entry(mvg, &mv->group_list, node) {
			if (mvg->vfio_group == vfio_group) {
				mutex_unlock(&mv->lock);
				mshv_vfio_group_put_external_user(vfio_group);
				return -EEXIST;
			}
		}

		mvg = kzalloc(sizeof(*mvg), GFP_KERNEL_ACCOUNT);
		if (!mvg) {
			mutex_unlock(&mv->lock);
			mshv_vfio_group_put_external_user(vfio_group);
			return -ENOMEM;
		}

		list_add_tail(&mvg->node, &mv->group_list);
		mvg->vfio_group = vfio_group;

		mutex_unlock(&mv->lock);

		return 0;

	case MSHV_DEV_VFIO_GROUP_DEL:
		if (get_user(fd, argp))
			return -EFAULT;

		f = fdget(fd);
		if (!f.file)
			return -EBADF;

		ret = -ENOENT;

		mutex_lock(&mv->lock);

		list_for_each_entry(mvg, &mv->group_list, node) {
			if (!mshv_vfio_external_group_match_file(mvg->vfio_group,
								 f.file))
				continue;

			list_del(&mvg->node);
			mshv_vfio_group_put_external_user(mvg->vfio_group);
			kfree(mvg);
			ret = 0;
			break;
		}

		mutex_unlock(&mv->lock);

		fdput(f);

		return ret;
	}

	return -ENXIO;
}

static int mshv_vfio_set_attr(struct mshv_device *dev,
			      struct mshv_device_attr *attr)
{
	switch (attr->group) {
	case MSHV_DEV_VFIO_GROUP:
		return mshv_vfio_set_group(dev, attr->attr, attr->addr);
	}

	return -ENXIO;
}

static int mshv_vfio_has_attr(struct mshv_device *dev,
			      struct mshv_device_attr *attr)
{
	switch (attr->group) {
	case MSHV_DEV_VFIO_GROUP:
		switch (attr->attr) {
		case MSHV_DEV_VFIO_GROUP_ADD:
		case MSHV_DEV_VFIO_GROUP_DEL:
			return 0;
		}

		break;
	}

	return -ENXIO;
}

static void mshv_vfio_destroy(struct mshv_device *dev)
{
	struct mshv_vfio *mv = dev->private;
	struct mshv_vfio_group *mvg, *tmp;

	list_for_each_entry_safe(mvg, tmp, &mv->group_list, node) {
		mshv_vfio_group_put_external_user(mvg->vfio_group);
		list_del(&mvg->node);
		kfree(mvg);
	}

	kfree(mv);
	kfree(dev);
}

static int mshv_vfio_create(struct mshv_device *dev, u32 type);

static struct mshv_device_ops mshv_vfio_ops = {
	.name = "mshv-vfio",
	.create = mshv_vfio_create,
	.destroy = mshv_vfio_destroy,
	.set_attr = mshv_vfio_set_attr,
	.has_attr = mshv_vfio_has_attr,
};

static int mshv_vfio_create(struct mshv_device *dev, u32 type)
{
	struct mshv_device *tmp;
	struct mshv_vfio *mv;

	/* Only one VFIO "device" per VM */
	hlist_for_each_entry(tmp, &dev->partition->devices, partition_node)
		if (tmp->ops == &mshv_vfio_ops)
			return -EBUSY;

	mv = kzalloc(sizeof(*mv), GFP_KERNEL_ACCOUNT);
	if (!mv)
		return -ENOMEM;

	INIT_LIST_HEAD(&mv->group_list);
	mutex_init(&mv->lock);

	dev->private = mv;

	return 0;
}

int mshv_vfio_ops_init(void)
{
	return mshv_register_device_ops(&mshv_vfio_ops, MSHV_DEV_TYPE_VFIO);
}

void mshv_vfio_ops_exit(void)
{
	mshv_unregister_device_ops(MSHV_DEV_TYPE_VFIO);
}
