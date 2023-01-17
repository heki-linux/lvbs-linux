// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Common ioctl functionality shared by mshv_root and mshv_vtl.
 * Provided by the core mshv module.
 */

#include <linux/kernel.h>

#include "mshv_eventfd.h"
#include "mshv.h"
#include "vfio.h"

long
mshv_ioctl_translate_gva(u32 vp_index, u64 partition_id, void __user *user_args)
{
	long ret;
	struct mshv_translate_gva args;
	u64 gpa;
	union hv_translate_gva_result result;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_translate_virtual_address(
			vp_index,
			partition_id,
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
EXPORT_SYMBOL_GPL(mshv_ioctl_translate_gva);

long
mshv_ioctl_assert_interrupt(u64 partition_id, void __user *user_args)
{
	struct mshv_assert_interrupt args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return hv_call_assert_virtual_interrupt(
			partition_id,
			args.vector,
			args.dest_addr,
			args.control);
}
EXPORT_SYMBOL_GPL(mshv_ioctl_assert_interrupt);

long
mshv_ioctl_signal_event_direct(u64 partition_id, void __user *user_args)
{
	struct mshv_signal_event_direct args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_signal_event_direct(args.vp,
					partition_id,
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
EXPORT_SYMBOL_GPL(mshv_ioctl_signal_event_direct);

long
mshv_ioctl_post_message_direct(u64 partition_id, void __user *user_args)
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
					partition_id,
					args.vtl,
					args.sint,
					&message[0]);
}
EXPORT_SYMBOL_GPL(mshv_ioctl_post_message_direct);
