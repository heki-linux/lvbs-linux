/*
 * This file contains code that handles pending work before transferring
 * to guest context. It needs to be in a separate file because the symbols
 * it uses are not exported.
 *
 * Inspired by native and KVM switching code.
 *
 * Author: Wei Liu <wei.liu@kernel.org>
 */

#include <linux/tracehook.h>

/* Invoke with preemption and interrupt enabled */
int xfer_to_guest_mode_handle_work(unsigned long ti_work)
{
	if (ti_work & _TIF_NOTIFY_SIGNAL)
		tracehook_notify_signal();

	if (ti_work & _TIF_SIGPENDING)
		return -EINTR;

	if (ti_work & _TIF_NEED_RESCHED)
		schedule();

	if (ti_work & _TIF_NOTIFY_RESUME)
		tracehook_notify_resume(NULL);

	return 0;
}
EXPORT_SYMBOL_GPL(xfer_to_guest_mode_handle_work);
