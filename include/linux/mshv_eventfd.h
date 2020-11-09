/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *
 * irqfd: Allows an fd to be used to inject an interrupt to the guest
 * All credit goes to kvm developers.
 */

#ifndef __LINUX_MSHV_EVENTFD_H
#define __LINUX_MSHV_EVENTFD_H

#include <linux/mshv.h>
#include <linux/poll.h>

struct mshv_kernel_irqfd {
	struct mshv_partition     *partition;
	struct eventfd_ctx        *eventfd;
	u32                        gsi;
	struct mshv_lapic_irq      lapic_irq;
	struct list_head           list;
	poll_table                 pt;
	wait_queue_head_t         *wqh;
	wait_queue_entry_t         wait;
	struct work_struct         shutdown;
};

int mshv_irqfd(struct mshv_partition *partition,
		struct mshv_irqfd *args);

void mshv_irqfd_init(struct mshv_partition *partition);
void mshv_irqfd_release(struct mshv_partition *partition);

int mshv_irqfd_wq_init(void);
void mshv_irqfd_wq_cleanup(void);

#endif /* __LINUX_MSHV_EVENTFD_H */
