// SPDX-License-Identifier: GPL-2.0-only
/*
 * eventfd support for mshv
 *
 * Heavily inspired from KVM implementation of irqfd/ioeventfd. The basic
 * framework code is taken from the kvm implementation.
 *
 * All credits to kvm developers.
 */

#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/eventfd.h>
#include <linux/mshv.h>
#include <linux/mshv_eventfd.h>

#include "mshv.h"

static struct workqueue_struct *irqfd_cleanup_wq;

void
mshv_register_irq_ack_notifier(struct mshv_partition *partition,
			       struct mshv_irq_ack_notifier *mian)
{
	spin_lock(&partition->irq_lock);
	hlist_add_head_rcu(&mian->link, &partition->irq_ack_notifier_list);
	spin_unlock(&partition->irq_lock);
}

void
mshv_unregister_irq_ack_notifier(struct mshv_partition *partition,
				 struct mshv_irq_ack_notifier *mian)
{
	spin_lock(&partition->irq_lock);
	hlist_del_init_rcu(&mian->link);
	spin_unlock(&partition->irq_lock);
	synchronize_rcu();
}

bool
mshv_notify_acked_gsi(struct mshv_partition *partition, int gsi)
{
	struct mshv_irq_ack_notifier *mian;
	bool acked = false;

	rcu_read_lock();
	hlist_for_each_entry_rcu(mian, &partition->irq_ack_notifier_list,
			link) {
		if (mian->gsi == gsi) {
			mian->irq_acked(mian);
			acked = true;
		}
	}
	rcu_read_unlock();

	return acked;
}

static void
irqfd_inject(struct mshv_kernel_irqfd *irqfd)
{
	struct mshv_lapic_irq *irq = &irqfd->lapic_irq;

	hv_call_assert_virtual_interrupt(irqfd->partition->id,
					 irq->vector, irq->apic_id,
					 irq->control);
}

static void
irqfd_shutdown(struct work_struct *work)
{
	struct mshv_kernel_irqfd *irqfd =
		container_of(work, struct mshv_kernel_irqfd, shutdown);

	/*
	 * Synchronize with the wait-queue and unhook ourselves to prevent
	 * further events.
	 */
	remove_wait_queue(irqfd->wqh, &irqfd->wait);

	/*
	 * It is now safe to release the object's resources
	 */
	eventfd_ctx_put(irqfd->eventfd);
	kfree(irqfd);
}

/* assumes partition->irqfds.lock is held */
static bool
irqfd_is_active(struct mshv_kernel_irqfd *irqfd)
{
	return list_empty(&irqfd->list) ? false : true;
}

/*
 * Mark the irqfd as inactive and schedule it for removal
 *
 * assumes partition->irqfds.lock is held
 */
static void
irqfd_deactivate(struct mshv_kernel_irqfd *irqfd)
{
	BUG_ON(!irqfd_is_active(irqfd));

	list_del_init(&irqfd->list);

	queue_work(irqfd_cleanup_wq, &irqfd->shutdown);
}

/*
 * Called with wqh->lock held and interrupts disabled
 */
static int
irqfd_wakeup(wait_queue_entry_t *wait, unsigned int mode,
		int sync, void *key)
{
	struct mshv_kernel_irqfd *irqfd =
		container_of(wait, struct mshv_kernel_irqfd, wait);
	unsigned long flags = (unsigned long)key;

	if (flags & POLLIN)
		/* An event has been signaled, inject an interrupt */
		irqfd_inject(irqfd);

	if (flags & POLLHUP) {
		/* The eventfd is closing, detach from Partition */
		struct mshv_partition *partition = irqfd->partition;
		unsigned long flags;

		spin_lock_irqsave(&partition->irqfds.lock, flags);

		/*
		 * We must check if someone deactivated the irqfd before
		 * we could acquire the irqfds.lock since the item is
		 * deactivated from the mshv side before it is unhooked from
		 * the wait-queue.  If it is already deactivated, we can
		 * simply return knowing the other side will cleanup for us.
		 * We cannot race against the irqfd going away since the
		 * other side is required to acquire wqh->lock, which we hold
		 */
		if (irqfd_is_active(irqfd))
			irqfd_deactivate(irqfd);

		spin_unlock_irqrestore(&partition->irqfds.lock, flags);
	}

	return 0;
}

static void
irqfd_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh,
			poll_table *pt)
{
	struct mshv_kernel_irqfd *irqfd =
		container_of(pt, struct mshv_kernel_irqfd, pt);

	irqfd->wqh = wqh;
	add_wait_queue(wqh, &irqfd->wait);
}

static int
mshv_irqfd_assign(struct mshv_partition *partition,
		  struct mshv_irqfd *args)
{
	struct mshv_kernel_irqfd *irqfd, *tmp;
	struct fd f;
	struct eventfd_ctx *eventfd = NULL;
	int ret;
	unsigned int events;

	irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL);
	if (!irqfd)
		return -ENOMEM;

	irqfd->partition = partition;
	irqfd->gsi = args->gsi;
	irqfd->lapic_irq.vector = args->vector;
	irqfd->lapic_irq.apic_id = args->apic_id;
	irqfd->lapic_irq.control.interrupt_type = args->interrupt_type;
	irqfd->lapic_irq.control.level_triggered = args->level_triggered;
	irqfd->lapic_irq.control.logical_dest_mode = args->logical_dest_mode;
	INIT_LIST_HEAD(&irqfd->list);
	INIT_WORK(&irqfd->shutdown, irqfd_shutdown);

	f = fdget(args->fd);
	if (!f.file) {
		ret = -EBADF;
		goto out;
	}

	eventfd = eventfd_ctx_fileget(f.file);
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		goto fail;
	}

	irqfd->eventfd = eventfd;

	/*
	 * Install our own custom wake-up handling so we are notified via
	 * a callback whenever someone signals the underlying eventfd
	 */
	init_waitqueue_func_entry(&irqfd->wait, irqfd_wakeup);
	init_poll_funcptr(&irqfd->pt, irqfd_ptable_queue_proc);

	spin_lock_irq(&partition->irqfds.lock);
	ret = 0;
	list_for_each_entry(tmp, &partition->irqfds.items, list) {
		if (irqfd->eventfd != tmp->eventfd)
			continue;
		/* This fd is used for another irq already. */
		ret = -EBUSY;
		spin_unlock_irq(&partition->irqfds.lock);
		goto fail;
	}
	list_add_tail(&irqfd->list, &partition->irqfds.items);
	spin_unlock_irq(&partition->irqfds.lock);

	/*
	 * Check if there was an event already pending on the eventfd
	 * before we registered, and trigger it as if we didn't miss it.
	 */
	events = vfs_poll(f.file, &irqfd->pt);

	if (events & POLLIN)
		irqfd_inject(irqfd);

	/*
	 * do not drop the file until the irqfd is fully initialized, otherwise
	 * we might race against the POLLHUP
	 */
	fdput(f);

	return 0;

fail:
	if (eventfd && !IS_ERR(eventfd))
		eventfd_ctx_put(eventfd);

	fdput(f);

out:
	kfree(irqfd);
	return ret;
}

/*
 * shutdown any irqfd's that match fd+gsi
 */
static int
mshv_irqfd_deassign(struct mshv_partition *partition,
		    struct mshv_irqfd *args)
{
	struct mshv_kernel_irqfd *irqfd, *tmp;
	struct eventfd_ctx *eventfd;

	eventfd = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	spin_lock_irq(&partition->irqfds.lock);

	list_for_each_entry_safe(irqfd, tmp, &partition->irqfds.items, list) {
		if (irqfd->eventfd == eventfd && irqfd->gsi == args->gsi)
			irqfd_deactivate(irqfd);
	}

	spin_unlock_irq(&partition->irqfds.lock);
	eventfd_ctx_put(eventfd);

	/*
	 * Block until we know all outstanding shutdown jobs have completed
	 * so that we guarantee there will not be any more interrupts on this
	 * gsi once this deassign function returns.
	 */
	flush_workqueue(irqfd_cleanup_wq);

	return 0;
}

int
mshv_irqfd(struct mshv_partition *partition, struct mshv_irqfd *args)
{
	if (args->flags & MSHV_IRQFD_FLAG_DEASSIGN)
		return mshv_irqfd_deassign(partition, args);

	return mshv_irqfd_assign(partition, args);
}

/*
 * This function is called as the mshv VM fd is being released.
 * Shutdown all irqfds that still remain open
 */
static void
mshv_irqfd_release(struct mshv_partition *partition)
{
	struct mshv_kernel_irqfd *irqfd, *tmp;

	spin_lock_irq(&partition->irqfds.lock);

	list_for_each_entry_safe(irqfd, tmp, &partition->irqfds.items, list)
		irqfd_deactivate(irqfd);

	spin_unlock_irq(&partition->irqfds.lock);

	/*
	 * Block until we know all outstanding shutdown jobs have completed
	 * since we do not take a mshv_partition* reference.
	 */
	flush_workqueue(irqfd_cleanup_wq);

}

int mshv_irqfd_wq_init(void)
{
	irqfd_cleanup_wq = alloc_workqueue("mshv-irqfd-cleanup", 0, 0);
	if (!irqfd_cleanup_wq)
		return -ENOMEM;

	return 0;
}

void mshv_irqfd_wq_cleanup(void)
{
	destroy_workqueue(irqfd_cleanup_wq);
}

/*
 * --------------------------------------------------------------------
 * ioeventfd: translate a MMIO memory write to an eventfd signal.
 *
 * userspace can register a MMIO address with an eventfd for receiving
 * notification when the memory has been touched.
 *
 * TODO: Implement eventfd for PIO as well.
 * --------------------------------------------------------------------
 */

static void
ioeventfd_release(struct kernel_mshv_ioeventfd *p, u64 partition_id)
{
	if (p->doorbell_id > 0)
		hv_unregister_doorbell(partition_id, p->doorbell_id);
	eventfd_ctx_put(p->eventfd);
	list_del(&p->list);
	kfree(p);
}

/* MMIO writes trigger an event if the addr/val match */
static void
ioeventfd_mmio_write(int doorbell_id, void *data)
{
	struct mshv_partition *partition = (struct mshv_partition *)data;
	struct kernel_mshv_ioeventfd *p;
	unsigned long flags;

	spin_lock_irqsave(&partition->ioeventfds.lock, flags);
	list_for_each_entry(p, &partition->ioeventfds.items, list) {
		if (p->doorbell_id == doorbell_id) {
			eventfd_signal(p->eventfd, 1);
			break;
		}
	}
	spin_unlock_irqrestore(&partition->ioeventfds.lock, flags);
}

static bool
ioeventfd_check_collision(struct mshv_partition *partition,
			  struct kernel_mshv_ioeventfd *p)
{
	struct kernel_mshv_ioeventfd *_p;

	list_for_each_entry(_p, &partition->ioeventfds.items, list)
		if (_p->addr == p->addr && _p->length == p->length &&
		    (_p->wildcard || p->wildcard ||
		     _p->datamatch == p->datamatch))
			return true;

	return false;
}

static int
mshv_assign_ioeventfd(struct mshv_partition *partition,
		      struct mshv_ioeventfd *args)
{
	struct kernel_mshv_ioeventfd *p;
	struct eventfd_ctx *eventfd;
	u64 doorbell_flags = 0;
	unsigned long irqflags;
	int ret;

	if (args->flags & MSHV_IOEVENTFD_FLAG_PIO)
		return -EOPNOTSUPP;

	/* must be natural-word sized */
	switch (args->len) {
	case 0:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_ANY;
		break;
	case 1:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_BYTE;
		break;
	case 2:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_WORD;
		break;
	case 4:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_DWORD;
		break;
	case 8:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_QWORD;
		break;
	default:
		pr_warn("ioeventfd: invalid length specified\n");
		return -EINVAL;
	}

	/* check for range overflow */
	if (args->addr + args->len < args->addr)
		return -EINVAL;

	/* check for extra flags that we don't understand */
	if (args->flags & ~MSHV_IOEVENTFD_VALID_FLAG_MASK)
		return -EINVAL;

	eventfd = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto fail;
	}

	INIT_LIST_HEAD(&p->list);
	p->addr    = args->addr;
	p->length  = args->len;
	p->eventfd = eventfd;

	/* The datamatch feature is optional, otherwise this is a wildcard */
	if (args->flags & MSHV_IOEVENTFD_FLAG_DATAMATCH)
		p->datamatch = args->datamatch;
	else {
		p->wildcard = true;
		doorbell_flags |= HV_DOORBELL_FLAG_TRIGGER_ANY_VALUE;
	}

	spin_lock_irqsave(&partition->ioeventfds.lock, irqflags);

	if (ioeventfd_check_collision(partition, p)) {
		ret = -EEXIST;
		goto unlock_fail;
	}

	ret = hv_register_doorbell(partition->id, ioeventfd_mmio_write,
				   (void *)partition, p->addr,
				   p->datamatch, doorbell_flags);
	if (ret < 0) {
		pr_err("Failed to register ioeventfd doorbell!\n");
		goto unlock_fail;
	}

	p->doorbell_id = ret;
	list_add_tail(&p->list, &partition->ioeventfds.items);

	spin_unlock_irqrestore(&partition->ioeventfds.lock, irqflags);

	return 0;

unlock_fail:
	spin_unlock_irqrestore(&partition->ioeventfds.lock, irqflags);

	kfree(p);

fail:
	eventfd_ctx_put(eventfd);

	return ret;
}

static int
mshv_deassign_ioeventfd(struct mshv_partition *partition,
			struct mshv_ioeventfd *args)
{
	struct kernel_mshv_ioeventfd *p, *tmp;
	struct eventfd_ctx *eventfd;
	unsigned long flags;
	int ret = -ENOENT;

	eventfd = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	spin_lock_irqsave(&partition->ioeventfds.lock, flags);

	list_for_each_entry_safe(p, tmp, &partition->ioeventfds.items, list) {
		bool wildcard = !(args->flags & MSHV_IOEVENTFD_FLAG_DATAMATCH);

		if (p->eventfd != eventfd  ||
		    p->addr != args->addr  ||
		    p->length != args->len ||
		    p->wildcard != wildcard)
			continue;

		if (!p->wildcard && p->datamatch != args->datamatch)
			continue;

		ioeventfd_release(p, partition->id);
		ret = 0;
		break;
	}

	spin_unlock_irqrestore(&partition->ioeventfds.lock, flags);

	eventfd_ctx_put(eventfd);

	return ret;
}

int
mshv_ioeventfd(struct mshv_partition *partition,
	       struct mshv_ioeventfd *args)
{
	/* PIO not yet implemented */
	if (args->flags & MSHV_IOEVENTFD_FLAG_PIO)
		return -EOPNOTSUPP;

	if (args->flags & MSHV_IOEVENTFD_FLAG_DEASSIGN)
		return mshv_deassign_ioeventfd(partition, args);

	return mshv_assign_ioeventfd(partition, args);
}

void
mshv_eventfd_init(struct mshv_partition *partition)
{
	spin_lock_init(&partition->irqfds.lock);
	INIT_LIST_HEAD(&partition->irqfds.items);

	spin_lock_init(&partition->ioeventfds.lock);
	INIT_LIST_HEAD(&partition->ioeventfds.items);
}

void
mshv_eventfd_release(struct mshv_partition *partition)
{
	struct kernel_mshv_ioeventfd *p, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&partition->ioeventfds.lock, flags);
	list_for_each_entry_safe(p, tmp, &partition->ioeventfds.items, list) {
		ioeventfd_release(p, partition->id);
	}
	spin_unlock_irqrestore(&partition->ioeventfds.lock, flags);

	mshv_irqfd_release(partition);
}
