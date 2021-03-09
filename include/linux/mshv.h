/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_MSHV_H
#define _LINUX_MSHV_H

/*
 * Microsoft Hypervisor root partition driver for /dev/mshv
 */

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/srcu.h>
#include <uapi/linux/mshv.h>

#define MSHV_MAX_PARTITIONS		128
#define MSHV_MAX_MEM_REGIONS		64
#define MSHV_MAX_VPS			256

struct mshv_vp {
	u32 index;
	struct mshv_partition *partition;
	struct mutex mutex;
	struct page *register_page;
	struct {
		struct semaphore sem;
		struct task_struct *task;
		struct hv_message *intercept_message;
	} run;
};

struct mshv_mem_region {
	u64 size; /* bytes */
	u64 guest_pfn;
	u64 userspace_addr; /* start of the userspace allocated memory */
	struct page **pages;
};

struct mshv_irq_ack_notifier {
	struct hlist_node link;
	unsigned int gsi;
	void (*irq_acked)(struct mshv_irq_ack_notifier *mian);
};

struct mshv_partition {
	u64 id;
	refcount_t ref_count;
	struct mutex mutex;
	struct {
		u32 count;
		struct mshv_mem_region slots[MSHV_MAX_MEM_REGIONS];
	} regions;
	struct {
		u32 count;
		struct mshv_vp *array[MSHV_MAX_VPS];
	} vps;

	spinlock_t irq_lock;
	struct srcu_struct irq_srcu;
	struct hlist_head irq_ack_notifier_list;

	struct {
		spinlock_t        lock;
		struct list_head  items;
		struct mutex resampler_lock;
		struct list_head  resampler_list;
	} irqfds;
	struct {
		spinlock_t        lock;
		struct list_head items;
	} ioeventfds;
	struct mshv_msi_routing_table __rcu *msi_routing;
};

struct mshv_lapic_irq {
	u32 vector;
	u64 apic_id;
	union hv_interrupt_control control;
};

#define MSHV_MAX_MSI_ROUTES		4096

struct mshv_kernel_msi_routing_entry {
	u32 entry_valid;
	u32 gsi;
	u32 address_lo;
	u32 address_hi;
	u32 data;
};

struct mshv_msi_routing_table {
	u32 nr_rt_entries;
	struct mshv_kernel_msi_routing_entry entries[];
};

int mshv_set_msi_routing(struct mshv_partition *partition,
		const struct mshv_msi_routing_entry *entries,
		unsigned int nr);
void mshv_free_msi_routing(struct mshv_partition *partition);

struct mshv_kernel_msi_routing_entry mshv_msi_map_gsi(
		struct mshv_partition *partition, u32 gsi);

void mshv_set_msi_irq(struct mshv_kernel_msi_routing_entry *e,
		      struct mshv_lapic_irq *irq);

void mshv_irqfd_routing_update(struct mshv_partition *partition);

struct hv_synic_pages {
	struct hv_message_page *synic_message_page;
	struct hv_synic_event_flags_page *synic_event_flags_page;
	struct hv_synic_event_ring_page *synic_event_ring_page;
};

struct mshv {
	struct hv_synic_pages __percpu *synic_pages;
	struct {
		spinlock_t lock;
		u64 count;
		struct mshv_partition *array[MSHV_MAX_PARTITIONS];
	} partitions;
};

#endif
