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

	struct list_head devices;

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

struct mshv_device {
	const struct mshv_device_ops *ops;
	struct mshv_partition *partition;
	void *private;
	struct list_head partition_node;

};

/* create, destroy, and name are mandatory */
struct mshv_device_ops {
	const char *name;

	/*
	 * create is called holding partition->mutex and any operations not suitable
	 * to do while holding the lock should be deferred to init (see
	 * below).
	 */
	int (*create)(struct mshv_device *dev, u32 type);

	/*
	 * init is called after create if create is successful and is called
	 * outside of holding partition->mutex.
	 */
	void (*init)(struct mshv_device *dev);

	/*
	 * Destroy is responsible for freeing dev.
	 *
	 * Destroy may be called before or after destructors are called
	 * on emulated I/O regions, depending on whether a reference is
	 * held by a vcpu or other mshv component that gets destroyed
	 * after the emulated I/O.
	 */
	void (*destroy)(struct mshv_device *dev);

	/*
	 * Release is an alternative method to free the device. It is
	 * called when the device file descriptor is closed. Once
	 * release is called, the destroy method will not be called
	 * anymore as the device is removed from the device list of
	 * the VM. partition->mutex is held.
	 */
	void (*release)(struct mshv_device *dev);

	int (*set_attr)(struct mshv_device *dev, struct mshv_device_attr *attr);
	int (*get_attr)(struct mshv_device *dev, struct mshv_device_attr *attr);
	int (*has_attr)(struct mshv_device *dev, struct mshv_device_attr *attr);
	long (*ioctl)(struct mshv_device *dev, unsigned int ioctl,
		      unsigned long arg);
	int (*mmap)(struct mshv_device *dev, struct vm_area_struct *vma);
};

int mshv_register_device_ops(const struct mshv_device_ops *ops, u32 type);
void mshv_unregister_device_ops(u32 type);

#endif
