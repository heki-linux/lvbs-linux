/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023, Microsoft Corporation.
 */

#ifndef _MSHV_ROOT_H_
#define _MSHV_ROOT_H_

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/srcu.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
#include <uapi/linux/mshv.h>
#include <asm/hyperv-tlfs.h>

#define MSHV_PARTITIONS_HASH_BITS	9
#define MSHV_MAX_PARTITIONS		(1 << MSHV_PARTITIONS_HASH_BITS)
#define MSHV_MAX_MEM_REGIONS		64
#define MSHV_MAX_VPS			256

struct mshv_vp {
	u32 index;
	struct mshv_partition *partition;
	struct mutex mutex;
	struct page *register_page;
	struct hv_message *intercept_message_page;
	struct hv_register_assoc *registers;
	struct {
		atomic64_t signaled_count;
		struct {
			u64 explicit_suspend: 1;
			u64 blocked_by_explicit_suspend: 1; /* root scheduler only */
			u64 intercept_suspend: 1;
			u64 blocked: 1; /* root scheduler only */
			u64 reserved: 60;
		} flags;
		unsigned int kicked_by_hv;
		wait_queue_head_t suspend_queue;
	} run;
};

struct mshv_mem_region {
	u64 size; /* bytes */
	u64 guest_pfn;
	u64 userspace_addr; /* start of the userspace allocated memory */
	struct page *pages[];
};

struct mshv_irq_ack_notifier {
	struct hlist_node link;
	unsigned int gsi;
	void (*irq_acked)(struct mshv_irq_ack_notifier *mian);
};

struct mshv_partition {
	struct hlist_node hnode;
	u64 id;
	refcount_t ref_count;
	struct mutex mutex;
	struct {
		u32 count;
		struct mshv_mem_region *array[MSHV_MAX_MEM_REGIONS];
	} regions;
	struct {
		u32 count;
		struct mshv_vp *array[MSHV_MAX_VPS];
	} vps;

	struct mutex irq_lock;
	struct srcu_struct irq_srcu;
	struct hlist_head irq_ack_notifier_list;

	struct hlist_head devices;

	struct completion async_hypercall;

	struct {
		spinlock_t        lock;
		struct hlist_head items;
		struct mutex resampler_lock;
		struct hlist_head resampler_list;
	} irqfds;
	struct {
		struct hlist_head items;
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
		DECLARE_HASHTABLE(items, MSHV_PARTITIONS_HASH_BITS);
	} partitions;
};

struct mshv_device {
	const struct mshv_device_ops *ops;
	struct mshv_partition *partition;
	void *private;
	struct hlist_node partition_node;

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

/*
 * Callback for doorbell events.
 * NOTE: This is called in interrupt context. Callback
 * should defer slow and sleeping logic to later.
 */
typedef void (*doorbell_cb_t) (int doorbell_id, void *);

/*
 * port table information
 */
struct port_table_info {
	struct rcu_head rcu;
	enum hv_port_type port_type;
	union {
		struct {
			u64 reserved[2];
		} port_message;
		struct {
			u64 reserved[2];
		} port_event;
		struct {
			u64 reserved[2];
		} port_monitor;
		struct {
			doorbell_cb_t doorbell_cb;
			void *data;
		} port_doorbell;
	};
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

void hv_port_table_fini(void);
int hv_portid_alloc(struct port_table_info *info);
int hv_portid_lookup(int port_id, struct port_table_info *info);
void hv_portid_free(int port_id);

int hv_register_doorbell(u64 partition_id, doorbell_cb_t doorbell_cb,
			 void *data, u64 gpa, u64 val, u64 flags);
int hv_unregister_doorbell(u64 partition_id, int doorbell_portid);

int mshv_register_device_ops(const struct mshv_device_ops *ops, u32 type);
void mshv_unregister_device_ops(u32 type);

void mshv_isr(void);
int mshv_synic_init(unsigned int cpu);
int mshv_synic_cleanup(unsigned int cpu);

extern struct mshv mshv;

#endif /* _MSHV_ROOT_H_ */
