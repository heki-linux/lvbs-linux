/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021, Microsoft Corporation.
 *
 * Authors:
 *   Nuno Das Neves <nudasnev@microsoft.com>
 *   Lillian Grassin-Drake <ligrassi@microsoft.com>
 *   Vineeth Pillai <viremana@linux.microsoft.com>
 */

#ifndef _MSHV_H_
#define _MSHV_H_

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/srcu.h>
#include <linux/wait.h>
#include <uapi/linux/mshv.h>
#include<asm/hyperv-tlfs.h>

/* Determined empirically */
#define HV_INIT_PARTITION_DEPOSIT_PAGES 208
#define HV_MAP_GPA_DEPOSIT_PAGES	256

#define HV_WITHDRAW_BATCH_SIZE	(HV_HYP_PAGE_SIZE / sizeof(u64))
#define HV_MAP_GPA_BATCH_SIZE	\
		((HV_HYP_PAGE_SIZE - sizeof(struct hv_map_gpa_pages)) / sizeof(u64))
#define PIN_PAGES_BATCH_SIZE	(0x10000000 / HV_HYP_PAGE_SIZE)
#define HV_GET_REGISTER_BATCH_SIZE	\
	(HV_HYP_PAGE_SIZE / sizeof(union hv_register_value))
#define HV_SET_REGISTER_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_set_vp_registers)) \
		/ sizeof(struct hv_register_assoc))
#define HV_GET_VP_STATE_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_get_vp_state_in)) \
		/ sizeof(u64))
#define HV_SET_VP_STATE_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_set_vp_state_in)) \
		/ sizeof(u64))
#define HV_GET_GPA_ACCESS_STATES_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(union hv_gpa_page_access_state)) \
		/ sizeof(union hv_gpa_page_access_state))

#define MSHV_MAX_PARTITIONS		512
#define MSHV_MAX_MEM_REGIONS		64
#define MSHV_MAX_VPS			256

/*
 * Hyper-V hypercalls
 */

int hv_call_withdraw_memory(u64 count, int node, u64 partition_id);
int hv_call_create_partition(
		u64 flags,
		struct hv_partition_creation_properties creation_properties,
		u64 *partition_id);
int hv_call_initialize_partition(u64 partition_id);
int hv_call_finalize_partition(u64 partition_id);
int hv_call_delete_partition(u64 partition_id);
int hv_call_map_gpa_pages(
		u64 partition_id,
		u64 gpa_target,
		u64 page_count, u32 flags,
		struct page **pages);
int hv_call_unmap_gpa_pages(
		u64 partition_id,
		u64 gpa_target,
		u64 page_count, u32 flags);
int hv_call_get_vp_registers(
		u32 vp_index,
		u64 partition_id,
		u16 count,
		struct hv_register_assoc *registers);
int hv_call_get_gpa_access_states(
		u64 partition_id,
		u32 count,
		u64 gpa_base_pfn,
		u64 state_flags,
		int *written_total,
		union hv_gpa_page_access_state *states);

int hv_call_set_vp_registers(
		u32 vp_index,
		u64 partition_id,
		u16 count,
		struct hv_register_assoc *registers);
int hv_call_install_intercept(u64 partition_id, u32 access_type,
		enum hv_intercept_type intercept_type,
		union hv_intercept_parameters intercept_parameter);
int hv_call_assert_virtual_interrupt(
		u64 partition_id,
		u32 vector,
		u64 dest_addr,
		union hv_interrupt_control control);
int hv_call_clear_virtual_interrupt(u64 partition_id);

#ifdef HV_SUPPORTS_VP_STATE
int hv_call_get_vp_state(
		u32 vp_index,
		u64 partition_id,
		enum hv_get_set_vp_state_type type,
		struct hv_vp_state_data_xsave xsave,
		/* Choose between pages and ret_output */
		u64 page_count,
		struct page **pages,
		union hv_get_vp_state_out *ret_output);
int hv_call_set_vp_state(
		u32 vp_index,
		u64 partition_id,
		enum hv_get_set_vp_state_type type,
		struct hv_vp_state_data_xsave xsave,
		/* Choose between pages and bytes */
		u64 page_count,
		struct page **pages,
		u32 num_bytes,
		u8 *bytes);
#endif

int hv_call_map_vp_state_page(u64 partition_id, u32 vp_index, u32 type,
				struct page **state_page);
int hv_call_unmap_vp_state_page(u64 partition_id, u32 vp_index, u32 type);
int hv_call_get_partition_property(
		u64 partition_id,
		u64 property_code,
		u64 *property_value);
int hv_call_set_partition_property(
		u64 partition_id,
		u64 property_code,
		u64 property_value);
int hv_call_translate_virtual_address(
		u32 vp_index,
		u64 partition_id,
		u64 flags,
		u64 gva,
		u64 *gpa,
		union hv_translate_gva_result *result);
int hv_call_get_vp_cpuid_values(
		u32 vp_index,
		u64 partition_id,
		union hv_get_vp_cpuid_values_flags values_flags,
		struct hv_cpuid_leaf_info *info,
		union hv_output_get_vp_cpuid_values *result);

int hv_call_create_port(u64 port_partition_id, union hv_port_id port_id,
			u64 connection_partition_id, struct hv_port_info *port_info,
			u8 port_vtl, u8 min_connection_vtl, int node);
int hv_call_delete_port(u64 port_partition_id, union hv_port_id port_id);
int hv_call_connect_port(u64 port_partition_id, union hv_port_id port_id,
			 u64 connection_partition_id,
			 union hv_connection_id connection_id,
			 struct hv_connection_info *connection_info,
			 u8 connection_vtl, int node);
int hv_call_disconnect_port(u64 connection_partition_id,
			    union hv_connection_id connection_id);
int hv_call_notify_port_ring_empty(u32 sint_index);
#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
int hv_call_register_intercept_result(u32 vp_index,
				  u64 partition_id,
				  enum hv_intercept_type intercept_type,
				  union hv_register_intercept_result_parameters *params);
#endif
int hv_call_signal_event_direct(u32 vp_index,
				u64 partition_id,
				u8 vtl,
				u8 sint,
				u16 flag_number,
				u8* newly_signaled);
int hv_call_post_message_direct(u32 vp_index,
				u64 partition_id,
				u8 vtl,
				u32 sint_index,
				u8* message);

/*
 * MSHV module internals
 */

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
			u64 kicked_by_hv: 1;
			u64 reserved: 60;
		} flags;
		wait_queue_head_t suspend_queue;
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

	struct mutex irq_lock;
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

int mshv_xfer_to_guest_mode_handle_work(unsigned long ti_work);

void mshv_isr(void);
int mshv_synic_init(unsigned int cpu);
int mshv_synic_cleanup(unsigned int cpu);

extern struct mshv mshv;

#endif /* _MSHV_H */
