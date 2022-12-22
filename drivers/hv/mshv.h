/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023, Microsoft Corporation.
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
#include <asm/hyperv-tlfs.h>

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

/*
 * Hyper-V hypercalls
 */

int hv_call_withdraw_memory(u64 count, int node, u64 partition_id);
int hv_call_create_partition(
		u64 flags,
		struct hv_partition_creation_properties creation_properties,
		union hv_partition_isolation_properties isolation_properties,
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
		union hv_input_vtl input_vtl,
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
		union hv_input_vtl input_vtl,
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
		u64 property_value,
		void (*completion_handler)(u64/* partition_id */, u64 */* status */));
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

struct mshv_partition *mshv_partition_find(u64 partition_id) __must_hold(RCU);

int mshv_xfer_to_guest_mode_handle_work(unsigned long ti_work);

typedef long (*mshv_ioctl_func_t)(void __user *user_arg);
void mshv_set_create_vtl_func(const mshv_ioctl_func_t func);
void mshv_set_create_partition_func(const mshv_ioctl_func_t func);

long mshv_ioctl_signal_event_direct(u64 partition_id, void __user *user_args);
long mshv_ioctl_translate_gva(u32 vp_index, u64 partition_id, void __user *user_args);
long mshv_ioctl_assert_interrupt(u64 partition_id, void __user *user_args);
long mshv_ioctl_install_intercept(u64 partition_id, void __user *user_args);
long mshv_ioctl_post_message_direct(u64 partition_id, void __user *user_args);

extern struct mshv mshv;

#endif /* _MSHV_H */
