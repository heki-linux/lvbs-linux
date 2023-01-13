/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_MSHV_H
#define _UAPI_LINUX_MSHV_H

/*
 * Userspace interface for /dev/mshv
 * Microsoft Hypervisor root partition APIs
 * NOTE: This API is not yet stable!
 */

#include <linux/types.h>
#include <asm/hyperv-tlfs.h>
#include <asm-generic/hyperv-tlfs.h>

#define MSHV_CAP_CORE_API_STABLE	0x0
#define MSHV_CAP_REGISTER_PAGE		0x1
#define MSHV_CAP_VTL_RETURN_ACTION	0x2
#define MSHV_CAP_DR6_SHARED		0x3


#define MSHV_VP_MMAP_REGISTERS_OFFSET (HV_VP_STATE_PAGE_REGISTERS * 0x1000)
#define MAX_RUN_MSG_SIZE		256

/*
 * Various isolation types supported by MSHV.
 */
#define HV_PARTITION_ISOLATION_TYPE_NONE            0
#define HV_PARTITION_ISOLATION_TYPE_VBS             1
#define HV_PARTITION_ISOLATION_TYPE_SNP             2
#define HV_PARTITION_ISOLATION_TYPE_TDX             3

/*
 * Various host isolation types supported by MSHV.
 */
#define HV_PARTITION_ISOLATION_HOST_TYPE_NONE       0x0
#define HV_PARTITION_ISOLATION_HOST_TYPE_HARDWARE   0x1
#define HV_PARTITION_ISOLATION_HOST_TYPE_RESERVED   0x2

/*
 * Definition of the partition isolation state. Used for
 * HV_PARTITION_PROPERTY_ISOLATION_STATE.
 *
 *
 * The isolation states (hv_partition_isolation_state) are sub-states of
 * ObPartitionActive that apply to VBS and hardware isolated partitions.
 * For VBS isolation, the trusted host VTL 1 component uses the isolation
 * state to establish a binding between a hypervisor partition and its
 * own partition context, and to enforce certain invariants.
 *
 * Hardware-isolated partitions (including partitions that simulate
 * hardware isolation) also use isolation states to track the progression
 * of the partition security state through the architectural state machine.
 * Insecure states indicate that there is no architectural state
 * associated with the partition, and Secure indicates that the partition
 * has secure architectural state.
 *
 * ObPartitionRestoring is treated differently for isolated partitions.
 * Only the trusted host component is allowed to restore partition state,
 * and ObPartitionRestoring can only transition directly to/from secure.
 *
 *
 * ..................................................................
 * .         UNINITIALIZED     FINALIZED                            .
 * .               |           ^       ^                            .
 * .    Initialize |          /         \                           .
 * .               |         /           \                          .
 * . --------------|--------/--- ACTIVE --\------------------------ .
 * . |             |       /               \                      | .
 * . |             |      / Finalize        \ Finalize            | .
 * . |             v     /                   \                    | .
 * . |       INSECURE-CLEAN <---------------- INSECURE-DIRTY      | .
 * . |                   \        Scrub      ^                    | .
 * . |                    \                 /                     | .
 * . |                     \               /                      | .
 * . |               Secure \             / Unsecure              | .
 * . |                       \           /                        | .
 * . |                        \         /                         | .
 * . |                         v       /                          | .
 * . |                           SECURE                           | .
 * . |                             ^                              | .
 * . |_____________________________|______________________________| .
 * .                               |                                .
 * .                               v                                .
 * .                           RESTORING                            .
 * ..................................................................
 */
enum hv_partition_isolation_state
{
	/*
	 * Initial and final state for all non-isolated partitions.
	 */
	HV_PARTITION_ISOLATION_INVALID             = 0,

	/*
	 * An "Insecure" partition is not being used by the trusted host
	 * component. In this state, VPs can be created and deleted. VPs cannot
	 * be started, and VP registers cannot be modified.

	 * Initial state of an isolated partition as result of Initialize or
	 * Scrub hypercalls. Guest-visible partition and VP state is considered
	 * "clean", in the sense that a call to ObScrubPartition should not
	 * result in any changes. Also, there are no accepted or confidential
	 * pages assigned to the partition. InsecureRundown is enabled.
	 */
	HV_PARTITION_ISOLATION_INSECURE_CLEAN       = 1,

	/*
	 * Guest-visible partition and VP state is not "clean". Hence it must
	 * be scrubbed first. One of 2 explicit states the trusted host
	 * component can request. It cannot transition the state to Secure. In
	 * this state,
	 *  - IsolationControl is clear.
	 *  - Secure rundowns are completely disabled.
	 *  - No assigned pages exist.
	 */
	HV_PARTITION_ISOLATION_INSECURE_DIRTY       = 2,

	/*
	 * The partition is being used by the trusted host component (and is
	 * typically bound to a single partition context in that component).
	 * One of 2 explicit states the trusted host component can request. In
	 * this state,
	 *  - VPs cannot be created or deleted.
	 *  - Partition cannot be finalized, scrubbed.
	 *  - Insecure rundowns are completely disabled.
	 */
	HV_PARTITION_ISOLATION_SECURE              = 3,

	/*
	 * Represents a failed attempt to transition to Secure state. Partition
	 * in this state cannot be finalized, scrubbed since one or more pages
	 * may be assigned.
	 */
	HV_PARTITION_ISOLATION_SECURE_DIRTY         = 4,

	/*
	 * An internal state indicating that a partition is in the process of
	 * transitioning from Secure to InsecureDirty.
	 */
	HV_PARTITION_ISOLATION_SECURE_TERMINATING   = 5,
};

struct mshv_create_partition {
	__u64 flags;
	struct hv_partition_creation_properties partition_creation_properties;
	union hv_partition_synthetic_processor_features synthetic_processor_features;
	union hv_partition_isolation_properties isolation_properties;
};

/*
 * Mappings can't overlap in GPA space or userspace
 * To unmap, these fields must match an existing mapping
 */
struct mshv_user_mem_region {
	__u64 size;		/* bytes */
	__u64 guest_pfn;
	__u64 userspace_addr;	/* start of the userspace allocated memory */
	__u32 flags;		/* ignored on unmap */
};

struct mshv_create_vp {
	__u32 vp_index;
};

#define MSHV_VP_MAX_REGISTERS	128

struct mshv_vp_registers {
	int count; /* at most MSHV_VP_MAX_REGISTERS */
	struct hv_register_assoc *regs;
};

struct mshv_install_intercept {
	__u32 access_type_mask;
	enum hv_intercept_type intercept_type;
	union hv_intercept_parameters intercept_parameter;
};

struct mshv_assert_interrupt {
	union hv_interrupt_control control;
	__u64 dest_addr;
	__u32 vector;
};

#ifdef HV_SUPPORTS_VP_STATE

struct mshv_vp_state {
	enum hv_get_set_vp_state_type type;
	struct hv_vp_state_data_xsave xsave; /* only for xsave request */

	__u64 buf_size; /* If xsave, must be page-aligned */
	union {
		struct hv_local_interrupt_controller_state *lapic;
		__u8 *bytes; /* Xsave data. must be page-aligned */
	} buf;
};

#endif

struct mshv_partition_property {
	enum hv_partition_property_code property_code;
	__u64 property_value;
};

struct mshv_translate_gva {
	__u64 gva;
	__u64 flags;
	union hv_translate_gva_result *result;
	__u64 *gpa;
};

#define MSHV_IRQFD_FLAG_DEASSIGN (1 << 0)
#define MSHV_IRQFD_FLAG_RESAMPLE (1 << 1)

struct mshv_irqfd {
	__s32 fd;
	__s32 resamplefd;
	__u32 gsi;
	__u32 flags;
};

enum {
	mshv_ioeventfd_flag_nr_datamatch,
	mshv_ioeventfd_flag_nr_pio,
	mshv_ioeventfd_flag_nr_deassign,
	mshv_ioeventfd_flag_nr_max,
};

#define MSHV_IOEVENTFD_FLAG_DATAMATCH (1 << mshv_ioeventfd_flag_nr_datamatch)
#define MSHV_IOEVENTFD_FLAG_PIO       (1 << mshv_ioeventfd_flag_nr_pio)
#define MSHV_IOEVENTFD_FLAG_DEASSIGN  (1 << mshv_ioeventfd_flag_nr_deassign)

#define MSHV_IOEVENTFD_VALID_FLAG_MASK  ((1 << mshv_ioeventfd_flag_nr_max) - 1)

struct mshv_ioeventfd {
	__u64 datamatch;
	__u64 addr;        /* legal pio/mmio address */
	__u32 len;         /* 1, 2, 4, or 8 bytes    */
	__s32 fd;
	__u32 flags;
	__u8  pad[4];
};

struct mshv_msi_routing_entry {
	__u32 gsi;
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
};

struct mshv_msi_routing {
	__u32 nr;
	__u32 pad;
	struct mshv_msi_routing_entry entries[0];
};

#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
struct mshv_register_intercept_result {
	__u32 intercept_type; /* enum hv_intercept_type */
	union hv_register_intercept_result_parameters parameters;
};
#endif

struct mshv_signal_event_direct {
	__u32 vp;
	__u8 vtl;
	__u8 sint;
	__u16 flag;
	/* output */
	__u8 newly_signaled;
};

struct mshv_post_message_direct {
	__u32 vp;
	__u8 vtl;
	__u8 sint;
	__u16 length;
	__u8 __user const *message;
};

struct mshv_register_deliverabilty_notifications {
	__u32 vp;
	__u32 pad;
	__u64 flag;
};

struct mshv_get_vp_cpuid_values {
	__u32 function;
	__u32 index;
	/* output */
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
};

struct mshv_vp_run_registers {
	struct hv_message *message;
	struct mshv_vp_registers registers;
};

#define MSHV_IOCTL 0xB8

/* mshv device */
#define MSHV_CHECK_EXTENSION    _IOW(MSHV_IOCTL, 0x00, __u32)
#define MSHV_CREATE_PARTITION	_IOW(MSHV_IOCTL, 0x01, struct mshv_create_partition)

/* partition device */
#define MSHV_MAP_GUEST_MEMORY	_IOW(MSHV_IOCTL, 0x02, struct mshv_user_mem_region)
#define MSHV_UNMAP_GUEST_MEMORY	_IOW(MSHV_IOCTL, 0x03, struct mshv_user_mem_region)
#define MSHV_CREATE_VP		_IOW(MSHV_IOCTL, 0x04, struct mshv_create_vp)
#define MSHV_INSTALL_INTERCEPT	_IOW(MSHV_IOCTL, 0x08, struct mshv_install_intercept)
#define MSHV_ASSERT_INTERRUPT	_IOW(MSHV_IOCTL, 0x09, struct mshv_assert_interrupt)
#define MSHV_SET_PARTITION_PROPERTY \
				_IOW(MSHV_IOCTL, 0xC, struct mshv_partition_property)
#define MSHV_GET_PARTITION_PROPERTY \
				_IOWR(MSHV_IOCTL, 0xD, struct mshv_partition_property)
#define MSHV_IRQFD		_IOW(MSHV_IOCTL, 0xE, struct mshv_irqfd)
#define MSHV_IOEVENTFD		_IOW(MSHV_IOCTL, 0xF, struct mshv_ioeventfd)
#define MSHV_SET_MSI_ROUTING	_IOW(MSHV_IOCTL, 0x11, struct mshv_msi_routing)
#define MSHV_GET_GPA_ACCESS_STATES \
				_IOWR(MSHV_IOCTL, 0x12, struct mshv_get_gpa_pages_access_state)
/* vp device */
#define MSHV_GET_VP_REGISTERS   _IOWR(MSHV_IOCTL, 0x05, struct mshv_vp_registers)
#define MSHV_SET_VP_REGISTERS   _IOW(MSHV_IOCTL, 0x06, struct mshv_vp_registers)
#define MSHV_RUN_VP		_IOR(MSHV_IOCTL, 0x07, struct hv_message)
#define MSHV_RUN_VP_REGISTERS	_IOWR(MSHV_IOCTL, 0x1C, struct mshv_vp_run_registers)
#ifdef HV_SUPPORTS_VP_STATE
#define MSHV_GET_VP_STATE	_IOWR(MSHV_IOCTL, 0x0A, struct mshv_vp_state)
#define MSHV_SET_VP_STATE	_IOWR(MSHV_IOCTL, 0x0B, struct mshv_vp_state)
#endif
#define MSHV_TRANSLATE_GVA	_IOWR(MSHV_IOCTL, 0x0E, struct mshv_translate_gva)
#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
#define MSHV_VP_REGISTER_INTERCEPT_RESULT \
				_IOW(MSHV_IOCTL, 0x17, struct mshv_register_intercept_result)
#endif
#define MSHV_SIGNAL_EVENT_DIRECT \
	_IOWR(MSHV_IOCTL, 0x18, struct mshv_signal_event_direct)
#define MSHV_POST_MESSAGE_DIRECT \
	_IOW(MSHV_IOCTL, 0x19, struct mshv_post_message_direct)
#define MSHV_REGISTER_DELIVERABILITY_NOTIFICATIONS \
	_IOW(MSHV_IOCTL, 0x1A, struct mshv_register_deliverabilty_notifications)
#define MSHV_GET_VP_CPUID_VALUES \
        _IOWR(MSHV_IOCTL, 0x1B, struct mshv_get_vp_cpuid_values)	

/* vtl device */
#define MSHV_CREATE_VTL			_IOR(MSHV_IOCTL, 0x1D, char)
#define MSHV_VTL_RAM_DISPOSITION	_IOR(MSHV_IOCTL, 0x20, struct mshv_ram_disposition)
#define MSHV_VTL_ADD_VTL0_MEMORY	_IOW(MSHV_IOCTL, 0x21, struct mshv_ram_disposition)
#define MSHV_VTL_SET_POLL_FILE		_IOW(MSHV_IOCTL, 0x25, struct mshv_set_poll_file)
#define MSHV_VTL_RETURN_TO_LOWER_VTL	_IO(MSHV_IOCTL, 0x27)

/* VMBus device IOCTLs */
#define MSHV_SINT_SIGNAL_EVENT    _IOW(MSHV_IOCTL, 0x22, struct mshv_signal_event)
#define MSHV_SINT_POST_MESSAGE    _IOW(MSHV_IOCTL, 0x23, struct mshv_sint_post_msg)
#define MSHV_SINT_SET_EVENTFD     _IOW(MSHV_IOCTL, 0x24, struct mshv_set_eventfd)

/* hv_hvcall device */
#define MSHV_HVCALL_SETUP        _IOW(MSHV_IOCTL, 0x1E, struct mshv_hvcall_setup)
#define MSHV_HVCALL              _IOWR(MSHV_IOCTL, 0x1F, struct mshv_hvcall)

/* ioctl for device fd */
#define MSHV_CREATE_DEVICE	  _IOWR(MSHV_IOCTL, 0x13, struct mshv_create_device)

/* ioctls for fds returned by MSHV_CREATE_DEVICE */
#define MSHV_SET_DEVICE_ATTR	  _IOW(MSHV_IOCTL, 0x14, struct mshv_device_attr)
#define MSHV_GET_DEVICE_ATTR	  _IOW(MSHV_IOCTL, 0x15, struct mshv_device_attr)
#define MSHV_HAS_DEVICE_ATTR	  _IOW(MSHV_IOCTL, 0x16, struct mshv_device_attr)

/* register page mapping example:
 * struct hv_vp_register_page *regs = mmap(NULL,
 *					   4096,
 *					   PROT_READ | PROT_WRITE,
 *					   MAP_SHARED,
 *					   vp_fd,
 *					   HV_VP_MMAP_REGISTERS_OFFSET);
 * munmap(regs, 4096);
 */

struct mshv_get_gpa_pages_access_state {
	__u32 count;
	__u64 flags;
	__u64 hv_gpa_page_number;
	union hv_gpa_page_access_state *states;
} __packed;

/*
 * Device control API.
 */
#define MSHV_CREATE_DEVICE_TEST		1

struct mshv_create_device {
	__u32	type;	/* in: MSHV_DEV_TYPE_xxx */
	__u32	fd;	/* out: device handle */
	__u32	flags;	/* in: MSHV_CREATE_DEVICE_xxx */
};

#define  MSHV_DEV_VFIO_GROUP			1
#define   MSHV_DEV_VFIO_GROUP_ADD			1
#define   MSHV_DEV_VFIO_GROUP_DEL			2

enum mshv_device_type {
	MSHV_DEV_TYPE_VFIO,
#define MSHV_DEV_TYPE_VFIO		MSHV_DEV_TYPE_VFIO
	MSHV_DEV_TYPE_MAX,
};

struct mshv_device_attr {
	__u32	flags;		/* no flags currently defined */
	__u32	group;		/* device-defined */
	__u64	attr;		/* group-defined */
	__u64	addr;		/* userspace address of attr data */
};

#endif
