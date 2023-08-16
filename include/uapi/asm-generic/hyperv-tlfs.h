/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_GENERIC_HYPERV_TLFS_USER_H
#define _UAPI_ASM_GENERIC_HYPERV_TLFS_USER_H

#ifndef BIT
#define BIT(X)	(1ULL << (X))
#endif

/* Define synthetic interrupt controller message constants. */
#define HV_MESSAGE_SIZE			(256)
#define HV_MESSAGE_PAYLOAD_BYTE_COUNT	(240)
#define HV_MESSAGE_PAYLOAD_QWORD_COUNT	(30)
#define HV_ANY_VP			(0xFFFFFFFF)

/* Define hypervisor message types. */
enum hv_message_type {
	HVMSG_NONE				= 0x00000000,

	/* Memory access messages. */
	HVMSG_UNMAPPED_GPA			= 0x80000000,
	HVMSG_GPA_INTERCEPT			= 0x80000001,

	/* Timer notification messages. */
	HVMSG_TIMER_EXPIRED			= 0x80000010,

	/* Error messages. */
	HVMSG_INVALID_VP_REGISTER_VALUE		= 0x80000020,
	HVMSG_UNRECOVERABLE_EXCEPTION		= 0x80000021,
	HVMSG_UNSUPPORTED_FEATURE		= 0x80000022,

	/*
	 * Opaque intercept message. The original intercept message is only
	 * accessible from the mapped intercept message page.
	 */
	HVMSG_OPAQUE_INTERCEPT			= 0x8000003F,

	/* Trace buffer complete messages. */
	HVMSG_EVENTLOG_BUFFERCOMPLETE		= 0x80000040,

	/* Hypercall intercept */
	HVMSG_HYPERCALL_INTERCEPT		= 0x80000050,

	/* SynIC intercepts */
	HVMSG_SYNIC_EVENT_INTERCEPT		= 0x80000060,
	HVMSG_SYNIC_SINT_INTERCEPT		= 0x80000061,
	HVMSG_SYNIC_SINT_DELIVERABLE	= 0x80000062,

	/* Async call completion intercept */
	HVMSG_ASYNC_CALL_COMPLETION		= 0x80000070,

	/* Root scheduler messages */
	HVMSG_SCHEDULER_VP_SIGNAL_BITSET	= 0x80000100,
	HVMSG_SCHEDULER_VP_SIGNAL_PAIR		= 0x80000101,

	/* Platform-specific processor intercept messages. */
	HVMSG_X64_IO_PORT_INTERCEPT		= 0x80010000,
	HVMSG_X64_MSR_INTERCEPT			= 0x80010001,
	HVMSG_X64_CPUID_INTERCEPT		= 0x80010002,
	HVMSG_X64_EXCEPTION_INTERCEPT		= 0x80010003,
	HVMSG_X64_APIC_EOI			= 0x80010004,
	HVMSG_X64_LEGACY_FP_ERROR		= 0x80010005,
	HVMSG_X64_IOMMU_PRQ			= 0x80010006,
	HVMSG_X64_HALT				= 0x80010007,
	HVMSG_X64_INTERRUPTION_DELIVERABLE	= 0x80010008,
	HVMSG_X64_SIPI_INTERCEPT		= 0x80010009,
};

/* Define synthetic interrupt controller message flags. */
union hv_message_flags {
	__u8 asu8;
	struct {
		__u8 msg_pending:1;
		__u8 reserved:7;
	} __packed;
};

enum hv_port_type {
	HV_PORT_TYPE_MESSAGE = 1,
	HV_PORT_TYPE_EVENT   = 2,
	HV_PORT_TYPE_MONITOR = 3,
	HV_PORT_TYPE_DOORBELL = 4	// Root Partition only
};

/*
 * Doorbell connection_info flags.
 */
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_MASK  0x00000007
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_ANY   0x00000000
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_BYTE  0x00000001
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_WORD  0x00000002
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_DWORD 0x00000003
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_QWORD 0x00000004
#define HV_DOORBELL_FLAG_TRIGGER_ANY_VALUE  0x80000000

/* Define port identifier type. */
union hv_port_id {
	__u32 asu32;
	struct {
		__u32 id:24;
		__u32 reserved:8;
	} __packed u;
};

/* Define connection identifier type. */
union hv_connection_id {
	__u32 asu32;
	struct {
		__u32 id:24;
		__u32 reserved:8;
	} u;
};

/* Define synthetic interrupt controller message header. */
struct hv_message_header {
	__u32 message_type;
	__u8 payload_size;
	union hv_message_flags message_flags;
	__u8 reserved[2];
	union {
		__u64 sender;
		union hv_port_id port;
	};
} __packed;

/* Define synthetic interrupt controller message format. */
struct hv_message {
	struct hv_message_header header;
	union {
		__u64 payload[HV_MESSAGE_PAYLOAD_QWORD_COUNT];
	} u;
} __packed;

/* Userspace-visible partition creation flags */
#define HV_PARTITION_CREATION_FLAG_SMT_ENABLED_GUEST                BIT(0)
#define HV_PARTITION_CREATION_FLAG_GPA_LARGE_PAGES_DISABLED         BIT(3)
#define HV_PARTITION_CREATION_FLAG_GPA_SUPER_PAGES_ENABLED          BIT(4)
#define HV_PARTITION_CREATION_FLAG_LAPIC_ENABLED                    BIT(13)

/* HV Map GPA (Guest Physical Address) Flags */
#define HV_MAP_GPA_PERMISSIONS_NONE     0x0
#define HV_MAP_GPA_READABLE             0x1
#define HV_MAP_GPA_WRITABLE             0x2
#define HV_MAP_GPA_KERNEL_EXECUTABLE    0x4
#define HV_MAP_GPA_USER_EXECUTABLE      0x8
#define HV_MAP_GPA_EXECUTABLE           0xC
#define HV_MAP_GPA_PERMISSIONS_MASK     0xF
#define HV_MAP_GPA_ACCESS_ALL \
	(HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE | \
	 HV_MAP_GPA_KERNEL_EXECUTABLE | HV_MAP_GPA_USER_EXECUTABLE)

struct hv_register_assoc {
	__u32 name;			/* enum hv_register_name */
	__u32 reserved1;
	__u64 reserved2;
	union hv_register_value value;
} __packed;

/*
 * For getting and setting VP state, there are two options based on the state type:
 *
 *     1.) Data that is accessed by PFNs in the input hypercall page. This is used
 *         for state which may not fit into the hypercall pages.
 *     2.) Data that is accessed directly in the input\output hypercall pages.
 *         This is used for state that will always fit into the hypercall pages.
 *
 * In the future this could be dynamic based on the size if needed.
 *
 * Note these hypercalls have an 8-byte aligned variable header size as per the tlfs
 */

#define HV_GET_SET_VP_STATE_TYPE_PFN	BIT(31)

enum hv_get_set_vp_state_type {
	HV_GET_SET_VP_STATE_LOCAL_INTERRUPT_CONTROLLER_STATE = 0 | HV_GET_SET_VP_STATE_TYPE_PFN,

	HV_GET_SET_VP_STATE_XSAVE		= 1 | HV_GET_SET_VP_STATE_TYPE_PFN,
	/* Synthetic message page */
	HV_GET_SET_VP_STATE_SIM_PAGE		= 2 | HV_GET_SET_VP_STATE_TYPE_PFN,
	/* Synthetic interrupt event flags page. */
	HV_GET_SET_VP_STATE_SIEF_PAGE		= 3 | HV_GET_SET_VP_STATE_TYPE_PFN,

	/* Synthetic timers. */
	HV_GET_SET_VP_STATE_SYNTHETIC_TIMERS	= 4,
};

enum hv_vp_state_page_type {
	HV_VP_STATE_PAGE_REGISTERS = 0,
	HV_VP_STATE_PAGE_INTERCEPT_MESSAGE = 1,
	HV_VP_STATE_PAGE_COUNT
};

enum hv_partition_property_code {
	/* Privilege properties */
	HV_PARTITION_PROPERTY_PRIVILEGE_FLAGS				= 0x00010000,
	HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES			= 0x00010001,

	/* Scheduling properties */
	HV_PARTITION_PROPERTY_SUSPEND					= 0x00020000,
	HV_PARTITION_PROPERTY_CPU_RESERVE				= 0x00020001,
	HV_PARTITION_PROPERTY_CPU_CAP					= 0x00020002,
	HV_PARTITION_PROPERTY_CPU_WEIGHT				= 0x00020003,
	HV_PARTITION_PROPERTY_CPU_GROUP_ID				= 0x00020004,

	/* Time properties */
	HV_PARTITION_PROPERTY_TIME_FREEZE				= 0x00030003,

	/* Debugging properties */
	HV_PARTITION_PROPERTY_DEBUG_CHANNEL_ID				= 0x00040000,

	/* Resource properties */
	HV_PARTITION_PROPERTY_VIRTUAL_TLB_PAGE_COUNT			= 0x00050000,
	HV_PARTITION_PROPERTY_VSM_CONFIG				= 0x00050001,
	HV_PARTITION_PROPERTY_ZERO_MEMORY_ON_RESET			= 0x00050002,
	HV_PARTITION_PROPERTY_PROCESSORS_PER_SOCKET			= 0x00050003,
	HV_PARTITION_PROPERTY_NESTED_TLB_SIZE				= 0x00050004,
	HV_PARTITION_PROPERTY_GPA_PAGE_ACCESS_TRACKING			= 0x00050005,
	HV_PARTITION_PROPERTY_VSM_PERMISSIONS_DIRTY_SINCE_LAST_QUERY	= 0x00050006,
	HV_PARTITION_PROPERTY_SGX_LAUNCH_CONTROL_CONFIG			= 0x00050007,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL0		= 0x00050008,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL1		= 0x00050009,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL2		= 0x0005000a,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL3		= 0x0005000b,
	HV_PARTITION_PROPERTY_ISOLATION_STATE				= 0x0005000c,
	HV_PARTITION_PROPERTY_ISOLATION_CONTROL				= 0x0005000d,
	HV_PARTITION_PROPERTY_RDT_L3_COS_INDEX				= 0x0005000e,
	HV_PARTITION_PROPERTY_RDT_RMID					= 0x0005000f,
	HV_PARTITION_PROPERTY_IMPLEMENTED_PHYSICAL_ADDRESS_BITS		= 0x00050010,
	HV_PARTITION_PROPERTY_NON_ARCHITECTURAL_CORE_SHARING		= 0x00050011,
	HV_PARTITION_PROPERTY_HYPERCALL_DOORBELL_PAGE			= 0x00050012,
	HV_PARTITION_PROPERTY_ISOLATION_POLICY				= 0x00050014,
	HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION                  = 0x00050017,

	/* Compatibility properties */
	HV_PARTITION_PROPERTY_PROCESSOR_VENDOR				= 0x00060000,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES_DEPRECATED		= 0x00060001,
	HV_PARTITION_PROPERTY_PROCESSOR_XSAVE_FEATURES			= 0x00060002,
	HV_PARTITION_PROPERTY_PROCESSOR_CL_FLUSH_SIZE			= 0x00060003,
	HV_PARTITION_PROPERTY_ENLIGHTENMENT_MODIFICATIONS		= 0x00060004,
	HV_PARTITION_PROPERTY_COMPATIBILITY_VERSION			= 0x00060005,
	HV_PARTITION_PROPERTY_PHYSICAL_ADDRESS_WIDTH			= 0x00060006,
	HV_PARTITION_PROPERTY_XSAVE_STATES				= 0x00060007,
	HV_PARTITION_PROPERTY_MAX_XSAVE_DATA_SIZE			= 0x00060008,
	HV_PARTITION_PROPERTY_PROCESSOR_CLOCK_FREQUENCY			= 0x00060009,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES0			= 0x0006000a,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES1			= 0x0006000b,

	/* Guest software properties */
	HV_PARTITION_PROPERTY_GUEST_OS_ID				= 0x00070000,

	/* Nested virtualization properties */
	HV_PARTITION_PROPERTY_PROCESSOR_VIRTUALIZATION_FEATURES		= 0x00080000,
};

enum hv_translate_gva_result_code {
	HV_TRANSLATE_GVA_SUCCESS			= 0,

	/* Translation failures. */
	HV_TRANSLATE_GVA_PAGE_NOT_PRESENT		= 1,
	HV_TRANSLATE_GVA_PRIVILEGE_VIOLATION		= 2,
	HV_TRANSLATE_GVA_INVALIDE_PAGE_TABLE_FLAGS	= 3,

	/* GPA access failures. */
	HV_TRANSLATE_GVA_GPA_UNMAPPED			= 4,
	HV_TRANSLATE_GVA_GPA_NO_READ_ACCESS		= 5,
	HV_TRANSLATE_GVA_GPA_NO_WRITE_ACCESS		= 6,
	HV_TRANSLATE_GVA_GPA_ILLEGAL_OVERLAY_ACCESS	= 7,

	/*
	 * Intercept for memory access by either
	 *  - a higher VTL
	 *  - a nested hypervisor (due to a violation of the nested page table)
	 */
	HV_TRANSLATE_GVA_INTERCEPT			= 8,

	HV_TRANSLATE_GVA_GPA_UNACCEPTED			= 9,
};

union hv_translate_gva_result {
	__u64 as_uint64;
	struct {
		__u32 result_code; /* enum hv_translate_hva_result_code */
		__u32 cache_type : 8;
		__u32 overlay_page : 1;
		__u32 reserved : 23;
	} __packed;
};

union hv_gpa_page_access_state_flags {
	struct {
		__u64 clear_accessed : 1;
		__u64 set_access : 1;
		__u64 clear_dirty : 1;
		__u64 set_dirty : 1;
		__u64 reserved : 60;
	} __packed;
	__u64 as_uint64;
} __packed;

struct hv_input_get_gpa_pages_access_state {
	__u64  partition_id;
	union hv_gpa_page_access_state_flags flags;
	__u64 hv_gpa_page_number;
} __packed;

union hv_gpa_page_access_state {
	struct {
		__u8 accessed : 1;
		__u8 dirty : 1;
		__u8 reserved: 6;
	};
	__u8 as_uint8;
} __packed;

union hv_partition_property_page_access_tracking_config {
	struct {
		__u64 enabled : 1;
		__u64 granularity : 1;
		__u64 reserved : 62;
	} __packed;
	__u64 as_uint64;
} __packed;

enum {
	MSHV_PAGE_ACCESS_TRACKING_GRANULARITY_SMALL_PAGES = 0,
	MSHV_PAGE_ACCESS_TRACKING_GRANULARITY_LARGE_PAGES = 1,
};


/* hv_translage_gva flags */
#define HV_TRANSLATE_GVA_VALIDATE_READ		0x0001
#define HV_TRANSLATE_GVA_VALIDATE_WRITE		0x0002
#define HV_TRANSLATE_GVA_VALIDATE_EXECUTE	0x0004
#define HV_TRANSLATE_GVA_PRIVILEGE_EXCEMP	0x0008
#define HV_TRANSLATE_GVA_SET_PAGE_TABLE_BITS	0x0010
#define HV_TRANSLATE_GVA_TLB_FLUSH_INHIBIT	0x0020
#define HV_TRANSLATE_GVA_CONTROL_MASK		0x003f

/* hv_modify_spa_page_host_access flags */
#define HV_MODIFY_SPA_PAGE_HOST_ACCESS_MAKE_EXCLUSIVE	0x1
#define HV_MODIFY_SPA_PAGE_HOST_ACCESS_MAKE_SHARED	0x2
#define HV_MODIFY_SPA_PAGE_HOST_ACCESS_LARGE_PAGE	0x4
#define HV_MODIFY_SPA_PAGE_HOST_ACCESS_HUGE_PAGE	0x8

#define HV_MODIFY_SPA_PAGE_HOST_ACCESS_FLAGS_MASK	\
	(HV_MODIFY_SPA_PAGE_HOST_ACCESS_MAKE_EXCLUSIVE	\
	 | HV_MODIFY_SPA_PAGE_HOST_ACCESS_MAKE_SHARED	\
	 | HV_MODIFY_SPA_PAGE_HOST_ACCESS_LARGE_PAGE	\
	 | HV_MODIFY_SPA_PAGE_HOST_ACCESS_HUGE_PAGE	\
	)

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
enum hv_partition_isolation_state {
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

union hv_partition_isolation_properties {
	__u64 as_uint64;
	struct {
		__u64 isolation_type: 5;
		__u64 isolation_host_type : 2;
		__u64 rsvd_z: 5;
		__u64 shared_gpa_boundary_page_number: 52;
	} __packed;
};

enum hv_isolated_page_type {
	hv_isolated_page_type_normal = 0,
	hv_isolated_page_type_vmsa = 1,
	hv_isolated_page_type_zero = 2,
	hv_isolated_page_type_unmeasured = 3,
	hv_isolated_page_type_secrets = 4,
	hv_isolated_page_type_cpuid = 5,
	hv_isolated_page_type_count = 6
};

enum hv_isolated_page_size {
	hv_isolated_page_size4_kb = 0,
	hv_isolated_page_size2_mb = 1
};

struct hv_opaque_intercept_message {
	__u32 vp_index;
} __packed;

union hv_interrupt_control {
	struct {
		__u32 interrupt_type; /* enum hv_interrupt type */
		__u32 level_triggered : 1;
		__u32 logical_dest_mode : 1;
		__u32 rsvd : 30;
	} __packed;
	__u64 as_uint64;
};

#endif
