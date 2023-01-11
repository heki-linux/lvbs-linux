/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_ARM64_HYPERV_TLFS_USER_H
#define _UAPI_ASM_ARM64_HYPERV_TLFS_USER_H

#include <linux/types.h>
#include <asm-generic/hyperv-common-types.h>

enum hv_arm64_pending_interruption_type {
	HV_ARM64_PENDING_INTERRUPT = 0,
	HV_ARM64_PENDING_EXCEPTION = 1
};

union hv_arm64_pending_interruption_register {
	__u64 as_uint64;
	struct {
		__u64 interruption_pending : 1;
		__u64 interruption_type : 1;
		__u64 reserved : 30;
		__u64 error_code : 32;
	};
};

union hv_arm64_interrupt_state_register {
	__u64 as_uint64;
	struct {
		__u64 interrupt_shadow : 1;
		__u64 reserved : 63;
	};
};

#define HV_ARM64_PENDING_EVENT_HEADER \
	__u8 event_pending : 1; \
	__u8 event_type : 3; \
	__u8 reserved : 4

union hv_arm64_pending_exception_event {
	__u64 as_uint64[2];
	struct {
		HV_ARM64_PENDING_EVENT_HEADER;

		__u32 exception_syndrome;
		__u64 fault_address;
	};
};

union hv_arm64_pending_secure_exception_event {
	__u64 as_uint64[2];
	struct {
		HV_ARM64_PENDING_EVENT_HEADER;
	};
};

union hv_register_value {
	struct hv_u128 reg128;
	__u64 reg64;
	__u32 reg32;
	__u16 reg16;
	__u8 reg8;
	union hv_explicit_suspend_register explicit_suspend;
	union hv_intercept_suspend_register intercept_suspend;
	union hv_dispatch_suspend_register dispatch_suspend;
	union hv_arm64_pending_interruption_register pending_interruption;
	union hv_arm64_interrupt_state_register interrupt_state;
	union hv_arm64_pending_exception_event pending_exception_event;
	union hv_arm64_pending_secure_exception_event pending_secure_exception_event;
};

#define HV_PARTITION_PROCESSOR_FEATURE_BANKS 1

union hv_partition_processor_features {
	__u64 as_uint64[HV_PARTITION_PROCESSOR_FEATURE_BANKS];

	struct {
		__u64 asid16 : 1;
		__u64 tgran16 : 1;
		__u64 tgran64 : 1;
		__u64 haf : 1;
		__u64 hdbs : 1;
		__u64 pan : 1;
		__u64 ats1e1 : 1;
		__u64 uao : 1;
		__u64 el0aarch32 : 1;
		__u64 fp : 1;
		__u64 fphp : 1;
		__u64 advsimd : 1;
		__u64 advsimdhp : 1;
		__u64 gicv3v4 : 1;
		__u64 gicv41 : 1;
		__u64 ras : 1;
		__u64 pmuv3 : 1;
		__u64 pmuv3armv81 : 1;
		__u64 pmuv3armv84 : 1;
		__u64 pmuv3armv85 : 1;
		__u64 aes : 1;
		__u64 polymul : 1;
		__u64 sha1 : 1;
		__u64 sha256 : 1;
		__u64 sha512 : 1;
		__u64 crc32 : 1;
		__u64 atomic : 1;
		__u64 rdm : 1;
		__u64 sha3 : 1;
		__u64 sm3 : 1;
		__u64 sm4 : 1;
		__u64 dp : 1;
		__u64 fhm : 1;
		__u64 dccvap : 1;
		__u64 dccvadp : 1;
		__u64 apabase : 1;
		__u64 apaep : 1;
		__u64 apaep2 : 1;
		__u64 apaep2fp : 1;
		__u64 apaep2fpc : 1;
		__u64 jscvt : 1;
		__u64 fcma : 1;
		__u64 rcpcv83 : 1;
		__u64 rcpcv84 : 1;
		__u64 gpa : 1;
		__u64 l1ippipt : 1;
		__u64 dzpermitted : 1;
		__u64 reserved : 17;
	};
};

struct hv_partition_creation_properties {
	union hv_partition_processor_features disabled_processor_features;
} __packed;

union hv_intercept_parameters {
	__u64 as_uint64;
	__u16 exception_vector;
};

enum hv_intercept_type {
	HV_INTERCEPT_TYPE_EXCEPTION			= 0X00000003,
	HV_INTERCEPT_TYPE_REGISTER			= 0X00000004,
	HV_INTERCEPT_TYPE_MMIO				= 0X00000005,
	HV_INTERCEPT_TYPE_HYPERCALL			= 0X00000008,
	HV_INTERCEPT_MC_UPDATE_PATCH_LEVEL_MSR_READ	= 0X0000000A,
	HV_INTERCEPT_TYPE_MAX,
	HV_INTERCEPT_TYPE_INVALID			= 0XFFFFFFFF,
};

#define HV_PARTITION_SYNTHETIC_PROCESSOR_FEATURES_BANKS 1

union hv_partition_synthetic_processor_features {
	__u64 as_uint64[HV_PARTITION_SYNTHETIC_PROCESSOR_FEATURES_BANKS];

	struct {
		__u64 reserved_z0:1;
		__u64 reserved_z1:1;

		/* Access to HV_X64_MSR_VP_RUNTIME.
		 * Corresponds to access_vp_run_time_reg privilege.
		 */
		__u64 access_vp_run_time_reg:1;

		/* Access to HV_X64_MSR_TIME_REF_COUNT.
		 * Corresponds to access_partition_reference_counter privilege.
		 */
		__u64 access_partition_reference_counter:1;

		/* Access to SINT-related registers (HV_X64_MSR_SCONTROL through
		 * HV_X64_MSR_EOM and HV_X64_MSR_SINT0 through HV_X64_MSR_SINT15).
		 * Corresponds to access_synic_regs privilege.
		 */
		__u64 access_synic_regs:1;

		/* Access to synthetic timers and associated MSRs
		 * (HV_X64_MSR_STIMER0_CONFIG through HV_X64_MSR_STIMER3_COUNT).
		 * Corresponds to access_synthetic_timer_regs privilege.
		 */
		__u64 access_synthetic_timer_regs:1;

		/* Access to APIC MSRs (HV_X64_MSR_EOI, HV_X64_MSR_ICR and HV_X64_MSR_TPR)
		 * as well as the VP assist page.
		 * Corresponds to access_intr_ctrl_regs privilege.
		 */
		__u64 access_intr_ctrl_regs:1;

		/* Access to registers associated with hypercalls (HV_X64_MSR_GUEST_OS_ID
		 * and HV_X64_MSR_HYPERCALL).
		 * Corresponds to access_hypercall_msrs privilege.
		 */
		__u64 access_hypercall_regs:1;

		/* VP index can be queried. corresponds to access_vp_index privilege. */
		__u64 access_vp_index:1;

		/* Access to the reference TSC. Corresponds to access_partition_reference_tsc
		 * privilege.
		 */
		__u64 access_partition_reference_tsc:1;

		__u64 reserved_z10:1;

		/* Partition has access to frequency regs. corresponds to access_frequency_regs
		 * privilege.
		 */
		__u64 access_frequency_regs:1;

		__u64 reserved_z12:1; /* Reserved for access_reenlightenment_controls. */
		__u64 reserved_z13:1; /* Reserved for access_root_scheduler_reg. */
		__u64 reserved_z14:1; /* Reserved for access_tsc_invariant_controls. */
		__u64 reserved_z15:1;

		__u64 reserved_z16:1; /* Reserved for access_vsm. */
		__u64 reserved_z17:1; /* Reserved for access_vp_registers. */

		/* Use fast hypercall output. Corresponds to privilege. */
		__u64 fast_hypercall_output:1;

		__u64 reserved_z19:1; /* Reserved for enable_extended_hypercalls. */

		/*
		 * HvStartVirtualProcessor can be used to start virtual processors.
		 * Corresponds to privilege.
		 */
		__u64 start_virtual_processor:1;

		__u64 reserved_z21:1; /* Reserved for Isolation. */

		/* Synthetic timers in direct mode. */
		__u64 direct_synthetic_timers:1;

		__u64 reserved_z23:1; /* Reserved for synthetic time unhalted timer */

		/* Use extended processor masks. */
		__u64 extended_processor_masks:1;

		/* HvCallFlushVirtualAddressSpace / HvCallFlushVirtualAddressList are supported. */
		__u64 tb_flush_hypercalls:1;

		/* HvCallSendSyntheticClusterIpi is supported. */
		__u64 synthetic_cluster_ipi:1;

		/* HvCallNotifyLongSpinWait is supported. */
		__u64 notify_long_spin_wait:1;

		/* HvCallQueryNumaDistance is supported. */
		__u64 query_numa_distance:1;

		/* HvCallSignalEvent is supported. Corresponds to privilege. */
		__u64 signal_events:1;

		/* HvCallRetargetDeviceInterrupt is supported. */
		__u64 retarget_device_interrupt:1;

		__u64 reserved:33;
	} __packed;
};


enum hv_interrupt_type {
	HV_ARM64_INTERRUPT_TYPE_FIXED             = 0x0000
};

static inline bool hv_should_clear_interrupt(enum hv_interrupt_type type)
{
	return false;
}

static inline int hv_get_interrupt_vector_from_payload(__u64 payload)
{
	return 0;
}

#endif
