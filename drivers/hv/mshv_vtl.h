/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _MSHV_VTL_H
#define _MSHV_VTL_H

#include <linux/mshv.h>
#include <linux/types.h>
#include <asm/mshyperv.h>

#define MSHV_ENTRY_REASON_LOWER_VTL_CALL     0x1
#define MSHV_ENTRY_REASON_INTERRUPT          0x2
#define MSHV_ENTRY_REASON_INTERCEPT          0x3

struct mshv_vtl_run {
	u32 cancel;
	u32 vtl_ret_action_size;
	__u32 flags;
	__u8 scan_proxy_irr;
	__u8 pad[2];
	__u8 enter_mode;
	char exit_message[MAX_RUN_MSG_SIZE];
	union {
		struct hv_vtl_cpu_context cpu_context;

		/*
		 * Reserving room for the cpu context to grow and be
		 * able to maintain compat with user mode.
		 */
		char reserved[1024];
	};
	char vtl_ret_actions[MAX_RUN_MSG_SIZE];
};

union hv_register_vsm_page_offsets {
	struct {
		u64 vtl_call_offset : 12;
		u64 vtl_return_offset : 12;
		u64 reserved_mbz : 40;
	};
	u64 as_uint64;
} __packed;

#endif /* _MSHV_VTL_H */
