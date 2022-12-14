/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_X64_MSHV_VTL_H
#define __ASM_X64_MSHV_VTL_H

#include <linux/mshv.h>
#include <linux/types.h>
#include <asm/fpu/types.h>

struct mshv_ram_disposition {
	__u64 start_pfn;
	__u64 last_pfn;
} __packed;

struct mshv_set_poll_file {
	__u32 cpu;
	__u32 fd;
} __packed;

struct mshv_cpu_context {
	union {
		struct {
			__u64 rax;
			__u64 rcx;
			__u64 rdx;
			__u64 rbx;
			__u64 cr2;
			__u64 rbp;
			__u64 rsi;
			__u64 rdi;
			__u64 r8;
			__u64 r9;
			__u64 r10;
			__u64 r11;
			__u64 r12;
			__u64 r13;
			__u64 r14;
			__u64 r15;
		};
		__u64 gp_regs[16];
	};

	struct fxregs_state fx_state;
};

struct mshv_vtl_run {
	__u32 cancel;
	__u32 vtl_ret_action_size;
	__u32 pad[2];
	char exit_message[MAX_RUN_MSG_SIZE];
	union {
		struct mshv_cpu_context cpu_context;

		/*
		 * Reserving room for the cpu context to grow and be
		 * able to maintain compat with user mode.
		 */
		char reserved[1024];
	};
	char vtl_ret_actions[MAX_RUN_MSG_SIZE];
};

#endif /* __ASM_X64_MSHV_VTL_H */