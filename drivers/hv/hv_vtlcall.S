/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Authors:
 *   Hernan Gatta <hegatta@microsoft.com>
 *
 */

#include <linux/linkage.h>
#include <asm/frame.h>
#include <asm/nospec-branch.h>

.text

#
# void hv_vsm_vtl_call(struct vtlcall_param *args);
#

SYM_FUNC_START(hv_vsm_vtl_call)
	FRAME_BEGIN

	#
	# Upon entry into this function, RDI holds a pointer to a
	# vtlcall_param structure (vtlcall_param), according to the System V AMD64 ABI
	# calling convention.
	#

	#
	# Keep copies of the registers we modify.
	#
	# TODO: Do we need to keep them all, or are some considered scratch?
	#

	push    %rcx
	push    %rdi
	push    %rsi
	push    %rdx
	push    %rbx
	mov     %r8,  %rax             # R8 cannot be saved with a push directly.
	push    %rax
	mov     %r9,  %rax             # Idem.
	push    %rax
	mov     %r10, %rax             # Idem.
	push    %rax
	mov     %r11, %rax             # Idem.
	push    %rax
	mov     %r12, %rax             # Idem.
	push    %rax
	mov     %r13, %rax             # Idem.
	push    %rax
	mov     %r14, %rax             # Idem.
	push    %rax
	mov     %r15, %rax             # Idem.
	push    %rax

	#
	# RDI is modified below, so copy it into a register that stays constant in
	# the instructon block immediately following.
	#

	mov     %rdi, %rcx

	#
	# Copy the values of the vtlcall_param structure off the pointer we
	# got to it from this function's single parameter into the registers used
	# to communicate with VTL 1.
	#

	mov     0x00(%rcx), %rdi
	mov     0x08(%rcx), %rsi
	mov     0x10(%rcx), %rdx
	mov     0x18(%rcx), %rbx

	#
	# Keep a copy of the current value of RCX, which must be modified to
	# communicate the function ID for the VMCALL to Hyper-V.
	#
	# TODO: This might become obsolete when we finally use the VSM code page to
	#       perform VTL Calls.
	#

	push    %rcx

	# RAX: Holds the VTL Switch Input (Control)
	# RCX: Holds the VM Function ID
	#
	# The Control value must be zero.
	# The Function ID for VTLCALL is 0x11.

	mov     $0x00, %rax
	mov     $0x11, %rcx

	#
	# VTL Call
	#

	vmcall

	#
	# Restore the previous value of RCX.
	#

	pop     %rcx

	#
	# VTL 1 might have modified any of the registers used to communicate with
	# it, so copy their values into the vtlcall_param structure. When
	# this function returns, anyone with a pointer to the structure can read
	# these values.
	#

	mov     %rdi,  0x00(%rcx)
	mov     %rsi,  0x08(%rcx)
	mov     %rdx,  0x10(%rcx)
	mov     %rbx,  0x18(%rcx)

	#
	# Restore all modified registers.
	#

	pop     %rax
	mov     %rax, %r15             # R15 cannot be restored with a pop directly.
	pop     %rax
	mov     %rax, %r14             # Idem.
	pop     %rax
	mov     %rax, %r13             # Idem.
	pop     %rax
	mov     %rax, %r12             # Idem.
	pop     %rax
	mov     %rax, %r11             # Idem.
	pop     %rax
	mov     %rax, %r10             # Idem.
	pop     %rax
	mov     %rax, %r9              # Idem.
	pop     %rax
	mov     %rax, %r8              # Idem.
	pop     %rbx
	pop     %rdx
	pop     %rsi
	pop     %rdi
	pop     %rcx

	FRAME_END
	ret
SYM_FUNC_END(hv_vsm_vtl_call)
