// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Microsoft, Inc.
 *
 * Author : Roman Kisel <romank@microsoft.com>
 */

#include <asm/boot.h>
#include <asm/mshyperv.h>
#include <asm/cpu_ops.h>

void hv_vtl_return(struct hv_vtl_cpu_context *vtl0, u32 flags, u64 vtl_return_offset)
{
	u64 register x18 asm("x18");

	x18 = (u64)vtl0->x;
	/*
	 * Not ABI-aware VTL switch as gcc doesn't allow more than 30 operands in asm() due to
	 * operands using the '+' constraint modifier counting as two operands (that is, both as
	 * input and output).
	 * x18 aka IP0 is non-shared. The compiler is told it is used inside this function, so
	 * it can be saved and restored around the asm() block if there is a need to use it.
	 */
	asm __volatile__ (
		/* Volatile registers in AAPSC64 */
		"ldp x0, x1, [x18]\n\t"
		"ldp x2, x3, [x18, #(2*8)]\n\t"
		"ldp x4, x5, [x18, #(4*8)]\n\t"
		"ldp x6, x7, [x18, #(6*8)]\n\t"
		"ldp x8, x9, [x18, #(8*8)]\n\t"
		"ldp x10, x11, [x18, #(10*8)]\n\t"
		"ldp x12, x13, [x18, #(12*8)]\n\t"
		"ldp x14, x15, [x18, #(14*8)]\n\t"
		"ldp x16, x17, [x18, #(16*8)]\n\t"

		/* Non-volatile registers in AAPSC64 */
		"ldp x19, x20, [x18, #(19*8)]\n\t"
		"ldp x21, x22, [x18, #(21*8)]\n\t"
		"ldp x23, x24, [x18, #(23*8)]\n\t"
		"ldp x25, x26, [x18, #(25*8)]\n\t"
		"ldp x27, x28, [x18, #(27*8)]\n\t"
		"ldp x29, x30, [x18, #(29*8)]\n\t"

		/* Floating point registers */
		"ldp q0, q1, [x18, #(16*2*8)]\n\t"
		"ldp q2, q3, [x18, #(18*16)]\n\t"
		"ldp q4, q5, [x18, #(20*16)]\n\t"
		"ldp q6, q7, [x18, #(22*16)]\n\t"
		"ldp q8, q9, [x18, #(24*16)]\n\t"
		"ldp q10, q11, [x18, #(26*16)]\n\t"
		"ldp q12, q13, [x18, #(28*16)]\n\t"
		"ldp q14, q15, [x18, #(30*16)]\n\t"
		"ldp q16, q17, [x18, #(32*16)]\n\t"
		"ldp q18, q19, [x18, #(34*16)]\n\t"
		"ldp q20, q21, [x18, #(36*16)]\n\t"
		"ldp q22, q23, [x18, #(38*16)]\n\t"
		"ldp q24, q25, [x18, #(40*16)]\n\t"
		"ldp q26, q27, [x18, #(42*16)]\n\t"
		"ldp q28, q29, [x18, #(44*16)]\n\t"
		"ldp q30, q31, [x18, #(46*16)]\n\t"

		/* Return to the lower VTL */
		"hvc #3\n\t"

		/* Volatile registers in AAPSC64 */
		"stp x0, x1, [x18]\n\t"
		"stp x2, x3, [x18, #(2*8)]\n\t"
		"stp x4, x5, [x18, #(4*8)]\n\t"
		"stp x6, x7, [x18, #(6*8)]\n\t"
		"stp x8, x9, [x18, #(8*8)]\n\t"
		"stp x10, x11, [x18, #(10*8)]\n\t"
		"stp x12, x13, [x18, #(12*8)]\n\t"
		"stp x14, x15, [x18, #(14*8)]\n\t"
		"stp x16, x17, [x18, #(16*8)]\n\t"

		/* Non-volatile registers in AAPSC64 */
		"stp x19, x20, [x18, #(19*8)]\n\t"
		"stp x21, x22, [x18, #(21*8)]\n\t"
		"stp x23, x24, [x18, #(23*8)]\n\t"
		"stp x25, x26, [x18, #(25*8)]\n\t"
		"stp x27, x28, [x18, #(27*8)]\n\t"
		"stp x29, x30, [x18, #(29*8)]\n\t"

		/* Floating point registers */
		"stp q0, q1, [x18, #(16*2*8)]\n\t"
		"stp q2, q3, [x18, #(18*16)]\n\t"
		"stp q4, q5, [x18, #(20*16)]\n\t"
		"stp q6, q7, [x18, #(22*16)]\n\t"
		"stp q8, q9, [x18, #(24*16)]\n\t"
		"stp q10, q11, [x18, #(26*16)]\n\t"
		"stp q12, q13, [x18, #(28*16)]\n\t"
		"stp q14, q15, [x18, #(30*16)]\n\t"
		"stp q16, q17, [x18, #(32*16)]\n\t"
		"stp q18, q19, [x18, #(34*16)]\n\t"
		"stp q20, q21, [x18, #(36*16)]\n\t"
		"stp q22, q23, [x18, #(38*16)]\n\t"
		"stp q24, q25, [x18, #(40*16)]\n\t"
		"stp q26, q27, [x18, #(42*16)]\n\t"
		"stp q28, q29, [x18, #(44*16)]\n\t"
		"stp q30, q31, [x18, #(46*16)]\n\t"

		: /* No outputs */
		: /* Input */ "r"(x18)
		: /* Clobber list*/
		"memory", "cc",
		"x0", "x1", "x2", "x3", "x4", "x5",
		"x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
		"x14", "x15", "x16", "x17", "x19", "x20", "x21",
		"x22", "x23", "x24", "x25", "x26", "x27", "x28",
		"x29", "x30", "q0", "q1", "q2", "q3", "q4", "q5",
		"q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13",
		"q14", "q15", "q16", "q17", "q18", "q19", "q20",
		"q21", "q22", "q23", "q24", "q25", "q26", "q27",
		"q28", "q29", "q30", "q31");
}
EXPORT_SYMBOL_GPL(hv_vtl_return);

void __init hv_vtl_init_platform(void)
{
	pr_info("Linux runs in Hyper-V Virtual Trust Level\n");
}

int __init hv_vtl_early_init(void)
{
	return 0;
}
early_initcall(hv_vtl_early_init);
