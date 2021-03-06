/*
 * Low level API for tdcall and tdvmcall
 *
 * Copyright (c) 2022, Intel Inc
 *
 * Authors:
 *   Zhenzhong Duan <zhenzhong.duan@intel.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <errno.h>

#define ARG7_SP_OFFSET		0x08

#define TDX_MODULE_rcx		0x0
#define TDX_MODULE_rdx		0x8
#define TDX_MODULE_r8		0x10
#define TDX_MODULE_r9		0x18
#define TDX_MODULE_r10		0x20
#define TDX_MODULE_r11		0x28

#define TDX_HYPERCALL_r10	0x0
#define TDX_HYPERCALL_r11	0x8
#define TDX_HYPERCALL_r12	0x10
#define TDX_HYPERCALL_r13	0x18
#define TDX_HYPERCALL_r14	0x20
#define TDX_HYPERCALL_r15	0x28

/*
 * Expose registers R10-R15 to VMM. It is passed via RCX register
 * to the TDX Module, which will be used by the TDX module to
 * identify the list of registers exposed to VMM. Each bit in this
 * mask represents a register ID. Bit field details can be found
 * in TDX GHCI specification.
 */
#define TDVMCALL_EXPOSE_REGS_MASK	0xfc00

/*
 * TDX guests use the TDCALL instruction to make requests to the
 * TDX module and hypercalls to the VMM. It is supported in
 * Binutils >= 2.36.
 */
#define tdcall .byte 0x66,0x0f,0x01,0xcc

/* HLT TDVMCALL sub-function ID */
#define EXIT_REASON_HLT		12

/*
 * __tdx_module_call()  - Helper function used by TDX guests to request
 * services from the TDX module (does not include VMM services).
 *
 * This function serves as a wrapper to move user call arguments to the
 * correct registers as specified by TDCALL ABI and share it with the
 * TDX module. If the TDCALL operation is successful and a valid
 * "struct tdx_module_output" pointer is available (in "out" argument),
 * output from the TDX module is saved to the memory specified in the
 * "out" pointer. Also the status of the TDCALL operation is returned
 * back to the user as a function return value.
 *
 *-------------------------------------------------------------------------
 * TDCALL ABI:
 *-------------------------------------------------------------------------
 * Input Registers:
 *
 * RAX                 - TDCALL Leaf number.
 * RCX,RDX,R8-R9       - TDCALL Leaf specific input registers.
 *
 * Output Registers:
 *
 * RAX                 - TDCALL instruction error code.
 * RCX,RDX,R8-R11      - TDCALL Leaf specific output registers.
 *
 *-------------------------------------------------------------------------
 *
 * __tdx_module_call() function ABI:
 *
 * @fn  (RDI)          - TDCALL Leaf ID,    moved to RAX
 * @rcx (RSI)          - Input parameter 1, moved to RCX
 * @rdx (RDX)          - Input parameter 2, moved to RDX
 * @r8  (RCX)          - Input parameter 3, moved to R8
 * @r9  (R8)           - Input parameter 4, moved to R9
 *
 * @out (R9)           - struct tdx_module_output pointer
 *                       stored temporarily in R12 (not
 *                       shared with the TDX module). It
 *                       can be NULL.
 *
 * Return status of TDCALL via RAX.
 */
.global __tdx_module_call
__tdx_module_call:
	/*
	 * R12 will be used as temporary storage for
	 * struct tdx_module_output pointer. More
	 * details about struct tdx_module_output can
	 * be found in arch/x86/include/asm/tdx.h. Also
	 * note that registers R12-R15 are not used by
	 * TDCALL services supported by this helper
	 * function.
	 */

	/* Callee saved, so preserve it */
	push %r12

	/*
	 * Push output pointer to stack, after TDCALL operation,
	 * it will be fetched into R12 register.
	 */
	push %r9

	/* Mangle function call ABI into TDCALL ABI: */
	/* Move TDCALL Leaf ID to RAX */
	mov %rdi, %rax
	/* Move input 4 to R9 */
	mov %r8,  %r9
	/* Move input 3 to R8 */
	mov %rcx, %r8
	/* Move input 1 to RCX */
	mov %rsi, %rcx
	/* Leave input param 2 in RDX */

	tdcall

	/* Fetch output pointer from stack to R12 */
	pop %r12

	/* Check for TDCALL success: 0 - Successful, otherwise failed */
	test %rax, %rax
	jnz 1f

	/*
	 * __tdx_module_call() can be initiated without an output pointer.
	 * So, check if caller provided an output struct before storing
	 * output registers.
	 */
	test %r12, %r12
	jz 1f

	/* Copy TDCALL result registers to output struct: */
	movq %rcx, TDX_MODULE_rcx(%r12)
	movq %rdx, TDX_MODULE_rdx(%r12)
	movq %r8,  TDX_MODULE_r8(%r12)
	movq %r9,  TDX_MODULE_r9(%r12)
	movq %r10, TDX_MODULE_r10(%r12)
	movq %r11, TDX_MODULE_r11(%r12)
1:
	/* Restore the state of R12 register */
	pop %r12
	ret

/*
 * __tdx_hypercall()  - Helper function used by TDX guests to request
 * services from the VMM. All requests are made via the TDX module
 * using TDCALL instruction.
 *
 * This function serves as a wrapper to move user call arguments to the
 * correct registers as specified by TDCALL ABI and share it with VMM
 * via the TDX module. After TDCALL operation, output from the VMM is
 * saved to the memory specified in the "out" (struct tdx_hypercall_output)
 * pointer.
 *
 *-------------------------------------------------------------------------
 * TD VMCALL ABI:
 *-------------------------------------------------------------------------
 *
 * Input Registers:
 *
 * RAX                 - TDCALL instruction leaf number (0 - TDG.VP.VMCALL)
 * RCX                 - BITMAP which controls which part of TD Guest GPR
 *                       is passed as-is to VMM and back.
 * R10                 - Set 0 to indicate TDCALL follows standard TDX ABI
 *                       specification. Non zero value indicates vendor
 *                       specific ABI.
 * R11                 - VMCALL sub function number
 * RBX, RBP, RDI, RSI  - Used to pass VMCALL sub function specific arguments.
 * R8-R9, R12-R15      - Same as above.
 *
 * Output Registers:
 *
 * RAX                 - TDCALL instruction status (Not related to hypercall
 *                        output).
 * R10                 - Hypercall output error code.
 * R11-R15             - Hypercall sub function specific output values.
 *
 *-------------------------------------------------------------------------
 *
 * __tdx_hypercall() function ABI:
 *
 * @type  (RDI)        - TD VMCALL type, moved to R10
 * @fn    (RSI)        - TD VMCALL sub function, moved to R11
 * @r12   (RDX)        - Input parameter 1, moved to R12
 * @r13   (RCX)        - Input parameter 2, moved to R13
 * @r14   (R8)         - Input parameter 3, moved to R14
 * @r15   (R9)         - Input parameter 4, moved to R15
 *
 * @out   (stack)      - struct tdx_hypercall_output pointer (cannot be NULL)
 *
 * On successful completion, return TDCALL status or -EINVAL for invalid
 * inputs.
 */
.globl __tdx_hypercall
__tdx_hypercall:
	/* Move argument 7 from caller stack to RAX */
	movq ARG7_SP_OFFSET(%rsp), %rax

	/* Check if caller provided an output struct */
	test %rax, %rax
	/* If out pointer is NULL, return -EINVAL */
	jz 1f

	/* Save callee-saved GPRs as mandated by the x86_64 ABI */
	push %r15
	push %r14
	push %r13
	push %r12

	/*
	 * Save output pointer (rax) in stack, it will be used
	 * again when storing the output registers after TDCALL
	 * operation.
	 */
	push %rax

	/* Mangle function call ABI into TDCALL ABI: */
	/* Set TDCALL leaf ID (TDVMCALL (0)) in RAX */
	xor %eax, %eax
	/* Move TDVMCALL type (standard vs vendor) in R10 */
	mov %rdi, %r10
	/* Move TDVMCALL sub function id to R11 */
	mov %rsi, %r11
	/* Move input 1 to R12 */
	mov %rdx, %r12
	/* Move input 2 to R13 */
	mov %rcx, %r13
	/* Move input 3 to R14 */
	mov %r8,  %r14
	/* Move input 4 to R15 */
	mov %r9,  %r15

	movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx

	/*
	 * For the idle loop STI needs to be called directly before
	 * the TDCALL that enters idle (EXIT_REASON_HLT case). STI
	 * enables interrupts only one instruction later. If there
	 * are any instructions between the STI and the TDCALL for
	 * HLT then an interrupt could happen in that time, but the
	 * code would go back to sleep afterwards, which can cause
	 * longer delays.
	 *
	 * This leads to significant difference in network performance
	 * benchmarks. So add a special case for EXIT_REASON_HLT to
	 * trigger STI before TDCALL. But this change is not required
	 * for all HLT cases. So use R15 register value to identify the
	 * case which needs STI. So, if R11 is EXIT_REASON_HLT and R15
	 * is 1, then call STI before TDCALL instruction. Note that R15
	 * register is not required by TDCALL ABI when triggering the
	 * hypercall for EXIT_REASON_HLT case. So use it in software to
	 * select the STI case.
	 */
	cmpl $EXIT_REASON_HLT, %r11d
	jne skip_sti
	cmpl $1, %r15d
	jne skip_sti
	/* Set R15 register to 0, it is unused in EXIT_REASON_HLT case */
	xor %r15, %r15
	sti
skip_sti:
	tdcall

	/* Restore output pointer to R9 */
	pop  %r9

	/* Copy hypercall result registers to output struct: */
	movq %r10, TDX_HYPERCALL_r10(%r9)
	movq %r11, TDX_HYPERCALL_r11(%r9)
	movq %r12, TDX_HYPERCALL_r12(%r9)
	movq %r13, TDX_HYPERCALL_r13(%r9)
	movq %r14, TDX_HYPERCALL_r14(%r9)
	movq %r15, TDX_HYPERCALL_r15(%r9)

	/*
	 * Zero out registers exposed to the VMM to avoid
	 * speculative execution with VMM-controlled values.
	 * This needs to include all registers present in
	 * TDVMCALL_EXPOSE_REGS_MASK (except R12-R15).
	 * R12-R15 context will be restored.
	 */
	xor %r10d, %r10d
	xor %r11d, %r11d

	/* Restore callee-saved GPRs as mandated by the x86_64 ABI */
	pop %r12
	pop %r13
	pop %r14
	pop %r15

	jmp 2f
1:
	movq $-EINVAL, %rax
2:
	retq
