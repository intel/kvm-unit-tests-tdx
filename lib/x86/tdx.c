/*
 * TDX library
 *
 * Copyright (c) 2023, Intel Inc
 *
 * Authors:
 *   Zhenzhong Duan <zhenzhong.duan@intel.com>
 *   Qian Wen <qian.wen@intel.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "tdx.h"
#include "bitops.h"
#include "errno.h"
#include "x86/processor.h"
#include "x86/smp.h"

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

#define TDG_VP_VEINFO_GET	3

/* Port I/O direction */
#define PORT_READ	0
#define PORT_WRITE	1

/* See Exit Qualification for I/O Instructions in VMX documentation */
#define VE_IS_IO_IN(e)		((e) & BIT(3))
#define VE_GET_IO_SIZE(e)	(((e) & GENMASK(2, 0)) + 1)
#define VE_GET_PORT_NUM(e)	((e) >> 16)
#define VE_IS_IO_STRING(e)	((e) & BIT(4))

#define EXIT_REASON_CPUID		10
#define EXIT_REASON_HLT			12
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32

/*
 * Used by the #VE exception handler to gather the #VE exception
 * info from the TDX module. This is a software only structure
 * and not part of the TDX module/VMM ABI.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	/* Guest Linear (virtual) Address */
	u64 gla;
	/* Guest Physical Address */
	u64 gpa;
	u32 instr_len;
	u32 instr_info;
};

u64 __tdx_hypercall(struct tdx_module_args *args)
{
	/*
	 * For TDVMCALL explicitly set RCX to the bitmap of shared registers.
	 * The caller isn't expected to set @args->rcx anyway.
	 */
	args->rcx = TDVMCALL_EXPOSE_REGS_MASK;

	/*
	 * Failure of __tdcall_saved_ret() indicates a failure of the TDVMCALL
	 * mechanism itself and that something has gone horribly wrong with
	 * the TDX module, so panic.
	 */
	if (__tdcall_saved_ret(TDG_VP_VMCALL, args))
		abort();

	if (args->r10)
		printf("__tdx_hypercall err:\n"
		       "R10=0x%016lx, R11=0x%016lx, R12=0x%016lx\n"
		       "R13=0x%016lx, R14=0x%016lx, R15=0x%016lx\n",
		       args->r10, args->r11, args->r12, args->r13, args->r14,
		       args->r15);

	/* TDVMCALL leaf return code is in R10 */
	return args->r10;
}

/*
 * The TDG.VP.VMCALL-Instruction-execution sub-functions are defined
 * independently from but are currently matched 1:1 with VMX EXIT_REASONs.
 * Reusing the KVM EXIT_REASON macros makes it easier to connect the host and
 * guest sides of these calls.
 */
static __always_inline u64 hcall_func(u64 exit_reason)
{
	return exit_reason;
}

/*
 * The TDX module spec states that #VE may be injected for a limited set of
 * reasons:
 *
 *  - Emulation of the architectural #VE injection on EPT violation;
 *
 *  - As a result of guest TD execution of a disallowed instruction,
 *    a disallowed MSR access, or CPUID virtualization;
 *
 *  - A notification to the guest TD about anomalous behavior;
 *
 * The last one is opt-in and is not used by the kernel.
 *
 * The Intel Software Developer's Manual describes cases when instruction
 * length field can be used in section "Information for VM Exits Due to
 * Instruction Execution".
 *
 * For TDX, it ultimately means GET_VEINFO provides reliable instruction length
 * information if #VE occurred due to instruction execution, but not for EPT
 * violations.
 *
 * Currently, EPT violation caused #VE is not being included, as the patch set
 * has not yet provided MMIO related test cases for TDX.
 */
static int ve_instr_len(struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_IO_INSTRUCTION:
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
	case EXIT_REASON_CPUID:
	case EXIT_REASON_HLT:
		/* It is safe to use ve->instr_len for #VE due instructions */
		return ve->instr_len;
	default:
		printf("WARNING: Unexpected #VE-type: %ld\n", ve->exit_reason);
		return ve->instr_len;
	}
}

bool is_tdx_guest(void)
{
	static int tdx_guest = -1;

	if (tdx_guest < 0) {
		struct cpuid c;
		u32 sig[3];

		c = cpuid(TDX_CPUID_LEAF_ID);
		sig[0] = c.b;
		sig[1] = c.d;
		sig[2] = c.c;

		tdx_guest = !memcmp(TDX_IDENT, sig, sizeof(sig));
	}

	return !!tdx_guest;
}

static bool handle_in(struct ex_regs *regs, int size, int port)
{
	struct tdx_module_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_IO_INSTRUCTION),
		.r12 = size,
		.r13 = PORT_READ,
		.r14 = port,
	};
	u64 mask = GENMASK(BITS_PER_BYTE * size - 1, 0);
	bool success;

	/*
	 * Emulate the I/O read via hypercall. More info about ABI can be found
	 * in TDX Guest-Host-Communication Interface (GHCI) section titled
	 * "TDG.VP.VMCALL<Instruction.IO>".
	 */
	success = !__tdx_hypercall(&args);

	/* Update part of the register affected by the emulated instruction */
	regs->rax &= ~mask;
	if (success)
		regs->rax |= args.r11 & mask;

	return success;
}

static bool handle_out(struct ex_regs *regs, int size, int port)
{
	u64 mask = GENMASK(BITS_PER_BYTE * size - 1, 0);
	struct tdx_module_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_IO_INSTRUCTION),
		.r12 = size,
		.r13 = PORT_WRITE,
		.r14 = port,
		.r15 = regs->rax & mask,
	};

	/*
	 * Emulate the I/O write via hypercall. More info about ABI can be found
	 * in TDX Guest-Host-Communication Interface (GHCI) section titled
	 * "TDG.VP.VMCALL<Instruction.IO>".
	 */
	return !__tdx_hypercall(&args);
}

/*
 * Emulate I/O using hypercall.
 *
 * Assumes the IO instruction was using ax, which is enforced
 * by the standard io.h macros.
 *
 * Return True on success or False on failure.
 */
static int handle_io(struct ex_regs *regs, struct ve_info *ve)
{
	u32 exit_qual = ve->exit_qual;
	int size, port;
	bool in, ret;

	if (VE_IS_IO_STRING(exit_qual))
		return -EIO;

	in   = VE_IS_IO_IN(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);


	if (in)
		ret = handle_in(regs, size, port);
	else
		ret = handle_out(regs, size, port);
	if (!ret)
		return -EIO;

	return ve_instr_len(ve);
}

static int handle_read_msr(struct ex_regs *regs, struct ve_info *ve)
{
	struct tdx_module_args args = {
	       .r10 = TDX_HYPERCALL_STANDARD,
	       .r11 = hcall_func(EXIT_REASON_MSR_READ),
	       .r12 = regs->rcx,
	};

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "TDG.VP.VMCALL<Instruction.RDMSR>".
	 */
	if (__tdx_hypercall(&args))
		return -EIO;

	regs->rax = lower_32_bits(args.r11);
	regs->rdx = upper_32_bits(args.r11);
	return ve_instr_len(ve);
}

static int handle_write_msr(struct ex_regs *regs, struct ve_info *ve)
{
	struct tdx_module_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_MSR_WRITE),
		.r12 = regs->rcx,
		.r13 = (u64)regs->rdx << 32 | regs->rax,
	};

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) section titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	if (__tdx_hypercall(&args))
		return -EIO;

	return ve_instr_len(ve);
}

static int handle_cpuid(struct ex_regs *regs, struct ve_info *ve)
{
	struct tdx_module_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_CPUID),
		.r12 = regs->rax,
		.r13 = regs->rcx,
	};

	/*
	 * Only allow VMM to control range reserved for hypervisor
	 * communication.
	 *
	 * Return all-zeros for any CPUID outside the range. It matches CPU
	 * behaviour for non-supported leaf.
	 */
	if (regs->rax < 0x40000000 || regs->rax > 0x4FFFFFFF) {
		regs->rax = regs->rbx = regs->rcx = regs->rdx = 0;
		return ve_instr_len(ve);
	}

	/*
	 * Emulate the CPUID instruction via a hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (__tdx_hypercall(&args))
		return -EIO;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contain contents of
	 * EAX, EBX, ECX, EDX registers after the CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->rax = args.r12;
	regs->rbx = args.r13;
	regs->rcx = args.r14;
	regs->rdx = args.r15;

	return ve_instr_len(ve);
}

static int handle_halt(struct ex_regs *regs, struct ve_info *ve)
{
	struct tdx_module_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_HLT),
		/*
		  r12 = 1: interrupt is blocking
		  r12 = 0: no interrupt blocking
		 */
		.r12 = !(regs->rflags & X86_EFLAGS_IF),
	};

	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 */
	if (__tdx_hypercall(&args))
		return -EIO;

	return ve_instr_len(ve);
}

static bool tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_args args = {};
	u64 ret;

	if (!ve)
		return false;

	/*
	 * NMIs and machine checks are suppressed. Before this point any
	 * #VE is fatal. After this point (TDGETVEINFO call), NMIs and
	 * additional #VEs are permitted (but it is expected not to
	 * happen unless kernel panics).
	 */
	ret = __tdcall_ret(TDG_VP_VEINFO_GET, &args);
	if (ret)
		return false;

	ve->exit_reason = args.rcx;
	ve->exit_qual	= args.rdx;
	ve->gla		= args.r8;
	ve->gpa		= args.r9;
	ve->instr_len	= args.r10 & UINT_MAX;
	ve->instr_info	= args.r10 >> 32;

	return true;
}

static bool tdx_handle_virt_exception(struct ex_regs *regs,
		struct ve_info *ve)
{
	int insn_len;

	/* #VE exit_reason in bit16-32 */
	this_cpu_write_exception_vector(regs->vector);
	this_cpu_write_exception_rflags_rf(!!(regs->rflags & X86_EFLAGS_RF));
	this_cpu_write_exception_error_code(regs->error_code);

	switch (ve->exit_reason) {
	case EXIT_REASON_IO_INSTRUCTION:
		insn_len = handle_io(regs, ve);
		break;
	case EXIT_REASON_MSR_READ:
		insn_len = handle_read_msr(regs, ve);
		break;
	case EXIT_REASON_MSR_WRITE:
		insn_len = handle_write_msr(regs, ve);
		break;
	case EXIT_REASON_CPUID:
		insn_len = handle_cpuid(regs, ve);
		break;
	case EXIT_REASON_HLT:
		insn_len = handle_halt(regs, ve);
		break;
	default:
		insn_len = -EIO;
		printf("WARNING: Unexpected #VE: %ld\n", ve->exit_reason);
		return false;
	}

	if (insn_len < 0)
		return false;

	/* After successful #VE handling, move the IP */
	regs->rip += insn_len;

	return true;
}

/* #VE exception handler. */
static void tdx_handle_ve(struct ex_regs *regs)
{
	struct ve_info ve;

	if (!tdx_get_ve_info(&ve)) {
		printf("tdx_get_ve_info failed\n");
		return;
	}

	tdx_handle_virt_exception(regs, &ve);
}

efi_status_t setup_tdx(void)
{
	if (!is_tdx_guest())
		return EFI_UNSUPPORTED;

	/*
	 * IO instructions from printf() cause #VE, it works
	 * on boot stage here because default #VE handler
	 * installed by firmware TDVF.
	 */
	printf("Detected TDX.\n");

	handle_exception(VE_VECTOR, tdx_handle_ve);

	return EFI_SUCCESS;
}
