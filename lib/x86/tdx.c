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
#include "errno.h"
#include "bitops.h"
#include "errno.h"
#include "x86/processor.h"
#include "x86/smp.h"
#include "asm/page.h"

/* Port I/O direction */
#define PORT_READ	0
#define PORT_WRITE	1

/* See Exit Qualification for I/O Instructions in VMX documentation */
#define VE_IS_IO_IN(e)		((e) & BIT(3))
#define VE_GET_IO_SIZE(e)	(((e) & GENMASK(2, 0)) + 1)
#define VE_GET_PORT_NUM(e)	((e) >> 16)
#define VE_IS_IO_STRING(e)	((e) & BIT(4))


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
	 * the TDX module.
	 */
	if (__tdcall_saved_ret(TDG_VP_VMCALL, args)) {
		/* Non zero return value indicates buggy TDX module, so panic */
		BUG_ON(1);
	}

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
	case EXIT_REASON_HLT:
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
	case EXIT_REASON_CPUID:
	case EXIT_REASON_IO_INSTRUCTION:
		/* It is safe to use ve->instr_len for #VE due instructions */
		return ve->instr_len;
	default:
		printf("WARNING: Unexpected #VE-type: %ld\n", ve->exit_reason);
		return ve->instr_len;
	}
}

static int handle_halt(struct ex_regs *regs, struct ve_info *ve)
{
	struct tdx_module_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_HLT),
		.r12 = !!(regs->rflags & X86_EFLAGS_IF),
	};

	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of the TD guest and to determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled, the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 */
	if (__tdx_hypercall(&args))
		/* Bypass failed hlt is better than hang */
		printf("WARNING: HLT instruction emulation failed\n");

	return ve_instr_len(ve);
}

static int read_msr(struct ex_regs *regs, struct ve_info *ve)
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

static bool tdx_is_bypassed_msr(u32 index)
{
	switch (index) {
	case MSR_IA32_TSC:
	case MSR_IA32_APICBASE:
	case MSR_EFER:
		return true;
	default:
		return false;
	}
}

static int write_msr(struct ex_regs *regs, struct ve_info *ve)
{
	if (tdx_is_bypassed_msr(regs->rcx))
		goto finish_wrmsr;

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

finish_wrmsr:
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

static bool handle_in(struct ex_regs *regs, int size, int port)
{
	struct tdx_module_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_IO_INSTRUCTION),
		.r12 = size,
		.r13 = PORT_READ,
		.r14 = port,
	};
	u64 mask = GENMASK(BITS_PER_BYTE * size, 0);
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
	u64 mask = GENMASK(BITS_PER_BYTE * size, 0);

	/*
	 * Emulate the I/O write via hypercall. More info about ABI can be found
	 * in TDX Guest-Host-Communication Interface (GHCI) section titled
	 * "TDG.VP.VMCALL<Instruction.IO>".
	 */
	return !_tdx_hypercall(hcall_func(EXIT_REASON_IO_INSTRUCTION), size,
			       PORT_WRITE, port, regs->rax & mask);
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

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info;

/* The highest bit of a guest physical address is the "sharing" bit */
phys_addr_t tdx_shared_mask(void)
{
	return 1ULL << (td_info.gpa_width - 1);
}

static void tdx_get_info(void)
{
	struct tdx_module_args args = {};
	u64 ret;

	/*
	 * TDINFO TDX module call is used to get the TD execution environment
	 * information like GPA width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), section 2.4.2 TDCALL
	 * [TDG.VP.INFO].
	 */
	ret = __tdcall_ret(TDG_VP_INFO, &args);

	/*
	 * Non zero return means buggy TDX module (which is
	 * fatal). So raise a BUG().
	 */
	BUG_ON(ret);

	td_info.gpa_width = args.rcx & GENMASK(5, 0);
	td_info.attributes = args.rdx;
}

bool is_tdx_guest(void)
{
	static int tdx_guest = -1;
	struct cpuid c;
	u32 sig[3];

	if (tdx_guest >= 0)
		goto done;

	if (cpuid(0).a < TDX_CPUID_LEAF_ID) {
		tdx_guest = 0;
		goto done;
	}

	c = cpuid(TDX_CPUID_LEAF_ID);
	sig[0] = c.b;
	sig[1] = c.d;
	sig[2] = c.c;

	tdx_guest = !memcmp(TDX_IDENT, sig, sizeof(sig));

done:
	return !!tdx_guest;
}

static bool tdx_check_exception_table(struct ex_regs *regs)
{
	struct ex_record *ex;

	for (ex = &exception_table_start; ex != &exception_table_end; ++ex) {
		if (ex->rip == regs->rip) {
			regs->rip = ex->handler;
			return true;
		}
	}
	unhandled_exception(regs, false);

	/* never reached */
	return false;
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
	unsigned int ex_val;
	int insn_len = -EIO;

	/* #VE exit_reason in bit16-32 */
	ex_val = regs->vector | (ve->exit_reason << 16);
	asm("mov %0, %%gs:4" : : "r"(ex_val));

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		insn_len = handle_halt(regs, ve);
		break;
	case EXIT_REASON_MSR_READ:
		insn_len = read_msr(regs, ve);
		break;
	case EXIT_REASON_MSR_WRITE:
		insn_len = write_msr(regs, ve);
		break;
	case EXIT_REASON_CPUID:
		insn_len = handle_cpuid(regs, ve);
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		insn_len = handle_io(regs, ve);
		break;
	default:
		printf("WARNING: Unexpected #VE: %ld\n", ve->exit_reason);
		return false;
	}
	if (insn_len < 0)
		return tdx_check_exception_table(regs);

	/* After successful #VE handling, move the IP */
	regs->rip += insn_len;
	/* Simulate single step on simulated instruction */
	if (regs->rflags & X86_EFLAGS_TF) {
		regs->vector = DB_VECTOR;
		write_dr6(read_dr6() | (1 << 14));
		do_handle_exception(regs);
	}

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

static unsigned long try_accept_one(phys_addr_t start, unsigned long len,
				    enum pg_level pg_level)
{
	unsigned long accept_size = page_level_size(pg_level);
	struct tdx_module_args args = {};
	u8 page_size;

	if (!IS_ALIGNED(start, accept_size))
		return 0;

	if (len < accept_size)
		return 0;

	/*
	 * Pass the page physical address to the TDX module to accept the
	 * pending, private page.
	 *
	 * Bits 2:0 of RCX encode page size: 0 - 4K, 1 - 2M, 2 - 1G.
	 */
	switch (pg_level) {
	case PG_LEVEL_4K:
		page_size = TDX_PS_4K;
		break;
	case PG_LEVEL_2M:
		page_size = TDX_PS_2M;
		break;
	case PG_LEVEL_1G:
		page_size = TDX_PS_1G;
		break;
	default:
		return 0;
	}

	args.rcx = start | page_size;
	if (__tdcall(TDG_MEM_PAGE_ACCEPT, &args))
		return 0;

	return accept_size;
}

bool tdx_accept_memory(phys_addr_t start, phys_addr_t end)
{
	/*
	 * For shared->private conversion, accept the page using
	 * TDG_MEM_PAGE_ACCEPT TDX module call.
	 */
	while (start < end) {
		unsigned long len = end - start;
		unsigned long accept_size;

		/*
		 * Try larger accepts first. It gives chance to VMM to keep
		 * 1G/2M Secure EPT entries where possible and speeds up
		 * process by cutting number of hypercalls (if successful).
		 */

		accept_size = try_accept_one(start, len, PG_LEVEL_1G);
		if (!accept_size)
			accept_size = try_accept_one(start, len, PG_LEVEL_2M);
		if (!accept_size)
			accept_size = try_accept_one(start, len, PG_LEVEL_4K);
		if (!accept_size)
			return false;
		start += accept_size;
	}

	return true;
}

/*
 * Notify the VMM about page mapping conversion. More info about ABI
 * can be found in TDX Guest-Host-Communication Interface (GHCI),
 * section "TDG.VP.VMCALL<MapGPA>".
 */
static bool tdx_map_gpa(phys_addr_t start, phys_addr_t end, bool enc)
{
	/* Retrying the hypercall a second time should succeed; use 3 just in case */
	const int max_retries_per_page = 3;
	int retry_count = 0;

	if (!enc) {
		/* Set the shared (decrypted) bits: */
		start |= tdx_shared_mask();
		end   |= tdx_shared_mask();
	}

	while (retry_count < max_retries_per_page) {
		struct tdx_module_args args = {
			.r10 = TDX_HYPERCALL_STANDARD,
			.r11 = TDVMCALL_MAP_GPA,
			.r12 = start,
			.r13 = end - start };

		u64 map_fail_paddr;
		u64 ret = __tdx_hypercall(&args);

		if (ret != TDVMCALL_STATUS_RETRY)
			return !ret;
		/*
		 * The guest must retry the operation for the pages in the
		 * region starting at the GPA specified in R11. R11 comes
		 * from the untrusted VMM. Sanity check it.
		 */
		map_fail_paddr = args.r11;
		if (map_fail_paddr < start || map_fail_paddr >= end)
			return false;

		/* "Consume" a retry without forward progress */
		if (map_fail_paddr == start) {
			retry_count++;
			continue;
		}

		start = map_fail_paddr;
		retry_count = 0;
	}

	return false;
}

bool tdx_enc_status_changed(phys_addr_t start, phys_addr_t end, bool enc)
{
	if (!tdx_map_gpa(start, end, enc))
		return false;

	/* shared->private conversion requires memory to be accepted before use */
	if (enc)
		return tdx_accept_memory(start, end);

	return true;
}

static bool tdx_accept_memory_regions(struct efi_boot_memmap *mem_map)
{
	unsigned long i, nr_desc = *mem_map->map_size / *mem_map->desc_size;
	efi_memory_desc_t *d;

	for (i = 0; i < nr_desc; i++) {
		d = efi_memdesc_ptr(*mem_map->map, *mem_map->desc_size, i);

		if (d->type == EFI_UNACCEPTED_MEMORY) {
			if (d->phys_addr & ~PAGE_MASK) {
				printf("WARNING: EFI: unaligned base %lx\n",
					   d->phys_addr);
				d->phys_addr &= PAGE_MASK;
			}
			if (!tdx_enc_status_changed(d->phys_addr, d->phys_addr +
					       PAGE_SIZE * d->num_pages, true)) {
				printf("Accepting memory failed\n");
				return false;
			}

			d->type = EFI_CONVENTIONAL_MEMORY;
		}
	}
	return true;
}

efi_status_t setup_tdx(efi_bootinfo_t *efi_bootinfo)
{
	if (!is_tdx_guest())
		return EFI_UNSUPPORTED;

	tdx_get_info();
	if (!tdx_accept_memory_regions(&efi_bootinfo->mem_map))
		return EFI_OUT_OF_RESOURCES;

	handle_exception(20, tdx_handle_ve);

	/*
	 * The printf can work here. Since TDVF default exception handler
	 * can handle the #VE caused by IO read/write during printf() before
	 * finalizing configuration of the unit test's #VE handler.
	 */
	printf("Initialized TDX.\n");

	return EFI_SUCCESS;
}
