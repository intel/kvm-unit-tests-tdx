/*
 * TDX library
 *
 * Copyright (c) 2022, Intel Inc
 *
 * Authors:
 *   Zhenzhong Duan <zhenzhong.duan@intel.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "tdx.h"
#include "errno.h"
#include "bitops.h"
#include "atomic.h"
#include "fwcfg.h"
#include "x86/acpi.h"
#include "x86/processor.h"
#include "x86/smp.h"
#include "x86/apic.h"
#include "asm/page.h"
#include "asm/barrier.h"

#define VE_IS_IO_OUT(exit_qual)		(((exit_qual) & 8) ? 0 : 1)
#define VE_GET_IO_SIZE(exit_qual)	(((exit_qual) & 7) + 1)
#define VE_GET_PORT_NUM(exit_qual)	((exit_qual) >> 16)
#define VE_IS_IO_STRING(exit_qual)	((exit_qual) & 16 ? 1 : 0)

#define BUFSZ		2000
#define serial_iobase	0x3f8

static struct spinlock tdx_puts_lock;

/*
 * Helper function used for making hypercall for "in"
 * instruction. If IO is failed, it will return all 1s.
 */
static inline unsigned int tdx_io_in(int size, int port)
{
	struct tdx_hypercall_output out;

	__tdx_hypercall(TDX_HYPERCALL_STANDARD, EXIT_REASON_IO_INSTRUCTION,
			size, 0, port, 0, &out);

	return out.r10 ? UINT_MAX : out.r11;
}

/*
 * Helper function used for making hypercall for "out"
 * instruction.
 */
static inline void tdx_io_out(int size, int port, u64 value)
{
	struct tdx_hypercall_output out;

	__tdx_hypercall(TDX_HYPERCALL_STANDARD, EXIT_REASON_IO_INSTRUCTION,
			size, 1, port, value, &out);
}

static void tdx_outb(u8 value, u32 port)
{
	tdx_io_out(sizeof(u8), port, value);
}

static u8 tdx_inb(u32 port)
{
	return tdx_io_in(sizeof(u8), port);
}

static void tdx_serial_outb(char ch)
{
	u8 lsr;

	do {
		lsr = tdx_inb(serial_iobase + 0x05);
	} while (!(lsr & 0x20));

	tdx_outb(ch, serial_iobase + 0x00);
}

static void tdx_puts(const char *buf)
{
	unsigned long len = strlen(buf);
	unsigned long i;

	spin_lock(&tdx_puts_lock);

	/* No need to initialize serial port as TDVF has done that */
	for (i = 0; i < len; i++)
		tdx_serial_outb(buf[i]);

	spin_unlock(&tdx_puts_lock);
}

/* Used only in TDX arch code itself */
static int tdx_printf(const char *fmt, ...)
{
	va_list va;
	char buf[BUFSZ];
	int r;

	va_start(va, fmt);
	r = vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);
	tdx_puts(buf);
	return r;
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

	tdx_guest = !memcmp("IntelTDX    ", sig, 12);

done:
	return !!tdx_guest;
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
	struct tdx_module_output out;
	u64 ret;

	/*
	 * TDINFO TDX Module call is used to get the TD
	 * execution environment information like GPA
	 * width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI
	 * can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec 2.4.2 TDCALL [TDG.VP.INFO].
	 */
	ret = __tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out);

	/*
	 * Non zero return means buggy TDX module (which is
	 * fatal). So raise a BUG().
	 */
	BUG_ON(ret);

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;
}

/*
 * Wrapper for standard use of __tdx_hypercall with BUG_ON() check
 * for TDCALL error.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14,
				 u64 r15, struct tdx_hypercall_output *out)
{
	struct tdx_hypercall_output outl;
	u64 err;

	/* __tdx_hypercall() does not accept NULL output pointer */
	if (!out)
		out = &outl;

	err = __tdx_hypercall(TDX_HYPERCALL_STANDARD, fn, r12, r13, r14,
			      r15, out);

	/* Non zero return value indicates buggy TDX module, so panic */
	BUG_ON(err);

	if (out->r10)
		tdx_printf("_tdx_hypercall err %lx %lx %lx %lx %lx %lx\n",
			   out->r10, out->r11, out->r12, out->r13,
			   out->r14, out->r15);
	return out->r10;
}

static bool _tdx_halt(const bool irq_disabled, const bool do_sti)
{
	u64 ret;

	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of TD guest and determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 *
	 * do_sti parameter is used by __tdx_hypercall() to decide
	 * whether to call STI instruction before executing TDCALL
	 * instruction.
	 */
	ret = _tdx_hypercall(EXIT_REASON_HLT, irq_disabled, 0, 0,
			     do_sti, NULL);
	return !ret;
}

static bool tdx_read_msr(unsigned int msr, u64 *val)
{
	struct tdx_hypercall_output out;
	u64 ret;

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec titled "TDG.VP.VMCALL<Instruction.RDMSR>".
	 */
	ret = _tdx_hypercall(EXIT_REASON_MSR_READ, msr, 0, 0, 0, &out);

	if (ret)
		return false;

	*val = out.r11;
	return true;
}

static bool tdx_write_msr(unsigned int msr, unsigned int low,
			       unsigned int high)
{
	u64 ret;

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) sec titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	ret = _tdx_hypercall(EXIT_REASON_MSR_WRITE, msr,
			     (u64)high << 32 | low, 0, 0, NULL);

	return !ret;
}

static bool tdx_handle_cpuid(struct ex_regs *regs)
{
	struct tdx_hypercall_output out;

	/*
	 * Emulate CPUID instruction via hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (_tdx_hypercall(EXIT_REASON_CPUID, regs->rax, regs->rcx,
			   0, 0, &out))
		return false;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contains contents of
	 * EAX, EBX, ECX, EDX registers after CPUID instruction execution.
	 * So copy the register contents back to ex_regs.
	 */
	regs->rax = out.r12;
	regs->rbx = out.r13;
	regs->rcx = out.r14;
	regs->rdx = out.r15;

	return true;
}

static bool tdx_handle_io(struct ex_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_output outh;
	int out, size, port, ret;
	bool string;
	u64 mask;

	string = VE_IS_IO_STRING(exit_qual);

	/* I/O strings ops are unrolled at build time. */
	if (string) {
		tdx_printf("string io isn't supported in #VE currently.\n");
		return false;
	}

	out = VE_IS_IO_OUT(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);
	mask = GENMASK(8 * size, 0);

	ret = _tdx_hypercall(EXIT_REASON_IO_INSTRUCTION,
			     size, out, port, regs->rax, &outh);
	if (!out) {
		regs->rax &= ~mask;
		regs->rax |= (ret ? UINT_MAX : outh.r11) & mask;
	}

	return ret ? false : true;
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
	struct tdx_module_output out;
	u64 ret;

	if (!ve)
		return false;

	/*
	 * NMIs and machine checks are suppressed. Before this point any
	 * #VE is fatal. After this point (TDGETVEINFO call), NMIs and
	 * additional #VEs are permitted (but it is expected not to
	 * happen unless kernel panics).
	 */
	ret = __tdx_module_call(TDX_GET_VEINFO, 0, 0, 0, 0, &out);
	if (ret)
		return false;

	ve->exit_reason = out.rcx;
	ve->exit_qual	= out.rdx;
	ve->gla		= out.r8;
	ve->gpa		= out.r9;
	ve->instr_len	= out.r10 & UINT_MAX;
	ve->instr_info	= out.r10 >> 32;

	return true;
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

static bool tdx_handle_virtualization_exception(struct ex_regs *regs,
		struct ve_info *ve)
{
	unsigned int ex_val;
	bool ret = true;
	u64 val = ~0ULL;
	bool do_sti;

	/* #VE exit_reason in bit16-32 */
	ex_val = regs->vector | (ve->exit_reason << 16);
	asm("mov %0, %%gs:4" : : "r"(ex_val));

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		do_sti = !!(regs->rflags & X86_EFLAGS_IF);
		/* Bypass failed hlt is better than hang */
		if (!_tdx_halt(!do_sti, do_sti))
			tdx_printf("HLT instruction emulation failed\n");
		break;
	case EXIT_REASON_MSR_READ:
		ret = tdx_read_msr(regs->rcx, &val);
		if (ret) {
			regs->rax = (u32)val;
			regs->rdx = val >> 32;
		}
		break;
	case EXIT_REASON_MSR_WRITE:
		if (!tdx_is_bypassed_msr(regs->rcx))
			ret = tdx_write_msr(regs->rcx, regs->rax, regs->rdx);
		break;
	case EXIT_REASON_CPUID:
		ret = tdx_handle_cpuid(regs);
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		ret = tdx_handle_io(regs, ve->exit_qual);
		break;
	default:
		tdx_printf("Unexpected #VE: %ld\n", ve->exit_reason);
		return false;
	}

	/* After successful #VE handling, move the IP */
	if (ret) {
		regs->rip += ve->instr_len;
		/* Simulate single step on simulated instruction */
		if (regs->rflags & X86_EFLAGS_TF) {
			regs->vector = DB_VECTOR;
			write_dr6(read_dr6() | (1 << 14));
			do_handle_exception(regs);
		}
	}
	else
		ret = tdx_check_exception_table(regs);

	return ret;
}

/* #VE exception handler. */
static void tdx_handle_ve(struct ex_regs *regs)
{
	struct ve_info ve;

	if (!tdx_get_ve_info(&ve)) {
		tdx_printf("tdx_get_ve_info failed\n");
		return;
	}

	tdx_handle_virtualization_exception(regs, &ve);
}

static u64 tdx_accept_page(phys_addr_t gpa, bool page_2mb)
{
	/*
	 * Pass the page physical address and size (4KB|2MB) to the
	 * TDX module to accept the pending, private page. More info
	 * about ABI can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec 2.4.7.
	 */

	if (page_2mb)
		gpa |= 1;

	return __tdx_module_call(TDX_ACCEPT_PAGE, gpa, 0, 0, 0, NULL);
}

/*
 * Inform the VMM of the guest's intent for this physical page:
 * shared with the VMM or private to the guest.  The VMM is
 * expected to change its mapping of the page in response.
 */
int tdx_hcall_gpa_intent(phys_addr_t start, phys_addr_t end,
			 enum tdx_map_type map_type)
{
	u64 ret = 0;

	if (map_type == TDX_MAP_SHARED) {
		start |= tdx_shared_mask();
		end |= tdx_shared_mask();
	}

	/*
	 * Notify VMM about page mapping conversion. More info
	 * about ABI can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec 3.2.
	 */
	ret = _tdx_hypercall(TDVMCALL_MAP_GPA, start, end - start, 0, 0,
			     NULL);
	if (ret)
		ret = -EIO;

	if (ret || map_type == TDX_MAP_SHARED)
		return ret;
	/*
	 * For shared->private conversion, accept the page using
	 * TDX_ACCEPT_PAGE TDX module call.
	 */
	while (start < end) {
		/* Try 2M page accept first if possible */
		if (!(start & ~PMD_MASK) && end - start >= PMD_SIZE &&
				!tdx_accept_page(start, true)) {
			start += PMD_SIZE;
			continue;
		}

		if (tdx_accept_page(start, false))
			return -EIO;
		start += PAGE_SIZE;
	}

	return 0;
}

bool tdx_accept_memory(phys_addr_t start, phys_addr_t end)
{
	if (tdx_hcall_gpa_intent(start, end, TDX_MAP_PRIVATE)) {
		tdx_printf("Accepting memory failed\n");
		return false;
	}
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
				tdx_printf("WARN: EFI: unaligned base %lx\n",
					   d->phys_addr);
				d->phys_addr &= PAGE_MASK;
			}
			if (!tdx_accept_memory(d->phys_addr, d->phys_addr +
					       PAGE_SIZE * d->num_pages))
				return false;

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

	printf("Initialized TDX.\n");

	return EFI_SUCCESS;
}

extern unsigned char online_cpus[(MAX_TEST_CPUS + 7) / 8];
extern void tdx_ap_start64(void);

/* TDX uses ACPI WAKE UP mechanism to wake up APs instead of SIPI */
efi_status_t tdx_aps_init(void)
{
	u32 i, total_cpus = fwcfg_get_nb_cpus();

	/* BSP is already online */
	set_bit(id_map[0], online_cpus);

	for (i = 1; i < total_cpus; i++) {
		if (acpi_wakeup_cpu(id_map[i], (u64)tdx_ap_start64))
			return EFI_DEVICE_ERROR;
	}

	while (atomic_read(&cpu_online_count) != total_cpus)
		cpu_relax();

	return EFI_SUCCESS;
}

void tdx_ap_init(void)
{
	atomic_inc(&cpu_online_count);
}
