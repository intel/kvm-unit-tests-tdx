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

#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#ifdef CONFIG_EFI

#include "libcflat.h"
#include "limits.h"
#include "efi.h"

#define TDX_HYPERCALL_STANDARD  0

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

/* TDX module Call Leaf IDs */
#define TDG_VP_VMCALL			0
#define TDG_VP_INFO			1
#define TDG_VP_VEINFO_GET		3
#define TDG_MEM_PAGE_ACCEPT		6

/* TDX hypercall Leaf IDs */
#define TDVMCALL_MAP_GPA		0x10001

#define TDVMCALL_STATUS_RETRY		1

/*
 * Bitmasks of exposed registers (with VMM).
 */
#define TDX_RDX		BIT(2)
#define TDX_RBX		BIT(3)
#define TDX_RSI		BIT(6)
#define TDX_RDI		BIT(7)
#define TDX_R8		BIT(8)
#define TDX_R9		BIT(9)
#define TDX_R10		BIT(10)
#define TDX_R11		BIT(11)
#define TDX_R12		BIT(12)
#define TDX_R13		BIT(13)
#define TDX_R14		BIT(14)
#define TDX_R15		BIT(15)

/*
 * These registers are clobbered to hold arguments for each
 * TDVMCALL. They are safe to expose to the VMM.
 * Each bit in this mask represents a register ID. Bit field
 * details can be found in TDX GHCI specification, section
 * titled "TDCALL [TDG.VP.VMCALL] leaf".
 */
#define TDVMCALL_EXPOSE_REGS_MASK	\
	(TDX_RDX | TDX_RBX | TDX_RSI | TDX_RDI | TDX_R8  | TDX_R9  | \
	 TDX_R10 | TDX_R11 | TDX_R12 | TDX_R13 | TDX_R14 | TDX_R15)

#define BUG_ON(condition) do { if (condition) abort(); } while (0)

/* TDX supported page sizes from the TDX module ABI. */
#define TDX_PS_4K	0
#define TDX_PS_2M	1
#define TDX_PS_1G	2
#define TDX_PS_NR	(TDX_PS_1G + 1)

#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_APIC_WRITE          56

/*
 * Used in __tdcall*() to gather the input/output registers' values of the
 * TDCALL instruction when requesting services from the TDX module. This is a
 * software only structure and not part of the TDX module/VMM ABI
 */
struct tdx_module_args {
	/* callee-clobbered */
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	/* extra callee-clobbered */
	u64 r10;
	u64 r11;
	/* callee-saved + rdi/rsi */
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 rbx;
	u64 rdi;
	u64 rsi;
};

/* Used to communicate with the TDX module */
u64 __tdcall(u64 fn, struct tdx_module_args *args);
u64 __tdcall_ret(u64 fn, struct tdx_module_args *args);
u64 __tdcall_saved_ret(u64 fn, struct tdx_module_args *args);

/* Used to request services from the VMM */
u64 __tdx_hypercall(struct tdx_module_args *args);

/*
 * Wrapper for standard use of __tdx_hypercall with no output aside from
 * return code.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	struct tdx_module_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = fn,
		.r12 = r12,
		.r13 = r13,
		.r14 = r14,
		.r15 = r15,
	};

	return __tdx_hypercall(&args);
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

bool is_tdx_guest(void);
phys_addr_t tdx_shared_mask(void);
bool tdx_accept_memory(phys_addr_t start, phys_addr_t end);
bool tdx_enc_status_changed(phys_addr_t start, phys_addr_t end, bool enc);
efi_status_t setup_tdx(efi_bootinfo_t *efi_bootinfo);

#else
inline bool is_tdx_guest(void) { return false; }
#endif /* CONFIG_EFI */

#endif /* _ASM_X86_TDX_H */
