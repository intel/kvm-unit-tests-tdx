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

#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#ifdef CONFIG_EFI

#include "libcflat.h"
#include "limits.h"
#include "efi.h"


#define TDX_HYPERCALL_STANDARD		0

/* TDX TDCALL.VMCALL leaf id  */
#define TDG_VP_VMCALL			0

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

bool is_tdx_guest(void);
efi_status_t setup_tdx(efi_bootinfo_t *efi_bootinfo);
phys_addr_t tdx_shared_mask(void);
bool tdx_accept_memory(phys_addr_t start, phys_addr_t end);
bool tdx_enc_status_changed(phys_addr_t start, phys_addr_t end, bool enc);

#else

struct tdx_module_args;

static inline bool is_tdx_guest(void) { return false; }

static inline u64 __tdcall(u64 fn, struct tdx_module_args *args)
{
	assert_msg(false, "not supported on non-efi.");
	return 0;
}

static inline u64 __tdcall_ret(u64 fn, struct tdx_module_args *args)
{
	assert_msg(false, "not supported on non-efi.");
	return 0;
}

static inline u64 __tdcall_saved_ret(u64 fn, struct tdx_module_args *args)
{
	assert_msg(false, "not supported on non-efi.");
	return 0;
}

/* Used to request services from the VMM */
static inline u64 __tdx_hypercall(struct tdx_module_args *args)
{
	assert_msg(false, "not supported on non-efi.");
	return 0;
}

#endif /* CONFIG_EFI */
#endif /* _ASM_X86_TDX_H */
