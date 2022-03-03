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

#define BUG_ON(condition) do { if (condition) abort(); } while (0)

#define TDX_CPUID_LEAF_ID		0x21
#define TDX_HYPERCALL_STANDARD		0

#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32

/* TDX Module call Leaf IDs */
#define TDX_GET_INFO			1
#define TDX_GET_VEINFO			3
#define TDX_ACCEPT_PAGE			6

/* TDX hypercall Leaf IDs */
#define TDVMCALL_MAP_GPA		0x10001

/*
 * Used in __tdx_module_call() helper function to gather the
 * output registers' values of TDCALL instruction when requesting
 * services from the TDX module. This is software only structure
 * and not related to TDX module/VMM.
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/*
 * Used in __tdx_hypercall() helper function to gather the
 * output registers' values of TDCALL instruction when requesting
 * services from the VMM. This is software only structure
 * and not related to TDX module/VMM.
 */
struct tdx_hypercall_output {
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

/*
 * Used by #VE exception handler to gather the #VE exception
 * info from the TDX module. This is software only structure
 * and not related to TDX module/VMM.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	u64 gla;	/* Guest Linear (virtual) Address */
	u64 gpa;	/* Guest Physical (virtual) Address */
	u32 instr_len;
	u32 instr_info;
};

/*
 * Page mapping type enum. This is software construct not
 * part of any hardware or VMM ABI.
 */
enum tdx_map_type {
	TDX_MAP_PRIVATE,
	TDX_MAP_SHARED,
};

bool is_tdx_guest(void);
phys_addr_t tdx_shared_mask(void);
int tdx_hcall_gpa_intent(phys_addr_t start, phys_addr_t end,
			 enum tdx_map_type map_type);
bool tdx_accept_memory(phys_addr_t start, phys_addr_t end);
efi_status_t setup_tdx(efi_bootinfo_t *efi_bootinfo);
efi_status_t bringup_tdx_aps(void);
void tdx_ap_online(void);

/* Helper function used to communicate with the TDX module */
u64 __tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		      struct tdx_module_output *out);

/* Helper function used to request services from VMM */
u64 __tdx_hypercall(u64 type, u64 fn, u64 r12, u64 r13, u64 r14,
		    u64 r15, struct tdx_hypercall_output *out);
#else
inline bool is_tdx_guest(void) { return false; }
inline void bringup_tdx_aps(void) { };
#endif /* TARGET_EFI */

#endif /* _ASM_X86_TDX_H */
