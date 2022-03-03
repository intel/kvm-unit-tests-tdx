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

	return EFI_SUCCESS;
}
