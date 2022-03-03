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
