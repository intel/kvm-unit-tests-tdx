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

bool is_tdx_guest(void);
efi_status_t setup_tdx(void);

#else

static inline bool is_tdx_guest(void) { return false; }

#endif /* CONFIG_EFI */
#endif /* _ASM_X86_TDX_H */
