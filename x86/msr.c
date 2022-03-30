/* msr tests */

#include "libcflat.h"
#include "processor.h"
#include "msr.h"
#include <stdlib.h>
#include "tdx.h"

/**
 * This test allows two modes:
 * 1. Default: the `msr_info' array contains the default test configurations
 * 2. Custom: by providing command line arguments it is possible to test any MSR and value
 *	Parameters order:
 *		1. msr index as a base 16 number
 *		2. value as a base 16 number
 */

struct msr_info {
	int index;
	bool is_64bit_only;
	const char *name;
	unsigned long long value;
};


#define addr_64 0x0000123456789abcULL
#define addr_ul (unsigned long)addr_64

#define MSR_TEST(msr, val, only64)	\
	{ .index = msr, .name = #msr, .value = val, .is_64bit_only = only64 }

struct msr_info msr_info[] =
{
	MSR_TEST(MSR_IA32_SYSENTER_CS, 0x1234, false),
	MSR_TEST(MSR_IA32_SYSENTER_ESP, addr_ul, false),
	MSR_TEST(MSR_IA32_SYSENTER_EIP, addr_ul, false),
	// reserved: 1:2, 4:6, 8:10, 13:15, 17, 19:21, 24:33, 35:63
	MSR_TEST(MSR_IA32_MISC_ENABLE, 0x400c51889, false),
	MSR_TEST(MSR_IA32_CR_PAT, 0x07070707, false),
	MSR_TEST(MSR_FS_BASE, addr_64, true),
	MSR_TEST(MSR_GS_BASE, addr_64, true),
	MSR_TEST(MSR_KERNEL_GS_BASE, addr_64, true),
	MSR_TEST(MSR_EFER, EFER_SCE, false),
	MSR_TEST(MSR_LSTAR, addr_64, true),
	MSR_TEST(MSR_CSTAR, addr_64, true),
	MSR_TEST(MSR_SYSCALL_MASK, 0xffffffff, true),
//	MSR_IA32_DEBUGCTLMSR needs svm feature LBRV
//	MSR_VM_HSAVE_PA only AMD host
};

static void test_msr_rw(struct msr_info *msr, unsigned long long val)
{
	unsigned long long r, orig;

	orig = rdmsr(msr->index);
	/*
	 * Special case EFER since clearing LME/LMA is not allowed in 64-bit mode,
	 * and conversely setting those bits on 32-bit CPUs is not allowed.  Treat
	 * the desired value as extra bits to set.
	 */
	if (msr->index == MSR_EFER)
		val |= orig;
	wrmsr(msr->index, val);
	r = rdmsr(msr->index);
	wrmsr(msr->index, orig);
	if (r != val) {
		printf("testing %s: output = %#" PRIx32 ":%#" PRIx32
		       " expected = %#" PRIx32 ":%#" PRIx32 "\n", msr->name,
		       (u32)(r >> 32), (u32)r, (u32)(val >> 32), (u32)val);
	}
	report(val == r, "%s", msr->name);
}

static void test_wrmsr_fault(struct msr_info *msr, unsigned long long val)
{
	unsigned char vector = wrmsr_checking(msr->index, val);

	report(vector == GP_VECTOR,
	       "Expected #GP on WRSMR(%s, 0x%llx), got vector %d",
	       msr->name, val, vector);
}

static void test_rdmsr_fault(struct msr_info *msr)
{
	unsigned char vector = rdmsr_checking(msr->index);

	report(vector == GP_VECTOR,
	       "Expected #GP on RDSMR(%s), got vector %d", msr->name, vector);
}

static void test_msr(struct msr_info *msr, bool is_64bit_host)
{
	/* Changing MSR_IA32_MISC_ENABLE and MSR_CSTAR is unsupported in TDX */
	if ((msr->index == MSR_IA32_MISC_ENABLE || msr->index == MSR_CSTAR) &&
	    is_tdx_guest())
		return;

	if (is_64bit_host || !msr->is_64bit_only) {
		test_msr_rw(msr, msr->value);

		/*
		 * The 64-bit only MSRs that take an address always perform
		 * canonical checks on both Intel and AMD.
		 */
		if (msr->is_64bit_only &&
		    msr->value == addr_64)
			test_wrmsr_fault(msr, NONCANONICAL);
	} else {
		test_wrmsr_fault(msr, msr->value);
		test_rdmsr_fault(msr);
	}
}

int main(int ac, char **av)
{
	bool is_64bit_host = this_cpu_has(X86_FEATURE_LM);
	int i;

	if (ac == 3) {
		char msr_name[16];
		int index = strtoul(av[1], NULL, 0x10);
		snprintf(msr_name, sizeof(msr_name), "MSR:0x%x", index);

		struct msr_info msr = {
			.index = index,
			.name = msr_name,
			.value = strtoull(av[2], NULL, 0x10)
		};
		test_msr(&msr, is_64bit_host);
	} else {
		for (i = 0 ; i < ARRAY_SIZE(msr_info); i++) {
			test_msr(&msr_info[i], is_64bit_host);
		}
	}

	return report_summary();
}
