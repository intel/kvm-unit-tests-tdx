#include "libcflat.h"
#include "x86/processor.h"
#include "x86/apic-defs.h"
#include "x86/tdx.h"
#include "msr.h"

static void test_selfipi_msr(void)
{
	unsigned char vector;
	u64 i;

	printf("\nStart APIC_SELF_IPI MSR write test.\n");

	for (i = 0; i < 16; i++) {
		vector = wrmsr_safe(APIC_SELF_IPI, i);
		report(vector == VE_VECTOR,
		       "Expected #VE on WRSMR(%s, 0x%lx), got vector %d",
		       "APIC_SELF_IPI", i, vector);
	}

	printf("End APIC_SELF_IPI MSR write test.\n");
}

int main(void)
{
	if (!is_tdx_guest()) {
		printf("Not TDX environment!\n");
		return report_summary();
	}

	test_selfipi_msr();
	return report_summary();
}
