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

static volatile unsigned long db_addr[20], dr6[20];
static volatile unsigned int n;
static void handle_db(struct ex_regs *regs)
{
	db_addr[n] = regs->rip;
	dr6[n] = read_dr6();

	if (dr6[n] & 0x1)
		regs->rflags |= (1 << 16);

	if (++n >= 10) {
		regs->rflags &= ~(1 << 8);
		write_dr7(0x00000400);
	}
}

static void test_single_step(void)
{
	extern char ss_0;
	extern char ss_1;
	extern char ss_2;
	extern char ss_3;
	extern char ss_4;
	extern char ss_5;
	extern char ss_6;
	extern char ss_7;
	extern char ss_8;
	extern char ss_9;

	printf("\nStart single step test.\n");
	handle_exception(DB_VECTOR, handle_db);

	/*
	 * Test #DB single step emulation for 2 scenarios:
	 * 1. #VE handler by lib/tdx.c:
	 *	Trigger by using cpuid(0xb) and wrmsr(0x828)
	 * 2. instruction vmexit handled by tdx module:
	 *	Trigger by using cpuid(0)
	 */
	n = 0;
	write_dr6(0);
	asm volatile(
			"pushf\n\t"
			"pop %%rax\n\t"
			"or $(1<<8),%%rax\n\t"
			"push %%rax\n\t"
			"popf\n\t"
			"and $~(1<<8),%%rax\n\t"
		".global ss_0; ss_0:\n\t"
			"push %%rax\n\t"
		".global ss_1; ss_1:\n\t"
			"mov $0xb,%%rax\n\t"
		".global ss_2; ss_2:\n\t"
			"cpuid\n\t"
		".global ss_3; ss_3:\n\t"
			"mov $0x0,%%rax\n\t"
		".global ss_4; ss_4:\n\t"
			"cpuid\n\t"
		".global ss_5; ss_5:\n\t"
			"movl $0x828,%%ecx\n\t"
		".global ss_6; ss_6:\n\t"
			"rdmsr\n\t"
		".global ss_7; ss_7:\n\t"
			"wrmsr\n\t"
		".global ss_8; ss_8:\n\t"
			"popf\n\t"
		".global ss_9; ss_9:\n\t"
		: : : "rax", "ebx", "ecx", "edx");

	report(n == 10 &&
	       db_addr[0] == (unsigned long)&ss_0 && dr6[0] == 0xffff4ff0 &&
	       db_addr[1] == (unsigned long)&ss_1 && dr6[1] == 0xffff4ff0 &&
	       db_addr[2] == (unsigned long)&ss_2 && dr6[2] == 0xffff4ff0 &&
	       db_addr[3] == (unsigned long)&ss_3 && dr6[3] == 0xffff4ff0 &&
	       db_addr[4] == (unsigned long)&ss_4 && dr6[4] == 0xffff4ff0 &&
	       db_addr[5] == (unsigned long)&ss_5 && dr6[5] == 0xffff4ff0 &&
	       db_addr[6] == (unsigned long)&ss_6 && dr6[6] == 0xffff4ff0 &&
	       db_addr[7] == (unsigned long)&ss_7 && dr6[7] == 0xffff4ff0 &&
	       db_addr[8] == (unsigned long)&ss_8 && dr6[8] == 0xffff4ff0 &&
	       db_addr[9] == (unsigned long)&ss_9 && dr6[9] == 0xffff4ff0,
	       "single step emulated instructions");
	printf("End single step test.\n");
}

int main(void)
{
	if (!is_tdx_guest()) {
		printf("Not TDX environment!\n");
		return report_summary();
	}

	test_selfipi_msr();
	test_single_step();
	return report_summary();
}
