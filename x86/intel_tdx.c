#include "libcflat.h"
#include "x86/processor.h"
#include "x86/apic-defs.h"
#include "x86/tdx.h"
#include "msr.h"

static volatile unsigned long db_addr[10], dr6[10];
static volatile unsigned int n;

static void test_selfipi_msr(void)
{
	unsigned char vector;
	u64 i;

	printf("start APIC_SELF_IPI MSR write test.\n");

	for (i = 0; i < 16; i++) {
		vector = wrmsr_checking(APIC_SELF_IPI, i);
		report(vector == VE_VECTOR,
		       "Expected #VE on WRSMR(%s, 0x%lx), got vector %d",
		       "APIC_SELF_IPI", i, vector);
	}

	printf("end APIC_SELF_IPI MSR write test.\n");
}

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
	unsigned long start;

	handle_exception(DB_VECTOR, handle_db);

	/*
	 * cpuid(0xb) and wrmsr(0x1a0) trigger #VE and are then emulated.
	 * Test #DB on these instructions as there is single step
	 * simulation in #VE handler. This is complement to x86/debug.c
	 * which test cpuid(0) and in(0x3fd) instruction. In fact,
	 * cpuid(0) is emulated by seam module.
	 */
	n = 0;
	write_dr6(0);
	asm volatile(
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"lea (%%rip),%0\n\t"
		"popf\n\t"
		"and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"mov $0xb,%%rax\n\t"
		"cpuid\n\t"
		"movl $0x1a0,%%ecx\n\t"
		"rdmsr\n\t"
		"wrmsr\n\t"
		"popf\n\t"
		: "=r" (start) : : "rax", "ebx", "ecx", "edx");
	report(n == 8 &&
	       db_addr[0] == start + 1 + 6 && dr6[0] == 0xffff4ff0 &&
	       db_addr[1] == start + 1 + 6 + 1 && dr6[1] == 0xffff4ff0 &&
	       db_addr[2] == start + 1 + 6 + 1 + 7 && dr6[2] == 0xffff4ff0 &&
	       db_addr[3] == start + 1 + 6 + 1 + 7 + 2 && dr6[3] == 0xffff4ff0 &&
	       db_addr[4] == start + 1 + 6 + 1 + 7 + 2 + 5 && dr6[4] == 0xffff4ff0 &&
	       db_addr[5] == start + 1 + 6 + 1 + 7 + 2 + 5 + 2 && dr6[5] == 0xffff4ff0 &&
	       db_addr[6] == start + 1 + 6 + 1 + 7 + 2 + 5 + 2 + 2 && dr6[6] == 0xffff4ff0 &&
	       db_addr[7] == start + 1 + 6 + 1 + 7 + 2 + 5 + 2 + 2 + 1 && dr6[6] == 0xffff4ff0,
	       "single step emulated instructions");
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
