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
		vector = wrmsr_safe(APIC_SELF_IPI, i);
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
	 * cpuid(0xb) and wrmsr(0x828) trigger #VE and are then emulated.
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
		"movl $0x828,%%ecx\n\t"
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

#define CPUID_FIXED0 (0x0)
#define CPUID_FIXED1 (0xffffffff)

#define CPUID_0_EAX_FIXED	(0x23)
#define CPUID_0_EAX_MASK	(0xffffffff)

#define CPUID_1_EAX_MASK	(0x3 << 14 | 0xf << 28)
#define CPUID_1_EBX_FIXED	(0x8 << 8)
#define CPUID_1_EBX_MASK	(0xff | 0xff << 8)
#define CPUID_1_ECX_FIXED	(7 | 1 << 4 | 1 << 9  | 1 << 13 | 1 << 15 | 1 << 17 | 0xf << 19 | 1 << 23 | 3 << 25 | 3 << 30)
#define CPUID_1_ECX_MASK	(7 | 7 << 4 | 1 << 9  | 1 << 13 | 7 << 15 | 0xf << 19 | 1 << 23 | 3 << 25 | 3 << 30)
#define CPUID_1_EDX_FIXED	(0x3ff | 0x3f << 11 | 5 << 19 | 0xf << 23)
#define CPUID_1_EDX_MASK	(0xffff | 3 << 16 | 7 << 19 | 0xf << 23 |1 << 30)

#define CPUID_3_EAX_MASK	CPUID_FIXED1
#define CPUID_3_EBX_MASK	CPUID_FIXED1
#define CPUID_3_ECX_MASK	CPUID_FIXED1
#define CPUID_3_EDX_MASK	CPUID_FIXED1


#define CPUID_4_0_EAX_MASK	(0xf << 10)
#define CPUID_4_0_EDX_MASK	(1 << 2)
#define CPUID_4_1_EAX_MASK	CPUID_4_0_EAX_MASK
#define CPUID_4_1_EDX_MASK	CPUID_4_0_EDX_MASK
#define CPUID_4_2_EAX_MASK	CPUID_4_0_EAX_MASK
#define CPUID_4_2_EDX_MASK	CPUID_4_0_EDX_MASK
#define CPUID_4_3_EAX_MASK	CPUID_4_0_EAX_MASK
#define CPUID_4_3_EDX_MASK	(0xfffffff8)
#define CPUID_4_4_EAX_MASK	CPUID_FIXED1
#define CPUID_4_4_EBX_MASK	CPUID_FIXED1
#define CPUID_4_4_ECX_MASK	CPUID_FIXED1
#define CPUID_4_4_EDX_MASK	CPUID_FIXED1

#define CPUID_7_0_EAX_FIXED	(2)
#define CPUID_7_0_EAX_MASK	CPUID_FIXED1
#define CPUID_7_0_EBX_FIXED	(1 | 3 << 6 | 1 << 10 | 1 << 13 | 5 << 18 | 3 << 23 | 1 << 29)
#define CPUID_7_0_EBX_MASK	(7 | 3 << 6 | 1 << 10 | 3 << 13 | 5 << 18 | 7 << 22 | 1 << 29)
#define CPUID_7_0_ECX_FIXED	(1 << 24 | 3 << 27)
#define CPUID_7_0_ECX_MASK	(1 << 15 | 0x1f << 17 | 1 << 24 | 0x1f << 26 )
#define CPUID_7_0_EDX_FIXED	(1 << 10 | 0x3f << 26)
#define CPUID_7_0_EDX_MASK	(3 | 3 << 6 | 0x1f << 9 | 1 << 17 | 1 << 21 | 0x3f << 26)
#define CPUID_7_1_EAX_MASK	(0xf | 5 << 7 | 0x3ff << 16 | 0x1f << 27)
#define CPUID_7_1_EBX_MASK	CPUID_FIXED1
#define CPUID_7_1_ECX_MASK	CPUID_FIXED1
#define CPUID_7_1_EDX_MASK	CPUID_FIXED1

#define CPUID_8_0_EAX_MASK	CPUID_FIXED1
#define CPUID_8_0_EBX_MASK	CPUID_FIXED1
#define CPUID_8_0_ECX_MASK	CPUID_FIXED1
#define CPUID_8_0_EDX_MASK	CPUID_FIXED1

#define CPUID_a_EBX_MASK	(0x0)
#define CPUID_a_EDX_MASK	(0x7ffff << 13)

#define CPUID_d_0_EAX_FIXED	(3)
#define CPUID_d_0_EAX_MASK	(3 | 3 << 3 | 1 << 8 | 1 << 10 | 0x1fff << 19)
#define CPUID_d_0_EDX_MASK	CPUID_FIXED1
#define CPUID_d_1_EAX_FIXED	(0xf)
#define CPUID_d_1_EAX_MASK	(0xf | 0x7ffffff << 5)
#define CPUID_d_1_ECX_MASK	(0xff | 3 << 9 | 1 << 13 | 0xffff << 16)
#define CPUID_d_1_EDX_MASK	CPUID_FIXED1

#define CPUID_15_EAX_FIXED	(1)
#define CPUID_15_EAX_MASK	CPUID_FIXED1
#define CPUID_15_ECX_FIXED	0x17d7840
#define CPUID_15_ECX_MASK	CPUID_FIXED1
#define CPUID_15_EDX_MASK	CPUID_FIXED1

#define CPUID_19_ECX_MASK	(0xfffffffe)
#define CPUID_19_EDX_MASK	CPUID_FIXED1

#define CPUID_21_0_EAX_MASK	CPUID_FIXED1
#define CPUID_21_0_EBX_FIXED	0x65746e49
#define CPUID_21_0_EBX_MASK	CPUID_FIXED1
#define CPUID_21_0_ECX_FIXED	0x20202020
#define CPUID_21_0_ECX_MASK	CPUID_FIXED1
#define CPUID_21_0_EDX_FIXED	0x5844546c
#define CPUID_21_0_EDX_MASK	CPUID_FIXED1

#define CPUID_80000000_EBX_MASK	CPUID_FIXED1
#define CPUID_80000000_ECX_MASK	CPUID_FIXED1
#define CPUID_80000000_EDX_MASK	CPUID_FIXED1

#define CPUID_80000001_EAX_MASK	CPUID_FIXED1
#define CPUID_80000001_EBX_MASK	CPUID_FIXED1
#define CPUID_80000001_ECX_MASK	CPUID_FIXED1
#define CPUID_80000001_ECX_FIXED (1 | 1 << 5 | 1<< 8)
#define CPUID_80000001_EDX_FIXED (1 << 20 | 3 << 26 | 1 << 29)
#define CPUID_80000001_EDX_MASK	(0xfffff7ff)

#define CPUID_80000008_EAX_FIXED (0x3934)
#define CPUID_80000008_EAX_MASK CPUID_FIXED1
#define CPUID_80000008_EBX_MASK	(0xfffffdff)
#define CPUID_80000008_ECX_MASK	CPUID_FIXED1
#define CPUID_80000008_EDX_MASK	CPUID_FIXED1

typedef struct CPUIDINFO {
	uint32_t eax;			/* Input EAX for CPUID */
	bool needs_ecx;			/* CPUID instruction uses ECX as input */
	enum cpuid_output_regs ecx;	/* Input ECX value for CPUID */
	int reg;			/* output register (R_* constant) */
	uint32_t mask;			/* The virtual bit value is fixed 0 */
	uint32_t value;			/* The virtual bit value is fixed 1 */
} CPUIDINFO;

CPUIDINFO cpuid_info[] = {
	{.eax = 0, .reg = EAX, .mask = CPUID_0_EAX_MASK, .value = CPUID_0_EAX_FIXED},
	{.eax = 1, .reg = EAX, .mask = CPUID_1_EAX_MASK},
	{.eax = 1, .reg = EBX, .mask = CPUID_1_EBX_MASK, .value = CPUID_1_EBX_FIXED},
	{.eax = 1, .reg = ECX, .mask = CPUID_1_ECX_MASK, .value = CPUID_1_ECX_FIXED},
	{.eax = 1, .reg = EDX, .mask = CPUID_1_EDX_MASK, .value = CPUID_1_EDX_FIXED},
	{.eax = 3, .reg = EAX, .mask = CPUID_3_EAX_MASK},
	{.eax = 3, .reg = EBX, .mask = CPUID_3_EBX_MASK},
	{.eax = 3, .reg = ECX, .mask = CPUID_3_ECX_MASK},
	{.eax = 3, .reg = EDX, .mask = CPUID_3_EDX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 0, .reg = EAX, .mask = CPUID_4_0_EAX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 0, .reg = EDX, .mask = CPUID_4_0_EDX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 1, .reg = EAX, .mask = CPUID_4_1_EAX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 1, .reg = EDX, .mask = CPUID_4_1_EDX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 2, .reg = EAX, .mask = CPUID_4_2_EAX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 2, .reg = EDX, .mask = CPUID_4_2_EDX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 3, .reg = EAX, .mask = CPUID_4_3_EAX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 3, .reg = EDX, .mask = CPUID_4_3_EDX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 4, .reg = EAX, .mask = CPUID_4_4_EAX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 4, .reg = EBX, .mask = CPUID_4_4_EBX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 4, .reg = ECX, .mask = CPUID_4_4_ECX_MASK},
	{.eax = 4, .needs_ecx = true, .ecx = 4, .reg = EDX, .mask = CPUID_4_4_EDX_MASK},
	{.eax = 7, .needs_ecx = true, .ecx = 0, .reg = EAX, .mask = CPUID_7_0_EAX_MASK, .value = CPUID_7_0_EAX_FIXED},
	{.eax = 7, .needs_ecx = true, .ecx = 0, .reg = EBX, .mask = CPUID_7_0_EBX_MASK, .value = CPUID_7_0_EBX_FIXED},
	{.eax = 7, .needs_ecx = true, .ecx = 0, .reg = ECX, .mask = CPUID_7_0_ECX_MASK, .value = CPUID_7_0_ECX_FIXED},
	{.eax = 7, .needs_ecx = true, .ecx = 0, .reg = EDX, .mask = CPUID_7_0_EDX_MASK, .value = CPUID_7_0_EDX_FIXED},
	{.eax = 7, .needs_ecx = true, .ecx = 1, .reg = EAX, .mask = CPUID_7_1_EAX_MASK},
	{.eax = 7, .needs_ecx = true, .ecx = 1, .reg = EBX, .mask = CPUID_7_1_EBX_MASK},
	{.eax = 7, .needs_ecx = true, .ecx = 1, .reg = ECX, .mask = CPUID_7_1_ECX_MASK},
	{.eax = 7, .needs_ecx = true, .ecx = 1, .reg = EDX, .mask = CPUID_7_1_EDX_MASK},
	{.eax = 0xa, .reg = EBX, .mask = CPUID_a_EBX_MASK},
	{.eax = 0xa, .reg = EDX, .mask = CPUID_a_EDX_MASK},
	{.eax = 0xd, .needs_ecx = true, .ecx = 0, .reg = EAX, .mask = CPUID_d_0_EAX_MASK, .value = CPUID_d_0_EAX_FIXED},
	{.eax = 0xd, .needs_ecx = true, .ecx = 0, .reg = EDX, .mask = CPUID_d_0_EDX_MASK},
	{.eax = 0xd, .needs_ecx = true, .ecx = 1, .reg = EAX, .mask = CPUID_d_1_EAX_MASK, .value = CPUID_d_1_EAX_FIXED},
	{.eax = 0xd, .needs_ecx = true, .ecx = 1, .reg = ECX, .mask = CPUID_d_1_ECX_MASK},
	{.eax = 0xd, .needs_ecx = true, .ecx = 1, .reg = EDX, .mask = CPUID_d_1_EDX_MASK},
	{.eax = 0x15, .reg = EAX, .mask = CPUID_15_EAX_MASK, .value = CPUID_15_EAX_FIXED},
	{.eax = 0x15, .reg = ECX, .mask = CPUID_15_ECX_MASK, .value = CPUID_15_ECX_FIXED},
	{.eax = 0x15, .reg = EDX, .mask = CPUID_15_EDX_MASK},
	{.eax = 0x19, .reg = ECX, .mask = CPUID_19_ECX_MASK},
	{.eax = 0x19, .reg = EDX, .mask = CPUID_19_EDX_MASK},
	{.eax = 0x21, .needs_ecx = true, .ecx = 0, .reg = EAX, .mask = CPUID_21_0_EAX_MASK},
	{.eax = 0x21, .needs_ecx = true, .ecx = 0, .reg = EBX, .mask = CPUID_21_0_EBX_MASK, .value = CPUID_21_0_EBX_FIXED},
	{.eax = 0x21, .needs_ecx = true, .ecx = 0, .reg = ECX, .mask = CPUID_21_0_ECX_MASK, .value = CPUID_21_0_ECX_FIXED},
	{.eax = 0x21, .needs_ecx = true, .ecx = 0, .reg = EDX, .mask = CPUID_21_0_EDX_MASK, .value = CPUID_21_0_EDX_FIXED},
	{.eax = 0x80000000, .reg = EBX, .mask = CPUID_80000000_EBX_MASK},
	{.eax = 0x80000000, .reg = ECX, .mask = CPUID_80000000_ECX_MASK},
	{.eax = 0x80000000, .reg = EDX, .mask = CPUID_80000000_EDX_MASK},
	{.eax = 0x80000001, .reg = EAX, .mask = CPUID_80000001_EAX_MASK},
	{.eax = 0x80000001, .reg = EBX, .mask = CPUID_80000001_EBX_MASK},
	{.eax = 0x80000001, .reg = ECX, .mask = CPUID_80000001_ECX_MASK, .value = CPUID_80000001_ECX_FIXED},
	{.eax = 0x80000001, .reg = EDX, .mask = CPUID_80000001_EDX_MASK, .value = CPUID_80000001_EDX_FIXED},
	{.eax = 0x80000008, .reg = EAX, .mask = CPUID_80000008_EAX_MASK, .value = CPUID_80000008_EAX_FIXED},
	{.eax = 0x80000008, .reg = EBX, .mask = CPUID_80000008_EBX_MASK},
	{.eax = 0x80000008, .reg = ECX, .mask = CPUID_80000008_ECX_MASK},
	{.eax = 0x80000008, .reg = EDX, .mask = CPUID_80000008_EDX_MASK},
};

static void check_cpuid_fixed(CPUIDINFO *ci)
{
	struct cpuid c = raw_cpuid(ci->eax, ci->ecx);
	uint32_t value = 0;

	switch (ci->reg) {
	case EAX:
		value = c.a;
		break;
	case EBX:
		value = c.b;
		break;
	case ECX:
		value = c.c;
		break;
	case EDX:
		value = c.d;
		break;
	}

	report((value & ci->mask) == ci->value,
	       "cpuid check failure, eax %x, ecx %x, reg %x, mask %x, expect %x, got %x\n",
	       ci->eax, ci->ecx, ci->reg, ci->mask, ci->value, value);
}

CPUIDINFO cpuid_all_zero_info[] = {
	{.eax = 3},
	{.eax = 8},
	{.eax = 0xe},
	{.eax = 0x11},
	{.eax = 0x12},
	{.eax = 0x13},
	{.eax = 0x20},
};

static void test_cpuid(void)
{
	int i;

	for (i = 0; i < sizeof(cpuid_info)/sizeof(*cpuid_info); i++)
	{
		check_cpuid_fixed(cpuid_info + i);
	}

	/* Some cpuid result are all zero */
	for (i = 0; i < sizeof(cpuid_all_zero_info)/sizeof(*cpuid_all_zero_info); i++)
	{
		CPUIDINFO *ci = cpuid_all_zero_info + i;
		ci->mask = CPUID_FIXED1;

		for (int j = 0; j < 4; j++) {
			ci->reg = j;
			check_cpuid_fixed(cpuid_info + i);
		}
	}

	/* Leaf 0xd / Sub-leaves 0x2-0x12 EDX zero */
	for (i = 2; i <= 0x12; i++) {
		CPUIDINFO ci = {.eax = 0xd, .needs_ecx = true, .ecx = i, .reg = EDX, .mask = CPUID_FIXED1};
		check_cpuid_fixed(&ci);
	}
}

int main(void)
{
	if (!is_tdx_guest()) {
		printf("Not TDX environment!\n");
		return report_summary();
	}

	test_selfipi_msr();
	test_single_step();
	test_cpuid();
	return report_summary();
}
