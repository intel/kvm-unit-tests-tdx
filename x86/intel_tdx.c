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

#define CPUID_FIXED0 0x0
#define CPUID_FIXED1 0xffffffff

#define CPUID_0_EAX_FIXED	0x23
#define CPUID_0_EAX_MASK	0xffffffff

#define CPUID_1_EAX_MASK	0xf000c000
#define CPUID_1_EBX_FIXED	0x800
#define CPUID_1_EBX_MASK	0xffff
#define CPUID_1_ECX_FIXED	0xc6faa217
#define CPUID_1_ECX_MASK	0xc6fba277
#define CPUID_1_EDX_FIXED	0x7a9fbff
#define CPUID_1_EDX_MASK	0x47bbffff

#define CPUID_3_EAX_MASK	CPUID_FIXED1
#define CPUID_3_EBX_MASK	CPUID_FIXED1
#define CPUID_3_ECX_MASK	CPUID_FIXED1
#define CPUID_3_EDX_MASK	CPUID_FIXED1

#define CPUID_4_0_EAX_MASK	0x3c00
#define CPUID_4_0_EDX_MASK	0x4
#define CPUID_4_1_EAX_MASK	0x3c00
#define CPUID_4_1_EDX_MASK	0x4
#define CPUID_4_2_EAX_MASK	0x3c00
#define CPUID_4_2_EDX_MASK	0x4
#define CPUID_4_3_EAX_MASK	0x3c00
#define CPUID_4_3_EDX_MASK	0xfffffff8
#define CPUID_4_4_EAX_MASK	CPUID_FIXED1
#define CPUID_4_4_EBX_MASK	CPUID_FIXED1
#define CPUID_4_4_ECX_MASK	CPUID_FIXED1
#define CPUID_4_4_EDX_MASK	CPUID_FIXED1

#define CPUID_7_0_EAX_FIXED	0x2
#define CPUID_7_0_EAX_MASK	CPUID_FIXED1
#define CPUID_7_0_EBX_FIXED	0x219424c1
#define CPUID_7_0_EBX_MASK	0x21d464c7
#define CPUID_7_0_ECX_FIXED	0x19000000
#define CPUID_7_0_ECX_MASK	0x7d3e8000
#define CPUID_7_0_EDX_FIXED	0xfc000400
#define CPUID_7_0_EDX_MASK	0xfc223ec3
#define CPUID_7_1_EAX_MASK	0xfbff028f
#define CPUID_7_1_EBX_MASK	CPUID_FIXED1
#define CPUID_7_1_ECX_MASK	CPUID_FIXED1
#define CPUID_7_1_EDX_MASK	CPUID_FIXED1

#define CPUID_8_0_EAX_MASK	CPUID_FIXED1
#define CPUID_8_0_EBX_MASK	CPUID_FIXED1
#define CPUID_8_0_ECX_MASK	CPUID_FIXED1
#define CPUID_8_0_EDX_MASK	CPUID_FIXED1

#define CPUID_a_EDX_MASK	0xffff6000

#define CPUID_d_0_EAX_FIXED	0x3
#define CPUID_d_0_EAX_MASK	0xfff8051b
#define CPUID_d_0_EDX_MASK	CPUID_FIXED1
#define CPUID_d_1_EAX_FIXED	0xf
#define CPUID_d_1_EAX_MASK	0xffffffef
#define CPUID_d_1_ECX_MASK	0xffff26ff
#define CPUID_d_1_EDX_MASK	CPUID_FIXED1

#define CPUID_15_EAX_FIXED	1
#define CPUID_15_EAX_MASK	CPUID_FIXED1
#define CPUID_15_ECX_FIXED	0x17d7840
#define CPUID_15_ECX_MASK	CPUID_FIXED1
#define CPUID_15_EDX_MASK	CPUID_FIXED1

#define CPUID_19_ECX_MASK	0xfffffffe
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
#define CPUID_80000001_ECX_FIXED 0x121
#define CPUID_80000001_EDX_FIXED 0x2c100000
#define CPUID_80000001_EDX_MASK	0xfffff7ff

#define CPUID_80000008_EAX_FIXED 0x3934
#define CPUID_80000008_EAX_MASK CPUID_FIXED1
#define CPUID_80000008_EBX_MASK	0xfffffdff
#define CPUID_80000008_ECX_MASK	CPUID_FIXED1
#define CPUID_80000008_EDX_MASK	CPUID_FIXED1

struct cpuid_info {
	int eax;	/* Input EAX for CPUID */
	int ecx;	/* Input ECX value for CPUID */
	int reg;	/* output register (R_* constant) */
	uint32_t mask;	/* The virtual bit value is fixed 0 */
	uint32_t value;	/* The virtual bit value is fixed 1 */
};

struct cpuid_info cpuid_info[] = {
	{ .eax = 0, .reg = EAX, .mask = CPUID_0_EAX_MASK, .value = CPUID_0_EAX_FIXED },
	{ .eax = 1, .reg = EAX, .mask = CPUID_1_EAX_MASK },
	{ .eax = 1, .reg = EBX, .mask = CPUID_1_EBX_MASK, .value = CPUID_1_EBX_FIXED },
	{ .eax = 1, .reg = ECX, .mask = CPUID_1_ECX_MASK, .value = CPUID_1_ECX_FIXED },
	{ .eax = 1, .reg = EDX, .mask = CPUID_1_EDX_MASK, .value = CPUID_1_EDX_FIXED },
	{ .eax = 3, .reg = EAX, .mask = CPUID_3_EAX_MASK },
	{ .eax = 3, .reg = EBX, .mask = CPUID_3_EBX_MASK },
	{ .eax = 3, .reg = ECX, .mask = CPUID_3_ECX_MASK },
	{ .eax = 3, .reg = EDX, .mask = CPUID_3_EDX_MASK },
	{ .eax = 4, .reg = EAX, .mask = CPUID_4_0_EAX_MASK },
	{ .eax = 4, .ecx = 0, .reg = EDX, .mask = CPUID_4_0_EDX_MASK },
	{ .eax = 4, .ecx = 1, .reg = EAX, .mask = CPUID_4_1_EAX_MASK },
	{ .eax = 4, .ecx = 1, .reg = EDX, .mask = CPUID_4_1_EDX_MASK },
	{ .eax = 4, .ecx = 2, .reg = EAX, .mask = CPUID_4_2_EAX_MASK },
	{ .eax = 4, .ecx = 2, .reg = EDX, .mask = CPUID_4_2_EDX_MASK },
	{ .eax = 4, .ecx = 3, .reg = EAX, .mask = CPUID_4_3_EAX_MASK },
	{ .eax = 4, .ecx = 3, .reg = EDX, .mask = CPUID_4_3_EDX_MASK },
	{ .eax = 4, .ecx = 4, .reg = EAX, .mask = CPUID_4_4_EAX_MASK },
	{ .eax = 4, .ecx = 4, .reg = EBX, .mask = CPUID_4_4_EBX_MASK },
	{ .eax = 4, .ecx = 4, .reg = ECX, .mask = CPUID_4_4_ECX_MASK },
	{ .eax = 4, .ecx = 4, .reg = EDX, .mask = CPUID_4_4_EDX_MASK },
	{ .eax = 7, .ecx = 0, .reg = EAX, .mask = CPUID_7_0_EAX_MASK, .value = CPUID_7_0_EAX_FIXED },
	{ .eax = 7, .ecx = 0, .reg = EBX, .mask = CPUID_7_0_EBX_MASK, .value = CPUID_7_0_EBX_FIXED },
	{ .eax = 7, .ecx = 0, .reg = ECX, .mask = CPUID_7_0_ECX_MASK, .value = CPUID_7_0_ECX_FIXED },
	{ .eax = 7, .ecx = 0, .reg = EDX, .mask = CPUID_7_0_EDX_MASK, .value = CPUID_7_0_EDX_FIXED },
	{ .eax = 7, .ecx = 1, .reg = EAX, .mask = CPUID_7_1_EAX_MASK },
	{ .eax = 7, .ecx = 1, .reg = EBX, .mask = CPUID_7_1_EBX_MASK },
	{ .eax = 7, .ecx = 1, .reg = ECX, .mask = CPUID_7_1_ECX_MASK },
	{ .eax = 7, .ecx = 1, .reg = EDX, .mask = CPUID_7_1_EDX_MASK },
	{ .eax = 0xa, .reg = EDX, .mask = CPUID_a_EDX_MASK },
	{ .eax = 0xd, .ecx = 0, .reg = EAX, .mask = CPUID_d_0_EAX_MASK, .value = CPUID_d_0_EAX_FIXED },
	{ .eax = 0xd, .ecx = 0, .reg = EDX, .mask = CPUID_d_0_EDX_MASK },
	{ .eax = 0xd, .ecx = 1, .reg = EAX, .mask = CPUID_d_1_EAX_MASK, .value = CPUID_d_1_EAX_FIXED },
	{ .eax = 0xd, .ecx = 1, .reg = ECX, .mask = CPUID_d_1_ECX_MASK },
	{ .eax = 0xd, .ecx = 1, .reg = EDX, .mask = CPUID_d_1_EDX_MASK },
	{ .eax = 0x15, .reg = EAX, .mask = CPUID_15_EAX_MASK, .value = CPUID_15_EAX_FIXED },
	{ .eax = 0x15, .reg = ECX, .mask = CPUID_15_ECX_MASK, .value = CPUID_15_ECX_FIXED },
	{ .eax = 0x15, .reg = EDX, .mask = CPUID_15_EDX_MASK },
	{ .eax = 0x19, .reg = ECX, .mask = CPUID_19_ECX_MASK },
	{ .eax = 0x19, .reg = EDX, .mask = CPUID_19_EDX_MASK },
	{ .eax = 0x21, .ecx = 0, .reg = EAX, .mask = CPUID_21_0_EAX_MASK },
	{ .eax = 0x21, .ecx = 0, .reg = EBX, .mask = CPUID_21_0_EBX_MASK, .value = CPUID_21_0_EBX_FIXED },
	{ .eax = 0x21, .ecx = 0, .reg = ECX, .mask = CPUID_21_0_ECX_MASK, .value = CPUID_21_0_ECX_FIXED },
	{ .eax = 0x21, .ecx = 0, .reg = EDX, .mask = CPUID_21_0_EDX_MASK, .value = CPUID_21_0_EDX_FIXED },
	{ .eax = 0x80000000, .reg = EBX, .mask = CPUID_80000000_EBX_MASK },
	{ .eax = 0x80000000, .reg = ECX, .mask = CPUID_80000000_ECX_MASK },
	{ .eax = 0x80000000, .reg = EDX, .mask = CPUID_80000000_EDX_MASK },
	{ .eax = 0x80000001, .reg = EAX, .mask = CPUID_80000001_EAX_MASK },
	{ .eax = 0x80000001, .reg = EBX, .mask = CPUID_80000001_EBX_MASK },
	{ .eax = 0x80000001, .reg = ECX, .mask = CPUID_80000001_ECX_MASK, .value = CPUID_80000001_ECX_FIXED },
	{ .eax = 0x80000001, .reg = EDX, .mask = CPUID_80000001_EDX_MASK, .value = CPUID_80000001_EDX_FIXED },
	{ .eax = 0x80000008, .reg = EAX, .mask = CPUID_80000008_EAX_MASK, .value = CPUID_80000008_EAX_FIXED },
	{ .eax = 0x80000008, .reg = EBX, .mask = CPUID_80000008_EBX_MASK },
	{ .eax = 0x80000008, .reg = ECX, .mask = CPUID_80000008_ECX_MASK },
	{ .eax = 0x80000008, .reg = EDX, .mask = CPUID_80000008_EDX_MASK },
};

struct cpuid_info cpuid_all_zero_info[] = {
	{.eax = 3},
	{.eax = 8},
	{.eax = 0xe},
	{.eax = 0x11},
	{.eax = 0x12},
	{.eax = 0x13},
	{.eax = 0x20},
};

static const char* reg_to_str(enum cpuid_output_regs reg)
{
	switch (reg) {
	case EAX:
		return "EAX";
	case EBX:
		return "EBX";
	case ECX:
		return "ECX";
	case EDX:
		return "EDX";
	default:
		return "Unknown";
	}
}

static void check_cpuid_fixed(struct cpuid_info *ci)
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

	value &= ci->mask;
	report(value == ci->value,
	       "cpuid check: eax 0x%x, ecx 0x%x, reg %s, mask 0x%x, expect 0x%x, got 0x%x",
	       ci->eax, ci->ecx, reg_to_str(ci->reg),
	       ci->mask, ci->value, value);
}

static void test_cpuid(void)
{
	int i;
	printf("\nStart CPUID checking.\n");
	for (i = 0; i < ARRAY_SIZE(cpuid_info); i++) {
		check_cpuid_fixed(cpuid_info + i);
	}

	/* Some cpuid result are all zero */
	for (i = 0; i < ARRAY_SIZE(cpuid_all_zero_info); i++) {
		struct cpuid_info *ci = cpuid_all_zero_info + i;
		ci->mask = CPUID_FIXED1;

		for (int j = 0; j < 4; j++) {
			ci->reg = j;
			check_cpuid_fixed(ci);
		}
	}

	/* Leaf 0xd / Sub-leaves 0x2-0x12 EDX zero */
	for (i = 2; i <= 0x12; i++) {
		struct cpuid_info ci = {.eax = 0xd, .ecx = i, .reg = EDX, .mask = CPUID_FIXED1};
		check_cpuid_fixed(&ci);
	}
	printf("End CPUID checking.\n");
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
