#ifndef _X86_DESC_H_
#define _X86_DESC_H_

#include <setjmp.h>

#ifdef __ASSEMBLY__
#define __ASM_FORM(x, ...)	x,## __VA_ARGS__
#else
#define __ASM_FORM(x, ...)	" " xstr(x,##__VA_ARGS__) " "
#endif

#ifndef __x86_64__
#define __ASM_SEL(a,b)		__ASM_FORM(a)
#else
#define __ASM_SEL(a,b)		__ASM_FORM(b)
#endif

void setup_idt(void);
void load_idt(void);
void setup_alt_stack(void);

struct ex_regs {
	unsigned long rax, rcx, rdx, rbx;
	unsigned long dummy, rbp, rsi, rdi;
#ifdef __x86_64__
	unsigned long r8, r9, r10, r11;
	unsigned long r12, r13, r14, r15;
#endif
	unsigned long vector;
	unsigned long error_code;
	unsigned long rip;
	unsigned long cs;
	unsigned long rflags;
#ifdef __x86_64__
	unsigned long rsp;
	unsigned long ss;
#endif
};

typedef void (*handler)(struct ex_regs *regs);

typedef struct {
	u16 prev;
	u16 res1;
	u32 esp0;
	u16 ss0;
	u16 res2;
	u32 esp1;
	u16 ss1;
	u16 res3;
	u32 esp2;
	u16 ss2;
	u16 res4;
	u32 cr3;
	u32 eip;
	u32 eflags;
	u32 eax, ecx, edx, ebx, esp, ebp, esi, edi;
	u16 es;
	u16 res5;
	u16 cs;
	u16 res6;
	u16 ss;
	u16 res7;
	u16 ds;
	u16 res8;
	u16 fs;
	u16 res9;
	u16 gs;
	u16 res10;
	u16 ldt;
	u16 res11;
	u16 t:1;
	u16 res12:15;
	u16 iomap_base;
} tss32_t;

typedef struct  __attribute__((packed)) {
	u32 res1;
	u64 rsp0;
	u64 rsp1;
	u64 rsp2;
	u64 res2;
	u64 ist1;
	u64 ist2;
	u64 ist3;
	u64 ist4;
	u64 ist5;
	u64 ist6;
	u64 ist7;
	u64 res3;
	u16 res4;
	u16 iomap_base;
} tss64_t;

#define __ASM_TRY(prefix, catch)				\
	"movl $0, %%gs:4\n\t"					\
	".pushsection .data.ex\n\t"				\
	__ASM_SEL(.long, .quad) " 1111f,  " catch "\n\t"	\
	".popsection \n\t"					\
	prefix "\n\t"						\
	"1111:"

#define ASM_TRY(catch) __ASM_TRY("", catch)

/* Forced emulation prefix, used to invoke the emulator unconditionally. */
#define KVM_FEP "ud2; .byte 'k', 'v', 'm';"
#define ASM_TRY_FEP(catch) __ASM_TRY(KVM_FEP, catch)

static inline bool is_fep_available(void)
{
	/*
	 * Use the non-FEP ASM_TRY() as KVM will inject a #UD on the prefix
	 * itself if forced emulation is not available.
	 */
	asm goto(ASM_TRY("%l[fep_unavailable]")
		 KVM_FEP "nop\n\t"
		 ::: "memory" : fep_unavailable);
	return true;
fep_unavailable:
	return false;
}

/*
 * selector     32-bit                        64-bit
 * 0x00         NULL descriptor               NULL descriptor
 * 0x08         ring-0 code segment (32-bit)  ring-0 code segment (64-bit)
 * 0x10         ring-0 data segment (32-bit)  ring-0 data segment (32/64-bit)
 * 0x18         ring-0 code segment (P=0)     ring-0 code segment (64-bit, P=0)
 * 0x20         intr_alt_stack TSS            ring-0 code segment (32-bit)
 * 0x28         ring-0 code segment (16-bit)  same
 * 0x30         ring-0 data segment (16-bit)  same
 * 0x38 (0x3b)  ring-3 code segment (32-bit)  same
 * 0x40 (0x43)  ring-3 data segment (32-bit)  ring-3 data segment (32/64-bit)
 * 0x48 (0x4b)  **unused**                    ring-3 code segment (64-bit)
 * 0x50-0x78    free to use for test cases    same
 * 0x80-0x870   primary TSS (CPU 0..254)      same
 * 0x878-0x1068 percpu area (CPU 0..254)      not used
 *
 * Note that the same segment can be used for 32-bit and 64-bit data segments
 * (the L bit is only defined for code segments)
 *
 * Selectors 0x08-0x10 and 0x3b-0x4b are set up for use with the SYSCALL
 * and SYSRET instructions.
 */

#define KERNEL_CS   0x08
#define KERNEL_DS   0x10
#define NP_SEL      0x18
#ifdef __x86_64__
#define KERNEL_CS32 0x20
#else
#define TSS_INTR    0x20
#endif
#define KERNEL_CS16 0x28
#define KERNEL_DS16 0x30
#define USER_CS32   0x3b
#define USER_DS     0x43
#ifdef __x86_64__
#define USER_CS64   0x4b
#endif

/* Synonyms */
#define KERNEL_DS32 KERNEL_DS
#define USER_DS32   USER_DS

#ifdef __x86_64__
#define KERNEL_CS64 KERNEL_CS
#define USER_CS     USER_CS64
#define KERNEL_DS64 KERNEL_DS
#define USER_DS64   USER_DS
#else
#define KERNEL_CS32 KERNEL_CS
#define USER_CS     USER_CS32
#endif

#define FIRST_SPARE_SEL 0x50
#define TSS_MAIN 0x80

typedef struct {
	unsigned short offset0;
	unsigned short selector;
	unsigned short ist : 3;
	unsigned short : 5;
	unsigned short type : 4;
	unsigned short : 1;
	unsigned short dpl : 2;
	unsigned short p : 1;
	unsigned short offset1;
#ifdef __x86_64__
	unsigned offset2;
	unsigned reserved;
#endif
} idt_entry_t;

typedef struct {
	uint16_t limit1;
	uint16_t base1;
	uint8_t  base2;
	union {
		uint16_t  type_limit_flags;      /* Type and limit flags */
		struct {
			uint16_t type:4;
			uint16_t s:1;
			uint16_t dpl:2;
			uint16_t p:1;
			uint16_t limit2:4;
			uint16_t avl:1;
			uint16_t l:1;
			uint16_t db:1;
			uint16_t g:1;
		} __attribute__((__packed__));
	} __attribute__((__packed__));
	uint8_t  base3;
} __attribute__((__packed__)) gdt_entry_t;

#ifdef __x86_64__
struct system_desc64 {
	gdt_entry_t common;
	uint32_t base4;
	uint32_t zero;
} __attribute__((__packed__));
#endif

#define DESC_BUSY 2

extern idt_entry_t boot_idt[256];

#ifndef __x86_64__
extern tss32_t tss[];
extern tss32_t tss_intr;
void set_gdt_task_gate(u16 tss_sel, u16 sel);
void set_idt_task_gate(int vec, u16 sel);
void set_intr_task_gate(int vec, void *fn);
void setup_tss32(void);
#else
extern tss64_t tss[];
#endif
extern gdt_entry_t gdt[];

struct ex_record {
	unsigned long rip;
	unsigned long handler;
};
extern struct ex_record exception_table_start, exception_table_end;

unsigned exception_vector(void);
unsigned exception_error_code(void);
bool exception_rflags_rf(void);
#ifndef __x86_64__
__attribute__((regparm(1)))
#endif
void do_handle_exception(struct ex_regs *regs);
void set_desc_entry(idt_entry_t *e, size_t e_sz, void *addr,
		    u16 sel, u16 type, u16 dpl);
void set_idt_entry(int vec, void *addr, int dpl);
void set_idt_sel(int vec, u16 sel);
void set_idt_dpl(int vec, u16 dpl);
void set_gdt_entry(int sel, unsigned long base, u32 limit, u8 access, u8 gran);
void load_gdt_tss(size_t tss_offset);
void set_intr_alt_stack(int e, void *fn);
void print_current_tss_info(void);
handler handle_exception(u8 v, handler fn);
void unhandled_exception(struct ex_regs *regs, bool cpu);
const char* exception_mnemonic(int vector);

bool test_for_exception(unsigned int ex, void (*trigger_func)(void *data),
			void *data);
void __set_exception_jmpbuf(jmp_buf *addr);
#define set_exception_jmpbuf(jmpbuf) \
	(setjmp(jmpbuf) ? : (__set_exception_jmpbuf(&(jmpbuf)), 0))

static inline void *get_idt_addr(idt_entry_t *entry)
{
	uintptr_t addr = entry->offset0 | ((u32)entry->offset1 << 16);
#ifdef __x86_64__
	addr |= (u64)entry->offset2 << 32;
#endif
	return (void *)addr;
}

extern gdt_entry_t *get_tss_descr(void);
extern unsigned long get_gdt_entry_base(gdt_entry_t *entry);
extern unsigned long get_gdt_entry_limit(gdt_entry_t *entry);

#endif
