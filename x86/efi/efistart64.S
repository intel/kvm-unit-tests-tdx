/* Startup code and pre-defined data structures */

#include "apic-defs.h"
#include "asm-generic/page.h"
#include "crt0-efi-x86_64.S"


/* Reserve stack in .data */
.data
.align PAGE_SIZE
	. = . + PAGE_SIZE * MAX_TEST_CPUS
.globl stacktop
stacktop:

.globl smp_stacktop
smp_stacktop:	.long 0

.align PAGE_SIZE
.globl ptl2
ptl2:
	. = . + 4 * PAGE_SIZE
.align PAGE_SIZE

.globl ptl3
ptl3:
	. = . + PAGE_SIZE
.align PAGE_SIZE

.globl ptl4
ptl4:
	. = . + PAGE_SIZE
.align PAGE_SIZE

.globl ptl5
ptl5:
	. = . + PAGE_SIZE
.align PAGE_SIZE

.section .init
.code64
.text

.macro load_absolute_addr64, addr, reg
	call 1f
1:
	popq \reg
	addq \addr - 1b, \reg
.endm

MSR_GS_BASE = 0xc0000101

.macro setup_percpu_area_64
	lea -4096(%rsp), %rax
	movq $0, %rdx
	movq $MSR_GS_BASE, %rcx
	wrmsr
.endm

.macro prepare_td
	load_absolute_addr64 $gdt_descr, %rdx
	lgdt (%rdx)

	movq $MSR_GS_BASE, %rcx
	rdmsr

	/* Update data segments */
	mov $0x10, %bx
	mov %bx, %ds
	mov %bx, %es
	mov %bx, %fs
	mov %bx, %gs
	mov %bx, %ss

	/* restore MSR_GS_BASE */
	wrmsr
.endm

.globl tdx_ap_start64
tdx_ap_start64:
	movq $-PAGE_SIZE, %rsp
	lock xadd %rsp, smp_stacktop(%rip)
	setup_percpu_area_64
	prepare_td
	load_absolute_addr64 $ap_start64, %rdx
	pushq $0x08
	pushq %rdx
	lretq

.code16
REALMODE_GDT_LOWMEM = PAGE_SIZE - 2

.globl rm_trampoline
rm_trampoline:

.globl sipi_entry
sipi_entry:
	mov %cr0, %eax
	or $1, %eax
	mov %eax, %cr0

	/* Retrieve relocated ap_rm_gdt_descr address at REALMODE_GDT_LOWMEM. */
	mov (REALMODE_GDT_LOWMEM), %ebx
	lgdtl (%ebx)

	lcall $0x18, $0x0

.globl ap_rm_gdt
ap_rm_gdt:
	.quad 0
	.quad 0x00cf9b000000ffff // flat 32-bit code segment
	.quad 0x00cf93000000ffff // flat 32-bit data segment
	.quad 0                  // call gate to 32-bit AP entrypoint
.globl ap_rm_gdt_end
ap_rm_gdt_end:

.globl ap_rm_gdt_descr
ap_rm_gdt_descr:
	.word 0
	.long 0

.globl sipi_end
sipi_end:

.globl rm_trampoline_end
rm_trampoline_end:

#include "../trampolines.S"
