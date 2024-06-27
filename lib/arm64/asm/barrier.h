#ifndef _ASMARM64_BARRIER_H_
#define _ASMARM64_BARRIER_H_
/*
 * From Linux arch/arm64/include/asm/barrier.h
 *
 * Copyright (C) 2017, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#define sev()		asm volatile("sev" : : : "memory")
#define wfe()		asm volatile("wfe" : : : "memory")
#define wfi()		asm volatile("wfi" : : : "memory")
#define yield()		asm volatile("yield" : : : "memory")
#define cpu_relax()	yield()

#define isb()		asm volatile("isb" : : : "memory")
#define dmb(opt)	asm volatile("dmb " #opt : : : "memory")
#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")
#define mb()		dsb(sy)
#define rmb()		dsb(ld)
#define wmb()		dsb(st)
#define smp_mb()	dmb(ish)
#define smp_rmb()	dmb(ishld)
#define smp_wmb()	dmb(ishst)

#define smp_store_release(p, v)                                         \
	do {								\
	        switch (sizeof(*p)) {					\
	        case 1:							\
	                asm volatile ("stlrb %w1, %0"			\
				      : "=Q" (*p) : "r" (v) : "memory"); \
			break;						\
		case 2:							\
			asm volatile ("stlrh %w1, %0"			\
				      : "=Q" (*p) : "r" (v) : "memory"); \
			break;						\
		case 4:							\
			asm volatile ("stlr %w1, %0"			\
				      : "=Q" (*p) : "r" (v) : "memory"); \
			break;						\
		case 8:							\
			asm volatile ("stlr %1, %0"			\
				      : "=Q" (*p) : "r" (v) : "memory"); \
			break;						\
		default:						\
			report_abort("Invalid smp_store_release() operand size"); \
			}						\
	 } while (0)

#include "asm-generic/barrier.h"
#endif /* _ASMARM64_BARRIER_H_ */
