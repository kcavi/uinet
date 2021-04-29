/*-
 * Copyright (c) 2003 Peter Wemm.
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Functions to provide access to special i386 instructions.
 * This in included in sys/systm.h, and that file should be
 * used in preference to this.
 */

#ifndef _MACHINE_CPUFUNC_H_
#define	_MACHINE_CPUFUNC_H_

#ifndef _SYS_CDEFS_H_
#error this file needs sys/cdefs.h as a prerequisite
#endif

struct region_descriptor;

#define readb(va)	(*(volatile uint8_t *) (va))
#define readw(va)	(*(volatile uint16_t *) (va))
#define readl(va)	(*(volatile uint32_t *) (va))
#define readq(va)	(*(volatile uint64_t *) (va))

#define writeb(va, d)	(*(volatile uint8_t *) (va) = (d))
#define writew(va, d)	(*(volatile uint16_t *) (va) = (d))
#define writel(va, d)	(*(volatile uint32_t *) (va) = (d))
#define writeq(va, d)	(*(volatile uint64_t *) (va) = (d))


int	breakpoint(void);
u_int	bsfl(u_int mask);
u_int	bsrl(u_int mask);
void	clflush(u_long addr);
void	clts(void);
void	cpuid_count(u_int ax, u_int cx, u_int *p);
void	disable_intr(void);
void	do_cpuid(u_int ax, u_int *p);
void	enable_intr(void);
void	halt(void);
void	ia32_pause(void);
u_char	inb(u_int port);
u_int	inl(u_int port);
void	insb(u_int port, void *addr, size_t count);
void	insl(u_int port, void *addr, size_t count);
void	insw(u_int port, void *addr, size_t count);
register_t	intr_disable(void);
void	intr_restore(register_t rf);
void	invd(void);
void	invlpg(u_int addr);
void	invltlb(void);
u_short	inw(u_int port);
void	lidt(struct region_descriptor *addr);
void	lldt(u_short sel);
void	load_cr0(u_long cr0);
void	load_cr3(u_long cr3);
void	load_cr4(u_long cr4);
void	load_dr0(uint64_t dr0);
void	load_dr1(uint64_t dr1);
void	load_dr2(uint64_t dr2);
void	load_dr3(uint64_t dr3);
void	load_dr4(uint64_t dr4);
void	load_dr5(uint64_t dr5);
void	load_dr6(uint64_t dr6);
void	load_dr7(uint64_t dr7);
void	load_fs(u_short sel);
void	load_gs(u_short sel);
void	ltr(u_short sel);
void	outb(u_int port, u_char data);
void	outl(u_int port, u_int data);
void	outsb(u_int port, const void *addr, size_t count);
void	outsl(u_int port, const void *addr, size_t count);
void	outsw(u_int port, const void *addr, size_t count);
void	outw(u_int port, u_short data);
u_long	rcr0(void);
u_long	rcr2(void);
u_long	rcr3(void);
u_long	rcr4(void);
uint64_t rdmsr(u_int msr);
uint32_t rdmsr32(u_int msr);
uint64_t rdpmc(u_int pmc);
uint64_t rdr0(void);
uint64_t rdr1(void);
uint64_t rdr2(void);
uint64_t rdr3(void);
uint64_t rdr4(void);
uint64_t rdr5(void);
uint64_t rdr6(void);
uint64_t rdr7(void);
uint64_t rdtsc(void);
u_long	read_rflags(void);
u_int	rfs(void);
u_int	rgs(void);
void	wbinvd(void);
void	write_rflags(u_int rf);
void	wrmsr(u_int msr, uint64_t newval);

void	reset_dbregs(void);

#ifdef _KERNEL
int	rdmsr_safe(u_int msr, uint64_t *val);
int	wrmsr_safe(u_int msr, uint64_t newval);
#endif

#endif /* !_MACHINE_CPUFUNC_H_ */
