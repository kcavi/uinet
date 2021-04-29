/*-
 * Copyright (c) Peter Wemm <peter@netplex.com.au>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

#ifndef _MACHINE_PCPU_H_
#define	_MACHINE_PCPU_H_

#ifndef _SYS_CDEFS_H_
#error "sys/cdefs.h is a prerequisite for this file"
#endif

/*
 * The SMP parts are setup in pmap.c and locore.s for the BSP, and
 * mp_machdep.c sets up the data for the AP's to "see" when they awake.
 * The reason for doing it via a struct is so that an array of pointers
 * to each CPU's data can be set up for things like "check curproc on all
 * other processors"
 */
#define	PCPU_MD_FIELDS							\
	char	pc_monitorbuf[128] __aligned(128); /* cache line */	\
	struct	pcpu *pc_prvspace;	/* Self-reference */		\
	struct	pmap *pc_curpmap;					\
	struct	amd64tss *pc_tssp;	/* TSS segment active on CPU */	\
	struct	amd64tss *pc_commontssp;/* Common TSS for the CPU */	\
	register_t pc_rsp0;						\
	register_t pc_scratch_rsp;	/* User %rsp in syscall */	\
	u_int	pc_apic_id;						\
	u_int   pc_acpi_id;		/* ACPI CPU id */		\
	/* Pointer to the CPU %fs descriptor */				\
	struct user_segment_descriptor	*pc_fs32p;			\
	/* Pointer to the CPU %gs descriptor */				\
	struct user_segment_descriptor	*pc_gs32p;			\
	/* Pointer to the CPU LDT descriptor */				\
	struct system_segment_descriptor *pc_ldt;			\
	/* Pointer to the CPU TSS descriptor */				\
	struct system_segment_descriptor *pc_tss;			\
	uint64_t	pc_pm_save_cnt;					\
	u_int	pc_cmci_mask;		/* MCx banks for CMCI */	\
	uint64_t pc_dbreg[16];		/* ddb debugging regs */	\
	int pc_dbreg_cmd;		/* ddb debugging reg cmd */	\
	u_int	pc_vcpu_id;		/* Xen vCPU ID */		\
	uint32_t pc_pcid_next;						\
	uint32_t pc_pcid_gen;						\
	char	__pad[149]		/* be divisor of PAGE_SIZE	\
					   after cache alignment */

#define	PC_DBREG_CMD_NONE	0
#define	PC_DBREG_CMD_LOAD	1


#endif /* !_MACHINE_PCPU_H_ */
