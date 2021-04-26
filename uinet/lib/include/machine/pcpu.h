/*
 * Copyright (c) 2010 Kip Macy All rights reserved.
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _FSTACK_MACHINE_PCPU_H_
#define _FSTACK_MACHINE_PCPU_H_

#include_next <machine/pcpu.h>

#undef __curthread
#undef PCPU_GET
#undef PCPU_ADD
#undef PCPU_INC
#undef PCPU_PTR
#undef PCPU_SET

extern __thread struct thread *pcurthread;
extern struct pcpu *pcpup;

#define PCPU_GET(member)         (pcpup->pc_ ## member)
#define PCPU_ADD(member, val)    (pcpup->pc_ ## member += (val))
#define PCPU_INC(member)         PCPU_ADD(member, 1)
#define PCPU_PTR(member)         (&pcpup->pc_ ## member)
#define PCPU_SET(member, val)    (pcpup->pc_ ## member = (val))

static __inline struct thread *
__curthread_ff(void)
{
    return (pcurthread);
}


#define __curthread __curthread_ff

#ifndef curthread
#define curthread __curthread_ff()
#endif
#endif    /* _FSTACK_MACHINE_PCPU_H_ */
