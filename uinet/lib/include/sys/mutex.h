/*
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

#ifndef _FSTACK_SYS_MUTEX_H_
#define _FSTACK_SYS_MUTEX_H_
#include_next <sys/mutex.h>

#if 0
#undef __mtx_lock
#undef __mtx_unlock
#undef __mtx_lock_spin
#undef __mtx_unlock_spin

#undef _mtx_lock_flags
#undef _mtx_unlock_flags
#undef _mtx_lock_spin_flags
#undef _mtx_unlock_spin_flags

#undef thread_lock_flags_
#undef thread_lock
#undef thread_lock_flags
#undef thread_unlock

#undef mtx_trylock_flags_
#undef _mtx_trylock_spin_flags
#undef __mtx_trylock_spin

#undef mtx_init
#undef mtx_destroy
#undef mtx_owned

#define DO_NOTHING do {} while(0)

#define __mtx_lock(mp, tid, opts, file, line) DO_NOTHING
#define __mtx_unlock(mp, tid, opts, file, line) DO_NOTHING
#define __mtx_lock_spin(mp, tid, opts, file, line) DO_NOTHING
#define __mtx_unlock_spin(mp) DO_NOTHING

#define _mtx_lock_flags(m, opts, file, line) DO_NOTHING
#define _mtx_unlock_flags(m, opts, file, line) DO_NOTHING
#define _mtx_lock_spin_flags(m, opts, file, line) DO_NOTHING
#define _mtx_unlock_spin_flags(m, opts, file, line) DO_NOTHING

#define thread_lock_flags_(tdp, opts, file, line) DO_NOTHING
#define thread_lock(tdp) DO_NOTHING
#define thread_lock_flags(tdp, opt)    DO_NOTHING
#define thread_unlock(tdp) DO_NOTHING

#define mtx_trylock_flags_(m, o, f, l) 1
#define _mtx_trylock_spin_flags(m, o, f, l) 1
#define __mtx_trylock_spin(m, t, o, f, l) 1

#endif

void ff_mtx_init(struct mtx *m, const char *name, const char *type, int opts);

#if 0
#define mtx_init(m, n, t, o) \
    ff_mtx_init(&(m)->lock_object, n, t, o)
#else

#undef mtx_init
#define mtx_init(m, n, t, o) \
    ff_mtx_init(m, n, t, o)

#endif /*wyq*/

//#define mtx_destroy(m) DO_NOTHING
//void mtx_destroy(struct mtx *m);
//wyq

#undef mtx_owned
#define mtx_owned(m)    (1)

#endif    /* _FSTACK_SYS_MUTEX_H_ */
