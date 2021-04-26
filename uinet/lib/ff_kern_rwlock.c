/*-
 * Copyright (c) 2010 Kip Macy
 * All rights reserved.
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Derived in part from libplebnet's pn_lock.c.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/rwlock.h>
#include <sys/proc.h>

#include "ff_host_interface.h"

static void
assert_rw(struct lock_object *lock, int what)
{
	rw_assert((struct rwlock *)lock, what);
}

#if 0
void
lock_rw(struct lock_object *lock, uintptr_t how)
{
	struct rwlock *rw;

	rw = (struct rwlock *)lock;
	if (how)
		rw_rlock(rw);
	else
		rw_wlock(rw);
}

uintptr_t
unlock_rw(struct lock_object *lock)
{
	struct rwlock *rw;

	rw = (struct rwlock *)lock;
	rw_assert(rw, RA_LOCKED | LA_NOTRECURSED);
	if (rw->rw_lock & RW_LOCK_READ) {
		rw_runlock(rw);
		return (1);
	} else {
		rw_wunlock(rw);
		return (0);
	}
}
#endif

#if 0
struct lock_class lock_class_rw = {
	.lc_name = "rw",
	.lc_flags = LC_SLEEPLOCK | LC_RECURSABLE | LC_UPGRADABLE,
	.lc_assert = assert_rw,
#ifdef DDB
	.lc_ddb_show = db_show_rwlock,
#endif
#if 0
	.lc_lock = lock_rw,
	.lc_unlock = unlock_rw,
#endif
#ifdef KDTRACE_HOOKS
	.lc_owner = owner_rw,
#endif
};
#endif

#if 0
void
rw_sysinit(void *arg)
{
	struct rw_args *args = arg;

	rw_init((struct rwlock *)args->ra_rw, args->ra_desc);
}


void
rw_sysinit_flags(void *arg)
{
    rw_sysinit(arg);
}

#endif


/*
 * Return the rwlock address when the lock cookie address is provided.
 * This functionality assumes that struct rwlock* have a member named rw_lock.
 */
#define	rwlock2rw(c)	(__containerof(c, struct rwlock, rw_lock))

void
_rw_init_flags(volatile uintptr_t *c, const char *name, int opts)
{
	struct rwlock *rw;
	int flags;

	rw = rwlock2rw((void *)c);
	
	MPASS((opts & ~(RW_DUPOK | RW_NOPROFILE | RW_NOWITNESS | RW_QUIET |
	    RW_RECURSE)) == 0);

	flags = LO_UPGRADABLE;
	if (opts & RW_DUPOK)
		flags |= LO_DUPOK;
	if (opts & RW_NOPROFILE)
		flags |= LO_NOPROFILE;
	if (!(opts & RW_NOWITNESS))
		flags |= LO_WITNESS;
	if (opts & RW_RECURSE)
		flags |= LO_RECURSABLE;
	if (opts & RW_QUIET)
		flags |= LO_QUIET;
	
	 lock_init(&rw->lock_object, &lock_class_rw, name, NULL, flags);
	if (0 != uhi_rwlock_init(&rw->rw_lock, flags & RW_RECURSE ? UHI_RW_WRECURSE : 0))
		panic("Could not initialize rwlock");
}


void
_rw_destroy(volatile uintptr_t *c)
{
	uhi_rwlock_destroy((uhi_rwlock_t *)c);
}

void
_rw_wlock_cookie(volatile uintptr_t *c, const char *file, int line)
{
	_uhi_rwlock_wlock((uhi_rwlock_t *)c, (void *)c, file, line);
}

int
__rw_try_wlock(volatile uintptr_t *c, const char *file, int line)
{
	int rval;

	rval = _uhi_rwlock_trywlock((uhi_rwlock_t *)c, (void *)c, file, line);

	return (rval);
}

void
_rw_wunlock_cookie(volatile uintptr_t *c, const char *file, int line)
{
	_uhi_rwlock_wunlock((uhi_rwlock_t *)c, (void *)c, file, line);
}

void
__rw_rlock(volatile uintptr_t *c, const char *file, int line)
{
	_uhi_rwlock_rlock((uhi_rwlock_t *)c, (void *)c, file, line);
}

int
__rw_try_rlock(volatile uintptr_t *c, const char *file, int line)
{
	int rval;
	rval = _uhi_rwlock_tryrlock((uhi_rwlock_t *)c, (void *)c, file, line);
	return (rval);
}

void
_rw_runlock_cookie(volatile uintptr_t *c, const char *file, int line)
{
	_uhi_rwlock_runlock((uhi_rwlock_t *)c, (void *)c, file, line);
}

int
__rw_try_upgrade(volatile uintptr_t *c, const char *file, int line)
{
	int rval;

	rval = _uhi_rwlock_tryupgrade((uhi_rwlock_t *)c, (void *)c, file, line);
	/* 0 means fail; non-zero means success */
	/* XXX uhi_rwlock_tryupgrade always returns 0? */

	return (rval);
}

void
__rw_downgrade(volatile uintptr_t *c, const char *file, int line)
{
	_uhi_rwlock_downgrade((uhi_rwlock_t *)c, (void *)c, file, line);
}


/*
 * Return a pointer to the owning thread if the lock is write-locked or
 * NULL if the lock is unlocked or read-locked.
 */

#define	RW_READ_VALUE(x)	((x)->rw_lock)

#define	lv_rw_wowner(v)							\
	((uintptr_t(v)) & RW_LOCK_READ ? NULL :					\
	 (struct thread *)RW_OWNER((uintptr_t(v))))

#define	rw_wowner(rw)	lv_rw_wowner(RW_READ_VALUE(rw))

int
_rw_wowned(const volatile uintptr_t *c)
{
#if 0
	struct rwlock *rw;

	rw = rwlock2rw(c);
	return (rw_wowner(rw) == curthread);
#else
	return 1;
#endif
}
