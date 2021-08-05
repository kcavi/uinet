/*
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *	 list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *	 this list of conditions and the following disclaimer in the documentation
 *	 and/or other materials provided with the distribution.
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
 * Derived in part from libuinet's uinet_host_interface.c.
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>

#include "ff_host_interface.h"
#include "ff_errno.h"

static struct timespec current_ts;
void ff_th_init(const char *name);
int pthread_setname_np(pthread_t thread, const char *name);


void uhi_clock_gettime(int id, int64_t *sec, long *nsec)
{
	struct timespec ts;
	int host_id;
	int rv;

	switch (id) {
	case UHI_CLOCK_REALTIME:
		host_id = CLOCK_REALTIME;
		break;
#ifdef CLOCK_MONOTONIC_FAST
	case UHI_CLOCK_MONOTONIC_FAST:
		host_id = CLOCK_MONOTONIC_FAST;
		break;
#endif
	case UHI_CLOCK_MONOTONIC:
	default:
		host_id = CLOCK_MONOTONIC;
		break;
	}

	rv = clock_gettime(host_id, &ts);
	assert(0 == rv);

	*sec = (int64_t)ts.tv_sec;
	*nsec = (long)ts.tv_nsec;

}


int uhi_cond_init(uhi_cond_t *c)
{
	pthread_condattr_t attr;
	pthread_cond_t *pc;
	int error;


	pc = malloc(sizeof(pthread_cond_t));
	if (NULL == pc)
		return (ENOMEM);

	*c = pc;

	pthread_condattr_init(&attr);

	error = pthread_cond_init(pc, &attr);
	pthread_condattr_destroy(&attr);

	return (error);
}


void uhi_cond_destroy(uhi_cond_t *c)
{
	pthread_cond_t *pc;

	pc = (pthread_cond_t *)(*c);

	pthread_cond_destroy(pc);
	free(pc);
}


void uhi_cond_wait(uhi_cond_t *c, uhi_mutex_t *m)
{
	pthread_cond_wait((pthread_cond_t *)(*c), (pthread_mutex_t *)(*m));
}


int uhi_cond_timedwait(uhi_cond_t *c, uhi_mutex_t *m, uint64_t nsecs)
{
	struct timespec abstime;
	int64_t now_sec;
	long now_nsec;
	uint64_t total_nsec;

	uhi_clock_gettime(UHI_CLOCK_REALTIME, &now_sec, &now_nsec);

	abstime.tv_sec = now_sec + nsecs / UHI_NSEC_PER_SEC;
	total_nsec = now_nsec + nsecs % UHI_NSEC_PER_SEC;
	if (total_nsec >= UHI_NSEC_PER_SEC) {
		total_nsec -= UHI_NSEC_PER_SEC;
		abstime.tv_sec++;
	}
	abstime.tv_nsec = total_nsec;

	return (pthread_cond_timedwait((pthread_cond_t *)(*c), (pthread_mutex_t *)(*m), &abstime));
}


void uhi_cond_signal(uhi_cond_t *c)
{
	pthread_cond_signal((pthread_cond_t *)(*c));
}


void uhi_cond_broadcast(uhi_cond_t *c)
{
	pthread_cond_broadcast((pthread_cond_t *)(*c));
}


int uhi_mutex_init(uhi_mutex_t *m, int opts)
{
	pthread_mutexattr_t attr;
	pthread_mutex_t *pm;
	int error;

	pm = malloc(sizeof(pthread_mutex_t));
	if (NULL == pm)
		return (ENOMEM);

	*m = pm;

	pthread_mutexattr_init(&attr);

	if (opts & UHI_MTX_RECURSE) {
		if (0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE))
			printf("Warning: mtx will not be recursive\n");
	} else {
		if (0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP))
			pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
	}

	error = pthread_mutex_init(pm, &attr);
	pthread_mutexattr_destroy(&attr);

	return (error);
}


void uhi_mutex_destroy(uhi_mutex_t *m)
{
	pthread_mutex_t *pm;

	pm = (pthread_mutex_t *)(*m);

	pthread_mutex_destroy(pm);
	free(pm);
}



void _uhi_mutex_lock(uhi_mutex_t *m, void *l, const char *file, int line)
{
	pthread_mutex_lock((pthread_mutex_t *)(*m));
}


/*
 * Returns 0 if the mutex cannot be acquired, non-zero if it can.
 */
int _uhi_mutex_trylock(uhi_mutex_t *m, void *l, const char *file, int line)
{
	int ret;
	ret = (0 == pthread_mutex_trylock((pthread_mutex_t *)(*m)));

	return (ret);
}


void _uhi_mutex_unlock(uhi_mutex_t *m, void *l, const char *file, int line)
{
	pthread_mutex_unlock((pthread_mutex_t *)(*m));
}

int uhi_rwlock_init(uhi_rwlock_t *rw, int opts)
{
	pthread_rwlockattr_t attr;
	pthread_rwlock_t *pm;
	int error;

	pm = malloc(sizeof(pthread_rwlock_t));
	if (NULL == pm)
		return (ENOMEM);


	error = pthread_rwlock_init(pm, NULL);
	*rw = pm;

	return (error);
}


void uhi_rwlock_destroy(uhi_rwlock_t *rw)
{
	pthread_rwlock_t *pm;

	pm = (pthread_rwlock_t *)(*rw);

	pthread_rwlock_destroy(pm);
	free(pm);
}


void _uhi_rwlock_wlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	if(*rw ==  NULL)
	{
		printf("%s %d rw=0x%p\n",__func__,__LINE__,*rw);
		return ;
	}

	pthread_rwlock_wrlock((pthread_rwlock_t *)(*rw));
}


int _uhi_rwlock_trywlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	int ret;

	ret = (0 == pthread_rwlock_trywrlock((pthread_rwlock_t *)(*rw)));
	return (ret);
}


void _uhi_rwlock_wunlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	if(*rw ==  NULL)
	{
		printf("%s %d rw=0x%p\n",__func__,__LINE__,*rw);
		return ;
	}
	pthread_rwlock_unlock((pthread_rwlock_t *)(*rw));
}


void _uhi_rwlock_rlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	if(*rw ==  NULL)
	{
		printf("%s %d rw=0x%p\n",__func__,__LINE__,*rw);
		return ;
	}

	pthread_rwlock_rdlock((pthread_rwlock_t *)(*rw));
}


int _uhi_rwlock_tryrlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	int ret;

	ret = (0 == pthread_rwlock_tryrdlock((pthread_rwlock_t *)(*rw)));
	return (ret);
}


void _uhi_rwlock_runlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	if(*rw ==  NULL)
	{
		printf("%s %d\n",__func__,__LINE__);
		return ;
	}
	pthread_rwlock_unlock((pthread_rwlock_t *)(*rw));
}


int _uhi_rwlock_tryupgrade(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	/*
	 * Always succeeds as this implementation is always an exclusive
	 * lock
	 */
	return (1);
}


void _uhi_rwlock_downgrade(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	/*
	 * Nothing to do here.	In this implementation, there is only one
	 * grade of this lock.
	 */
}


int uhi_nanosleep(uint64_t nsecs)
{
	struct timespec ts;
	struct timespec rts;
	int rv;

	ts.tv_sec = nsecs / UHI_NSEC_PER_SEC;
	ts.tv_nsec = nsecs % UHI_NSEC_PER_SEC;
	while ((-1 == (rv = nanosleep(&ts, &rts))) && (EINTR == errno)) {
		ts = rts;
	}
	if (-1 == rv) {
		rv = errno;
	}

	return (rv);
}

int ff_sleep(uint32_t secs)
{
	sleep(secs);
}

int ff_msleep(uint32_t msecs)
{
	usleep(msecs * 1000);
}

int ff_usleep(uint32_t usecs)
{
	usleep(usecs);
}



int linux_open(const char *pathname, int flags, mode_t mode)
{
	//int fd = open(pathname, O_RDWR|O_CREAT /* flags*/,  777/*mode*/);

	int fd = open(pathname,	 flags,	 mode);
	return fd;
}


void ff_thread_set_name(const char *name)
{
	if (name != NULL) {
		pthread_setname_np(pthread_self(), name);
	}
}


/*
 *	prio runs from 0 to 100, with 0 corresponding to the minimum possible
 *	priority and 100 corresponding to the maximum possible priority.
 */
int uhi_thread_setprio(unsigned int prio)
{
	int policy;
	struct sched_param sparam;

	policy = SCHED_OTHER;
	sparam.sched_priority =
		sched_get_priority_min(policy) +
		((sched_get_priority_max(policy) - sched_get_priority_min(policy)) * prio) / 100;

	return (pthread_setschedparam(pthread_self(), policy, &sparam));
}


/*
 *	prio runs from 0 to 100, with 0 corresponding to the minimum possible
 *	priority and 100 corresponding to the maximum possible priority.
 */
int uhi_thread_setprio_rt(unsigned int prio)
{
	pthread_t t;
	int policy;
	struct sched_param sparam;

	t = pthread_self();

	policy = SCHED_RR;
	sparam.sched_priority =
		sched_get_priority_min(policy) +
		((sched_get_priority_max(policy) - sched_get_priority_min(policy)) * prio) / 100;

	if (0 != pthread_setschedparam(t, policy, &sparam)) {
		policy = SCHED_FIFO;
		sparam.sched_priority =
			sched_get_priority_min(policy) +
			((sched_get_priority_max(policy) - sched_get_priority_min(policy)) * prio) / 100;

			return (pthread_setschedparam(t, policy, &sparam));
	}

	return (0);
}




static void *pthread_start_routine(void *arg)
{
	struct uhi_thread_start_args *tsa = arg;
	int error;
#if 0
	/*
	 * uinet_shutdown() waits for a message from the shutdown thread
	 * indicating shutdown is complete.	 If uinet_shutdown() is called
	 * from a signal handler running in a thread context that is holding
	 * a lock that the shutdown activity needs to acquire in order to
	 * complete, deadlock will occur.  Masking all signals in all
	 * internal uinet threads prevents such a deadlock by preventing all
	 * signal handlers (and thus any that might call uinet_shutdown())
	 * from running in the context of any thread that might be holding a
	 * lock required by the shutdown thread.
	 */
	uhi_mask_all_signals();

	if (tsa->set_tls) {
		error = uhi_tls_set(tsa->tls_key, tsa->tls_data);
		if (error != 0)
			printf("Warning: unable to set user-supplied thread-specific data (%d)\n", error);
	}

	error = uhi_tls_set(uhi_thread_tls_key, tsa);
	if (error != 0)
		printf("Warning: unable to set uhi thread-specific data (%d)\n", error);

	uhi_thread_set_name(tsa->name);

	uhi_thread_run_hooks(UHI_THREAD_HOOK_START);

	if (tsa->start_notify_routine)
		tsa->start_notify_routine(tsa->start_notify_routine_arg);
#endif

	ff_th_init(tsa->name);

	tsa->start_routine(tsa->start_routine_arg);

	return (NULL);
}


int uhi_thread_create(uhi_thread_t *new_thread, struct uhi_thread_start_args *start_args, unsigned int stack_bytes)
{
	int error;
	pthread_t thread;
	pthread_attr_t attr;


	pthread_attr_init(&attr);
	if (stack_bytes) {
		pthread_attr_setstacksize(&attr, stack_bytes);
	}

	error = pthread_create(&thread, &attr, pthread_start_routine, start_args);
	pthread_attr_destroy(&attr);

	if (new_thread)
		*new_thread = (uhi_thread_t)thread;

	return (error);

}


int rsp_pthread_create(char *name, pthread_t *thread, const pthread_attr_t *attr,
						  void *(*start_routine) (void *), void *arg)
{
	struct uhi_thread_start_args *tsa;
	uhi_thread_t host_thread;
	tsa = malloc(sizeof(struct uhi_thread_start_args));
	memset(tsa,0,sizeof(struct uhi_thread_start_args));

	tsa->start_routine = start_routine;
	tsa->start_routine_arg = arg;
	tsa->end_routine = NULL;
	strncpy(tsa->name,name,sizeof(tsa->name) - 1);



	uhi_thread_create(&host_thread, tsa, 0);

}


void *
ff_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset)
{
	int host_prot;
	int host_flags;

	assert(ff_PROT_NONE == PROT_NONE);
	host_prot = 0;
	if ((prot & ff_PROT_READ) == ff_PROT_READ)	 host_prot |= PROT_READ;
	if ((prot & ff_PROT_WRITE) == ff_PROT_WRITE) host_prot |= PROT_WRITE;

	host_flags = 0;
	if ((flags & ff_MAP_SHARED) == ff_MAP_SHARED)	host_flags |= MAP_SHARED;
	if ((flags & ff_MAP_PRIVATE) == ff_MAP_PRIVATE) host_flags |= MAP_PRIVATE;
	if ((flags & ff_MAP_ANON) == ff_MAP_ANON)		host_flags |= MAP_ANON;

	void *ret = (mmap(addr, len, host_prot, host_flags, fd, offset));

	if (ret == (void *) -1) {
		printf("fst mmap failed:%s\n", strerror(errno));
		exit(1);
	}
	return ret;
}

int
ff_munmap(void *addr, uint64_t len)
{
	return (munmap(addr, len));
}


void *
ff_malloc(unsigned long size)
{
	return (malloc(size));
}


void *
ff_calloc(unsigned long number, unsigned long size)
{
	return (calloc(number, size));
}


void *
ff_realloc(void *p, unsigned long size)
{
	if (size) {
		return (realloc(p, size));
	}

	return (p);
}

void *rsp_malloc(unsigned long size)
{
	void *alloc;

	alloc = malloc(size);

	if(alloc)
		bzero(alloc, size);
	return (alloc);
}

void *rsp_calloc(unsigned long number, unsigned long size)
{
	return (calloc(number, size));
}


void *rsp_free(void *p)
{
	 free(p);
}


void
ff_free(void *p)
{
	free(p);
}

void panic(const char *, ...) __attribute__((__noreturn__));

const char *panicstr = NULL;

void
panic(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	//vprintf(fmt, ap);
	printf(fmt, ap);
	va_end(ap);

	abort();
}

void
ff_clock_gettime(int id, int64_t *sec, long *nsec)
{
	struct timespec ts;
	int host_id;
	int rv;

	switch (id) {
	case ff_CLOCK_REALTIME:
		host_id = CLOCK_REALTIME;
		break;
#ifdef CLOCK_MONOTONIC_FAST
	case ff_CLOCK_MONOTONIC_FAST:
		host_id = CLOCK_MONOTONIC_FAST;
		break;
#endif
	case ff_CLOCK_MONOTONIC:
	default:
		host_id = CLOCK_MONOTONIC;
		break;
	}

	rv = clock_gettime(host_id, &ts);
	assert(0 == rv);

	*sec = (int64_t)ts.tv_sec;
	*nsec = (long)ts.tv_nsec;
}

uint64_t
ff_clock_gettime_ns(int id)
{
	int64_t sec;
	long nsec;

	ff_clock_gettime(id, &sec, &nsec);

	return ((uint64_t)sec * ff_NSEC_PER_SEC + nsec);
}

void
ff_get_current_time(time_t *sec, long *nsec)
{
	if (sec) {
		*sec = current_ts.tv_sec;
	}

	if (nsec) {
		*nsec = current_ts.tv_nsec;
	}
}

void
ff_update_current_ts()
{
	int rv = clock_gettime(CLOCK_REALTIME, &current_ts);
	assert(rv == 0);
}

int get_random(void *ptr, unsigned int len)
{
	int fd = -1;
	unsigned int seed = 0;
	int size;
	fd = open ("/dev/urandom", O_RDONLY);
	if (fd < 0)
	{
		printf("Can not open /dev/urandom\n");
		return -1;
	}
	else
	{
		size = read(fd, ptr, len);
		close(fd);
	}
	return 0;


}

void
ff_arc4rand(void *ptr, unsigned int len, int reseed)
{
	(void)reseed;

	//RAND_bytes(ptr, len);
	get_random(ptr, len);
}

uint32_t
ff_arc4random(void)
{
	uint32_t ret;
	ff_arc4rand(&ret, sizeof ret, 0);
	return ret;
}

int ff_setenv(const char *name, const char *value)
{
	return setenv(name, value, 1);
}

char *ff_getenv(const char *name)
{
	return getenv(name);
}

void ff_os_errno(int error)
{
	switch (error) 
	{
		case ff_EPERM:		 errno = EPERM; break;
		case ff_ENOENT:		 errno = ENOENT; break;
		case ff_ESRCH:		 errno = ESRCH; break;
		case ff_EINTR:		 errno = EINTR; break;
		case ff_EIO:		 errno = EIO; break;
		case ff_ENXIO:		 errno = ENXIO; break;
		case ff_E2BIG:		 errno = E2BIG; break;
		case ff_ENOEXEC:	 errno = ENOEXEC; break;
		case ff_EBADF:		 errno = EBADF; break;
		case ff_ECHILD:		 errno = ECHILD; break;
		case ff_EDEADLK:	 errno = EDEADLK; break;
		case ff_ENOMEM:		 errno = ENOMEM; break;
		case ff_EACCES:		 errno = EACCES; break;
		case ff_EFAULT:		 errno = EFAULT; break;
		case ff_ENOTBLK:	 errno = ENOTBLK; break;
		case ff_EBUSY:		 errno = EBUSY; break;
		case ff_EEXIST:		 errno = EEXIST; break;
		case ff_EXDEV:		 errno = EXDEV; break;
		case ff_ENODEV:		 errno = ENODEV; break;
		case ff_ENOTDIR:	 errno = ENOTDIR; break;
		case ff_EISDIR:		 errno = EISDIR; break;
		case ff_EINVAL:		 errno = EINVAL; break;
		case ff_ENFILE:		 errno = ENFILE; break;
		case ff_EMFILE:		 errno = EMFILE; break;
		case ff_ENOTTY:		 errno = ENOTTY; break;
		case ff_ETXTBSY:	 errno = ETXTBSY; break;
		case ff_EFBIG:		 errno = EFBIG; break;
		case ff_ENOSPC:		 errno = ENOSPC; break;
		case ff_ESPIPE:		 errno = ESPIPE; break;
		case ff_EROFS:		 errno = EROFS; break;
		case ff_EMLINK:		 errno = EMLINK; break;
		case ff_EPIPE:		 errno = EPIPE; break;
		case ff_EDOM:		 errno = EDOM; break;
		case ff_ERANGE:		 errno = ERANGE; break;

		/* case ff_EAGAIN:		 same as EWOULDBLOCK */
		case ff_EWOULDBLOCK:	 errno = EWOULDBLOCK; break;

		case ff_EINPROGRESS:	 errno = EINPROGRESS; break;
		case ff_EALREADY:		 errno = EALREADY; break;
		case ff_ENOTSOCK:		 errno = ENOTSOCK; break;
		case ff_EDESTADDRREQ:	 errno = EDESTADDRREQ; break;
		case ff_EMSGSIZE:		 errno = EMSGSIZE; break;
		case ff_EPROTOTYPE:		 errno = EPROTOTYPE; break;
		case ff_ENOPROTOOPT:	 errno = ENOPROTOOPT; break;
		case ff_EPROTONOSUPPORT: errno = EPROTONOSUPPORT; break;
		case ff_ESOCKTNOSUPPORT: errno = ESOCKTNOSUPPORT; break;

		/* case ff_EOPNOTSUPP:	 same as ENOTSUP */
		case ff_ENOTSUP:		 errno = ENOTSUP; break;

		case ff_EPFNOSUPPORT:	 errno = EPFNOSUPPORT; break;
		case ff_EAFNOSUPPORT:	 errno = EAFNOSUPPORT; break;
		case ff_EADDRINUSE:		 errno = EADDRINUSE; break;
		case ff_EADDRNOTAVAIL:	 errno = EADDRNOTAVAIL; break;
		case ff_ENETDOWN:		 errno = ENETDOWN; break;
		case ff_ENETUNREACH:	 errno = ENETUNREACH; break;
		case ff_ENETRESET:		 errno = ENETRESET; break;
		case ff_ECONNABORTED:	 errno = ECONNABORTED; break;
		case ff_ECONNRESET:		 errno = ECONNRESET; break;
		case ff_ENOBUFS:		 errno = ENOBUFS; break;
		case ff_EISCONN:		 errno = EISCONN; break;
		case ff_ENOTCONN:		 errno = ENOTCONN; break;
		case ff_ESHUTDOWN:		 errno = ESHUTDOWN; break;
		case ff_ETOOMANYREFS:	 errno = ETOOMANYREFS; break;
		case ff_ETIMEDOUT:		 errno = ETIMEDOUT; break;
		case ff_ECONNREFUSED:	 errno = ECONNREFUSED; break;
		case ff_ELOOP:			 errno = ELOOP; break;
		case ff_ENAMETOOLONG:	 errno = ENAMETOOLONG; break;
		case ff_EHOSTDOWN:		 errno = EHOSTDOWN; break;
		case ff_EHOSTUNREACH:	 errno = EHOSTUNREACH; break;
		case ff_ENOTEMPTY:		 errno = ENOTEMPTY; break;
		case ff_EUSERS:		 errno = EUSERS; break;
		case ff_EDQUOT:		 errno = EDQUOT; break;
		case ff_ESTALE:		 errno = ESTALE; break;
		case ff_EREMOTE:	 errno = EREMOTE; break;
		case ff_ENOLCK:		 errno = ENOLCK; break;
		case ff_ENOSYS:		 errno = ENOSYS; break;
		case ff_EIDRM:		 errno = EIDRM; break;
		case ff_ENOMSG:		 errno = ENOMSG; break;
		case ff_EOVERFLOW:	 errno = EOVERFLOW; break;
		case ff_ECANCELED:	 errno = ECANCELED; break;
		case ff_EILSEQ:		 errno = EILSEQ; break;
		case ff_EBADMSG:	 errno = EBADMSG; break;
		case ff_EMULTIHOP:	 errno = EMULTIHOP; break;
		case ff_ENOLINK:	 errno = ENOLINK; break;
		case ff_EPROTO:		 errno = EPROTO; break;
		default:			  errno = error; break;
	}

}

