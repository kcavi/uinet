/*
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
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
 * Derived in part from libuinet's uinet_host_interface.h.
 */

#ifndef _FSTACK_HOST_INTERFACE_H_
#define _FSTACK_HOST_INTERFACE_H_

typedef intptr_t uhi_thread_t;
typedef intptr_t uhi_tls_key_t;

struct uhi_thread_start_args {
#define UHI_THREAD_NAME_SIZE	32
	char name[UHI_THREAD_NAME_SIZE];
	void (*start_routine)(void *);
	void *start_routine_arg;
	void (*end_routine)(struct uhi_thread_start_args *);
	void (*start_notify_routine)(void *);
	void *start_notify_routine_arg;
	int set_tls;
	uhi_tls_key_t tls_key;
	void *tls_data;
};



#define ff_PROT_NONE     0x00
#define ff_PROT_READ     0x01
#define ff_PROT_WRITE    0x02

#define ff_MAP_SHARED    0x0001
#define ff_MAP_PRIVATE   0x0002
#define ff_MAP_ANON      0x1000
#define ff_MAP_NOCORE    0x00020000

#define ff_MAP_FAILED    ((void *)-1)

#define UHI_RW_WRECURSE 0x1


void *ff_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset);
int ff_munmap(void *addr, uint64_t len);

void *ff_malloc(unsigned long size);
void *ff_calloc(unsigned long number, unsigned long size);
void *ff_realloc(void *p, unsigned long size);
void ff_free(void *p);

#define ff_CLOCK_REALTIME        0
#define ff_CLOCK_MONOTONIC        4
#define ff_CLOCK_MONOTONIC_FAST       12

#define ff_NSEC_PER_SEC    (1000ULL * 1000ULL * 1000ULL)

void ff_clock_gettime(int id, int64_t *sec, long *nsec);
uint64_t ff_clock_gettime_ns(int id);
uint64_t ff_get_tsc_ns(void);

void ff_get_current_time(time_t *sec, long *nsec);
void ff_update_current_ts(void);

typedef void * ff_mutex_t;
typedef void * ff_cond_t;
typedef void * ff_rwlock_t;

void ff_arc4rand(void *ptr, unsigned int len, int reseed);
uint32_t ff_arc4random(void);

int ff_setenv(const char *name, const char *value);
char *ff_getenv(const char *name);

void ff_os_errno(int error);

int ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport);

typedef void * uhi_cond_t;
typedef void * uhi_mutex_t;
typedef void * uhi_rwlock_t;


#define UHI_CLOCK_REALTIME		0
#define UHI_CLOCK_MONOTONIC		4
#define UHI_CLOCK_MONOTONIC_FAST       12

#define UHI_NSEC_PER_SEC	(1000ULL * 1000ULL * 1000ULL)

#define UHI_MTX_RECURSE	0x1


int  uhi_cond_init(uhi_cond_t *c);
void uhi_cond_destroy(uhi_cond_t *c);
void uhi_cond_wait(uhi_cond_t *c, uhi_mutex_t *m);
int  uhi_cond_timedwait(uhi_cond_t *c, uhi_mutex_t *m, uint64_t nsecs);
void uhi_cond_signal(uhi_cond_t *c);
void uhi_cond_broadcast(uhi_cond_t *c);


int   uhi_nanosleep(uint64_t nsecs);


int   uhi_mutex_init(uhi_mutex_t *m, int opts);
void  uhi_mutex_destroy(uhi_mutex_t *m);


int uhi_nanosleep(uint64_t nsecs);
void uhi_clock_gettime(int id, int64_t *sec, long *nsec);
int   uhi_thread_setprio(unsigned int prio);
int   uhi_thread_setprio_rt(unsigned int prio);
void ff_thread_set_name(const char *name);


int usp_pthread_create(char *name, pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg);



#endif

