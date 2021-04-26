/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#ifndef _USP_SYS_SELECT_H_
#define	_USP_SYS_SELECT_H_


typedef	unsigned long	__usp_fd_mask;

/*
 * Select uses bit masks of file descriptors in longs.  These macros
 * manipulate such bit fields (the filesystem macros use chars).
 * FD_SETSIZE may be defined by the user, but the default here should
 * be enough for most uses.
 */

#define	USP_FD_SETSIZE	1024

#define	_USPNFDBITS	(sizeof(__fd_mask) * 8)	/* bits per mask */
#define	_usphowmany(x, y)	(((x) + ((y) - 1)) / (y))


typedef	struct usp_fd_set {
	__fd_mask	__fds_bits[_usphowmany(USP_FD_SETSIZE, _USPNFDBITS)];
} usp_fd_set;


#define	__usp_fdset_mask(n)	((__fd_mask)1 << ((n) % _USPNFDBITS))
#define	USP_FD_CLR(n, p)	((p)->__fds_bits[(n)/_USPNFDBITS] &= ~__fdset_mask(n))

#define	USP_FD_COPY(f, t)	(void)(*(t) = *(f))

#define	USP_FD_ISSET(n, p)	(((p)->__fds_bits[(n)/_USPNFDBITS] & __usp_fdset_mask(n)) != 0)
#define	USP_FD_SET(n, p)	((p)->__fds_bits[(n)/_USPNFDBITS] |= __usp_fdset_mask(n))
#define	USP_FD_ZERO(p) do {					\
	usp_fd_set *_p;					\
	size_t _n;					\
							\
	_p = (p);					\
	_n = _usphowmany(USP_FD_SETSIZE, _USPNFDBITS);		\
	while (_n > 0)					\
		_p->__fds_bits[--_n] = 0;		\
} while (0)

int	usp_select(int, usp_fd_set *, usp_fd_set *, usp_fd_set *, struct timeval *);


#endif /* _USP_SYS_SELECT_H_ */
