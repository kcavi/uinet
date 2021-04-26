/*-
 * Copyright (c) 1997 Peter Wemm <peter@freebsd.org>
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#ifndef _USP_SYS_POLL_H_
#define	_USP_SYS_POLL_H_

/*
 * This file is intended to be compatible with the traditional poll.h.
 */

typedef	unsigned int	usp_nfds_t;

/*
 * This structure is passed as an array to poll(2).
 */
struct usp_pollfd {
	int	fd;		/* which file descriptor to poll */
	short	events;		/* events we are interested in */
	short	revents;	/* events found on return */
};

/*
 * Requestable events.  If poll(2) finds any of these set, they are
 * copied to revents on return.
 * XXX Note that FreeBSD doesn't make much distinction between POLLPRI
 * and POLLRDBAND since none of the file types have distinct priority
 * bands - and only some have an urgent "mode".
 * XXX Note POLLIN isn't really supported in true SVSV terms.  Under SYSV
 * POLLIN includes all of normal, band and urgent data.  Most poll handlers
 * on FreeBSD only treat it as "normal" data.
 */
#define	USP_POLLIN		0x0001		/* any readable data available */
#define	USP_POLLPRI		0x0002		/* OOB/Urgent readable data */
#define	USP_POLLOUT		0x0004		/* file descriptor is writeable */
#define	USP_POLLRDNORM	0x0040		/* non-OOB/URG data available */
#define	USP_POLLWRNORM	POLLOUT		/* no write type differentiation */
#define	USP_POLLRDBAND	0x0080		/* OOB/Urgent readable data */
#define	USP_POLLWRBAND	0x0100		/* OOB/Urgent data can be written */


#define	USP_POLLINIGNEOF	0x2000		/* like POLLIN, except ignore EOF */


/*
 * These events are set if they occur regardless of whether they were
 * requested.
 */
#define	USP_POLLERR		0x0008		/* some poll error occurred */
#define	USP_POLLHUP		0x0010		/* file descriptor was "hung up" */
#define	USP_POLLNVAL	0x0020		/* requested events "invalid" */


#endif /* !_USP_POLL_H_ */
