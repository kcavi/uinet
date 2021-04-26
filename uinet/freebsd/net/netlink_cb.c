/*-
 * Copyright (c) 1988, 1991, 1993
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
 *	@(#)rtsock.c	8.7 (Berkeley) 10/12/95
 * $FreeBSD$
 */
#include "opt_compat.h"
#include "opt_mpath.h"
#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/rwlock.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/raw_cb.h>
#include <net/route.h>
#include <net/route_var.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_carp.h>
#ifdef INET6
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#endif

#include "netlink_cb.h"




int
netlink_pcballoc(so, pcbinfo)
	struct socket *so;
	struct netlinkpcbinfo *pcbinfo;
{
	register struct netlinkpcb *inp;

	inp = (struct netlinkpcb *)malloc(sizeof(*inp), M_DEVBUF, M_WAITOK | M_ZERO);
	if (inp == NULL)
	{
		return (ENOBUFS);
	}
	bzero((caddr_t)inp, sizeof(*inp));
	inp->nlp_pcbinfo = pcbinfo;
	inp->nlp_socket = so;
	so->so_pcb = (caddr_t)inp;
	return (0);
}


/*
 * Lookup PCB in hash list.
 */
struct netlinkpcb *
netlink_pcblookup(pcbinfo, pid)
	struct netlinkpcbinfo *pcbinfo;
	uint32_t pid;
{
	struct netlinkpcbhead *head;
	register struct netlinkpcb *inp;
	int s;

	s = splnet();
	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->hashbase[NETLINK_PCBHASH(pid, pcbinfo->hashmask)];
	/*for (inp = head->lh_first; inp != NULL; inp = inp->nlp_hash.le_next)*/
	LIST_FOREACH(inp, head, nlp_hash) {
		if (inp->nlp_portid == pid)
			goto found;
	}
	splx(s);
	return (NULL);

found:
	/*
	 * Move PCB to head of this hash chain so that it can be
	 * found more quickly in the future.
	 * XXX - this is a pessimization on machines with few
	 * concurrent connections.
	 */
	if (inp != head->lh_first) {
		LIST_REMOVE(inp, nlp_hash);
		LIST_INSERT_HEAD(head, inp, nlp_hash);
	}
	splx(s);
	return (inp);
}

void
netlink_pcbdisconnect(inp)
	struct netlinkpcb *inp;
{
	inp->nlp_state = 0;
	netlink_pcbrehash(inp);

	if (inp->nlp_socket->so_state & SS_NOFDREF)
		netlink_pcbdetach(inp);
}

void
netlink_pcbdetach(inp)
	struct netlinkpcb *inp;
{
#if 0
	struct socket *so = inp->nlp_socket;
#endif
	int s;
#if 0
	so->so_pcb = 0;
	sofree(so);
#endif

	/*FREE(inp->nlp_mclist, MT_PCB);*/
	s = splnet();
	LIST_REMOVE(inp, nlp_hash);
	splx(s);
	free(inp, M_DEVBUF);
}

void
netlink_pcbrehash(inp)
	struct netlinkpcb *inp;
{
	struct netlinkpcbhead *head;
	int s;

	s = splnet();
	LIST_REMOVE(inp, nlp_hash);

	head = &inp->nlp_pcbinfo->hashbase[NETLINK_PCBHASH(inp->nlp_portid, inp->nlp_pcbinfo->hashmask)];

	LIST_INSERT_HEAD(head, inp, nlp_hash);
	splx(s);
}


/*
 * Insert PCB into hash chain. Must be called at splnet.
 */
void
netlink_pcbinshash(nlpcb)
	struct netlinkpcb *nlpcb;
{
	struct netlinkpcbhead *head;
	int s;
	
	s = splnet();
	head = &nlpcb->nlp_pcbinfo->hashbase[NETLINK_PCBHASH(nlpcb->nlp_portid, nlpcb->nlp_pcbinfo->hashmask)];

	LIST_INSERT_HEAD(head, nlpcb, nlp_hash);

	splx(s);
}


