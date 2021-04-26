
/* packet_cb.c */ 

/* Copyright 2012-2017 Fiberhome Networks Co., Ltd. */

/*
modification history 
--------------------------
01a,2012-07-14,lsh written
 */

/* 
DESCRIPTION
.
 */ 

#include <sys/cdefs.h>
 __FBSDID("$FreeBSD$");
 
#include "opt_mrouting.h"
#include "opt_ipsec.h"
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_sctp.h"
#include "opt_mpath.h"


#include <sys/param.h>
#include <sys/domain.h>
#include <sys/eventhandler.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include "list.h"
#include "packet_cb.h"
#include "packet_dev.h"




/*
 * Discard the PACKET multicast options.
 */
void
packet_freemcast(mcast, inp)
	register struct packet_mclist *mcast;
	struct packetpcb *inp;
        
{
#if 0
        M_BLK_ID	pInmMblk;
        M_BLK_ID	pInmMblkNext;

	if (imo != NULL) {
                pInmMblk = imo->pInmMblk;
                pInmMblkNext = imo->pInmMblk;
        	while ((pInmMblk = pInmMblkNext) != NULL)
                    {
                    pInmMblkNext = pInmMblk->mBlkHdr.mNext; 
                    in_delmulti (pInmMblk, pInPcb);
                    }
		DS_FREE(imo, 0/*MT_IPMOPTS*/);
	}
#endif
}


int packet_pcballoc(struct socket *so, struct packetpcbinfo *pcbinfo)
{
	register struct packetpcb *inp;
	int s;

	inp = (struct packetpcb *)malloc(sizeof(*inp), M_DEVBUF, M_WAITOK|M_ZERO);
	if (inp == NULL)
	{
            return (ENOBUFS);
	}
	bzero((caddr_t)inp, sizeof(*inp));
	inp->pp_pcbinfo = pcbinfo;
	inp->pp_socket = so;
	s = splnet();
	list_add(&inp->pp_list, &pcbinfo->listhead);
	packet_pcbinshash(inp);
	splx(s);
	so->so_pcb = (caddr_t)inp;
	return (0);
}





void packet_pcbdisconnect(struct packetpcb *inp)
{
	inp->pp_ifindex = 0;
	inp->pp_proto = 0;
	inp->pp_running = 0;
	packet_pcbrehash(inp);

	if (inp->pp_socket->so_state & SS_NOFDREF)
		packet_pcbdetach(inp);
}

void packet_pcbdetach(struct packetpcb *inp)
{
	struct socket *so = inp->pp_socket;
	int s;

	so->so_pcb = 0;
	sofree(so);

	packet_freemcast(inp->pp_mclist, inp);
	s = splnet();
	list_del(&inp->pp_hash);
	list_del(&inp->pp_list);
	splx(s);
	free(inp, 0/*MT_PCB*/);
}


/*
 * Pass some notification to all connections of a protocol
 * associated with address dst.  The local address and/or port numbers
 * may be specified to limit the search.  The "usual action" will be
 * taken, depending on the ctlinput cmd.  The caller must filter any
 * cmds that are uninteresting (e.g., no error in the map).
 * Call the protocol specific routine (if any) to report
 * any errors for each matching socket.
 *
 * Must be called at splnet.
 */
void packet_pcbnotify(head, dst, fport_arg, laddr, lport_arg, cmd, notify)
	struct packetpcbhead *head;
	struct sockaddr *dst;
	u_int fport_arg, lport_arg;
	struct in_addr *laddr;
	int cmd;
	void (*notify) (struct inpcb *, int);
{
#if 0
	register struct packetpcb *inp, *oinp;
	struct in_addr faddr;
	u_short fport = fport_arg, lport = lport_arg;
	int errno, s;


	if ((unsigned)cmd > PRC_NCMDS || dst->sa_family != AF_INET)
		return;
	faddr = ((struct sockaddr_in *)dst)->sin_addr;
	if (faddr.s_addr == INADDR_ANY)
		return;

	/*
	 * Redirects go to all references to the destination,
	 * and use in_rtchange to invalidate the route cache.
	 * Dead host indications: notify all references to the destination.
	 * Otherwise, if we have knowledge of the local port and address,
	 * deliver only to that socket.
	 */
	if (PRC_IS_REDIRECT(cmd) || cmd == PRC_HOSTDEAD) {
		fport = 0;
		lport = 0;
		laddr.s_addr = 0;
		if (cmd != PRC_HOSTDEAD)
			notify = in_rtchange;
	}
	errno = inetctlerrmap[cmd];
	s = splnet();
	for (inp = head->lh_first; inp != NULL;) {
		if (inp->pp_faddr.s_addr != faddr.s_addr ||
		    inp->pp_socket == 0 ||
		    (lport && inp->pp_lport != lport) ||
		    (laddr.s_addr && inp->pp_laddr.s_addr != laddr.s_addr) ||
		    (fport && inp->pp_fport != fport)) {
			inp = inp->pp_list.le_next;
			continue;
		}
		oinp = inp;
		inp = inp->pp_list.le_next;
		if (notify)
			(*notify)(oinp, errno);
	}
	splx(s);
#endif
}


/*
 * Insert PCB into hash chain. Must be called at splnet.
 */
void packet_pcbinshash(struct packetpcb *inp)
{
	struct list_head *head;

	head = &inp->pp_pcbinfo->hashbase[PACKET_PCBHASH(inp->pp_proto,
		 inp->pp_ifindex, inp->pp_pcbinfo->hashmask)];

	list_add(&inp->pp_hash, head);
}

void packet_pcbrehash(struct packetpcb *inp)
{
	struct list_head *head;
	int s;

	s = splnet();
	list_del(&inp->pp_hash);

	head = &inp->pp_pcbinfo->hashbase[PACKET_PCBHASH(inp->pp_proto,
		 inp->pp_ifindex, inp->pp_pcbinfo->hashmask)];

	list_add(&inp->pp_hash, head);
	splx(s);
}


