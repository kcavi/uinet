#ifndef __INCnetlink_pcbh
#define __INCnetlink_pcbh

#ifdef __cplusplus
extern "C" {
#endif

#include "list.h"


/*
 * Common structure pcb for internet protocol implementation.
 * Here are stored pointers to local and foreign host table
 * entries, local and foreign socket numbers, and pointers
 * up (to a socket structure) and down (to a protocol-specific)
 * control block.
 */

LIST_HEAD(netlinkpcbhead, netlinkpcb);

struct netlinkpcb {
	LIST_ENTRY(netlinkpcb) nlp_hash;	/* hash list */
	LIST_ENTRY(netlinkpcb) nlp_list;	/* list for all PCBs of this proto */
	struct	netlinkpcbinfo *nlp_pcbinfo;
	struct	socket *nlp_socket;	/* back pointer to socket */
	caddr_t	nlp_ppcb;		/* pointer to per-protocol pcb */
	uint16_t	nlp_proto;		/* protocol type */
	uint16_t	res;
	uint32_t		nlp_portid;
	uint32_t		nlp_dstportid;
	uint32_t		nlp_dstgroup;
	uint32_t		nlp_flags;
	uint32_t		nlp_subscriptions;
	uint32_t		nlp_ngroups;
	unsigned long		*nlp_groups;
	unsigned long		nlp_state;
	/*wait_queue_head_t	nlp_wait;*/
	struct netlink_callback	*nlp_cb;
	void			(*nlp_datarcv)(struct mbuf *m);
};


struct netlinkpcbinfo {
	struct netlinkpcbhead *hashbase;
	struct netlinkpcbhead mc_list;
	uint32_t hashmask;
	uint32_t nl_nonroot;
	uint32_t groups;
	int registered;
};


#define NETLINK_PCBHASH(pid, mask) \
	((pid) % (mask))



/* flags in inp_flags: */
#define	NETLINK_RECVOPTS		0x01	/* receive incoming IP options */
#define	NETLINK_RECVRETOPTS		0x02	/* receive IP options for reply */
#define	NETLINK_RECVDSTADDR		0x04	/* receive IP dst address */
#define	NETLINK_CONTROLOPTS		(INP_RECVOPTS|INP_RECVRETOPTS|INP_RECVDSTADDR)
#define	NETLINK_HDRINCL		0x08	/* user supplies entire IP header */

#define	NETLINKLOOKUP_WILDCARD	1

#define	sotonlpcb(so)	((struct netlinkpcb *)(so)->so_pcb)


extern int netlink_pcballoc (struct socket *, struct netlinkpcbinfo *);
extern void netlink_pcbdetach (struct netlinkpcb *);
extern void netlink_pcbdisconnect (struct netlinkpcb *);
extern void netlink_pcbinshash (struct netlinkpcb *);
extern void netlink_pcbrehash (struct netlinkpcb *);

#ifdef __cplusplus
}
#endif

#endif /* __INCnetlink_pcbh */
