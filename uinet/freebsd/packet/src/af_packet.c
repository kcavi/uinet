
/* af_packet.c */ 

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


#include <net/if.h>
#include <net/if_var.h>




#include "list.h"

#include "packet_cb.h"
#include "packet_dev.h"

static void packet_dev_mclist(struct packet_dev *dev, struct packet_mclist *i, int what);
extern struct packet_dev *packet_dev_get(uint32_t ifIndex);

int	_packetSwIndex;


#define	PACKETSNDQ		8192
#define	PACKETRCVQ		8192
uint32_t	packet_sendspace = PACKETSNDQ;
uint32_t	packet_recvspace = PACKETRCVQ;


uint16_t	packet_pcbhashsize = 32;


struct packetpcbinfo packetpcbinfo;
extern struct domain packetdomain;
extern struct pr_usrreqs packet_usrreqs;


struct list_head ptype_base[PTYPE_HASH_SIZE];
struct list_head ptype_all;	/* Taps */

/*
 * Initialize raw connection block q.
 */
void packet_init()
{
	int ix;
	
	INIT_LIST_HEAD(&packetpcbinfo.listhead);

	packetpcbinfo.hashbase = malloc(packet_pcbhashsize*sizeof(struct list_head), M_DEVBUF, M_WAITOK|M_ZERO);
	
	for (ix = 0; ix < packet_pcbhashsize; ix++)
		INIT_LIST_HEAD(&packetpcbinfo.hashbase[ix]);

	packetpcbinfo.hashmask = packet_pcbhashsize;

	packetDevInit(0);
}


#define VLAN_CTRL_PRI(c)               ((c) >> 13 & 0x007)
#define VLAN_CTRL_CFI(c)                ((c) >> 12 & 0x001)
#define VLAN_CTRL_VID(c)                 ((c) >>  0 & 0xfff)
#if 0
static void
packet_savecontrol(inp, mp, llHdr, m)
	struct packetpcb *inp;
	struct mbuf **mp;
	LL_HDR_INFO *llHdr;
	struct mbuf *m;
{
	if (inp->pp_socket->so_options & SO_TIMESTAMP) {
		struct timeval tv;

		microtime(&tv);
		*mp = sbcreatecontrol((caddr_t) &tv, sizeof(tv),
			SCM_TIMESTAMP, SOL_SOCKET);
		if (*mp)
			mp = &(*mp)->m_next;
	}

	if ((inp->pp_flags & PACKETCB_PKTINFO) != 0) {
		struct packet_rxpktinfo pktinfo;

		bzero(&pktinfo, sizeof(pktinfo));

		if(inp->pp_socket->so_type == SOCK_RAW)
		pktinfo.pkt_dataoffset = llHdr->dataOffset;
	
		pktinfo.pkt_outervid = VLAN_CTRL_VID(llHdr->ctrlSize);
		pktinfo.pkt_innervid = VLAN_CTRL_VID(llHdr->ctrlSize>>16);
		pktinfo.pkt_outerpri= VLAN_CTRL_PRI(llHdr->ctrlSize);
		pktinfo.pkt_innerpri= VLAN_CTRL_PRI(llHdr->ctrlSize>>16);
	#ifdef USP_MBUF_EXT
		pktinfo.pkt_outervid = m->mBlkHdr.superVid;
		pktinfo.pkt_inport = m->lPort;
	
		pktinfo.pkt_cblen = m->m_pkthdr.cbLen;
		if(pktinfo.pkt_cblen > sizeof(pktinfo.pkt_cb))
			pktinfo.pkt_cblen = sizeof(pktinfo.pkt_cb);
		memcpy(&pktinfo.pkt_cb[0], &m->m_pkthdr.cb[0], pktinfo.pkt_cblen);

		if(m->m_flags & M_SLFTOCPU)
		{
			pktinfo.pkt_flags 	|= PACKET_FLAG_SLFTOCPU;
		}
		if(m->m_flags & M_SFLOWINGRESSTOCPU)
		{
			pktinfo.pkt_flags 	|= PACKET_FLAG_SFLOWINGRESSTOCPU;
		}
		if(m->m_flags & M_SFLOWEGRESSTOCPU)
		{
			pktinfo.pkt_flags 	|= PACKET_FLAG_SFLOWEGRESSTOCPU;
		}
		if(m->m_flags & M_IPFIXINGRESSTOCPU)
		{
			pktinfo.pkt_flags 	|= PACKET_FLAG_IPFIXINGRESSTOCPU;
		}
		if(m->m_flags & M_IPFIXEGRESSTOCPU)
		{
			pktinfo.pkt_flags 	|= PACKET_FLAG_IPFIXEGRESSTOCPU;
		}
		if(m->m_flags & M_TIMESTAMP)
		{
			pktinfo.pkt_flags 	|= PACKET_FLAG_TIMESTAMP;
		}
		if(m->m_flags & M_PONONUATTR)
		{
			pktinfo.pkt_flags 	|= PACKET_FLAG_PONONUATTR;
		}
	#endif
		bcopy(mtod(m, caddr_t)+llHdr->srcAddrOffset, pktinfo.pkt_srcaddr, llHdr->srcSize);
		bcopy(mtod(m, caddr_t)+llHdr->destAddrOffset, pktinfo.pkt_dstaddr, llHdr->destSize);
		
		*mp = sbcreatecontrol((caddr_t) &pktinfo,
			sizeof(struct packet_rxpktinfo), PACKET_RX_PKTINFO,
			SOL_PACKET);
		if (*mp)
			mp = &(*mp)->m_next;
	}
}
#endif

int afPktCountFd=-1;
int afPktCount = 0;

void packet_rcv(struct ifnet *ifp, struct mbuf *m)
{
	struct packet_type *pt,*lastpt=NULL;
	struct mbuf * copym;
	
	struct ether_header *eth = m->m_data;
	uint16_t type = eth->ether_type; 

	list_for_each_entry(pt, &ptype_base[ntohs(type) & PTYPE_HASH_MASK], node)
	{
		if(pt->type != eth->ether_type)
			continue;

		copym = m_copy(m, 0, (int)M_COPYALL);

		pt->func(copym, ifp, pt, NULL);
		
	}	

}


extern int32_t gPacketDebug;
static int packet_input(struct mbuf *m,struct packet_dev *dev,struct packet_type *pt,LL_HDR_INFO *llHdr)
{
	struct packetpcb *inp;
	struct socket *last = 0;
	struct sockaddr_ll sll;
	struct  mbuf *opts = NULL;
	int ret=0;

	inp = pt->af_packet_priv;

	sll.sll_len = sizeof(struct sockaddr_ll);
	sll.sll_family = AF_PACKET;
	//sll.sll_hatype = dev->type;
	//sll.sll_protocol = m->mBlkHdr.reserved;
	//sll.sll_pkttype = (m->mBlkHdr.mFlags & M_BCAST)?PACKET_BROADCAST:
	//					(m->mBlkHdr.mFlags & M_MCAST)?PACKET_MULTICAST:PACKET_HOST;
#if 0
	if(inp->pp_origdev)
		sll.sll_origifindex = m->lPort;
	else
#endif
	//sll.sll_ifindex = dev->ifIndex;

	sll.sll_halen = 0;

	//sll.sll_halen = dev->addrlen;
	/*ifp->if_hard_header_parse(ifp, m);*/
	/*
	帧头字段以后可能需要修改
	*/
	//netMblkOffsetToBufCopy (m, dev->addrlen/*ll_hdr->srcAddrOffset*/, (char *) sll.sll_addr, 
	//		sll.sll_halen, (FUNCPTR) bcopy);


	/* The device has an explicit notion of ll header,
	   exported to higher levels.

	   Otherwise, the device hides datails of it frame
	   structure, so that corresponding packet head
	   never delivered to user.
	 */


	last = inp->pp_socket;
	if(last == NULL)
	{
		m_freem(m);
		return ERROR;
	}
	if(gPacketDebug&DEBUG_PACKET_IN)
	{
		printf("packet_input: pt->type %x, , lowat %x, sb_flag %x,"
			"sll.sll_ifindex %x\n", 
			pt->type,  last->so_rcv.sb_lowat,
			 last->so_rcv.sb_flags, sll.sll_ifindex);
	}

	//packet_savecontrol(inp, &opts, llHdr, m);
	
	/* snarf收包是带MAC帧头的
	*/
	//if (last->so_proto->pr_type != SOCK_RAW)
	//   m_adj(m,llHdr->dataOffset);
		
	ret = sbappendaddr(&last->so_rcv, (struct sockaddr *)&sll, m, opts);
	if(gPacketDebug&DEBUG_PACKET_IN)
	{
		printf("packet_input: after sbappendaddr dev->type %x, lowat %x,  sb_flag %x ret=%d\n", 
			pt->type, last->so_rcv.sb_lowat,  last->so_rcv.sb_flags,ret);
	}
	if (ret == 0)
	{
		m_freem(m);
		if (opts)
			m_freem(opts);
	}
	else
	{
		if(afPktCountFd != -1  /*&& last->so_fd == afPktCountFd*/)
			afPktCount ++;
		sorwakeup(last);
	}
	
	return OK;
}


static int packet_input_spkt(struct mbuf *m,struct packet_dev *dev,struct packet_type *pt,int dataOffset)
{
#if 0
	struct socket *sk;
	struct packetpcb *po;
	struct sockaddr_ll *sll;
	union {
		struct tpacket_hdr *h1;
		struct tpacket2_hdr *h2;
		void *raw;
	} h;
	u8 *skb_head = skb->data;
	int skb_len = skb->len;
	unsigned int snaplen, res;
	unsigned long status = TP_STATUS_LOSING|TP_STATUS_USER;
	unsigned short macoff, netoff, hdrlen;
	struct sk_buff *copy_skb = NULL;
	struct timeval tv;
	struct timespec ts;
	struct skb_shared_hwtstamps *shhwtstamps = skb_hwtstamps(skb);

	if (skb->pkt_type == PACKET_LOOPBACK)
		goto drop;

	sk = pt->af_packet_priv;
	po = pkt_sk(sk);

	if (!net_eq(dev_net(dev), sock_net(sk)))
		goto drop;

	if (dev->header_ops) {
		if (sk->sk_type != SOCK_DGRAM)
			skb_push(skb, skb->data - skb_mac_header(skb));
		else if (skb->pkt_type == PACKET_OUTGOING) {
			/* Special case: outgoing packets have ll header at head */
			skb_pull(skb, skb_network_offset(skb));
		}
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		status |= TP_STATUS_CSUMNOTREADY;

	snaplen = skb->len;

	res = run_filter(skb, sk, snaplen);
	if (!res)
		goto drop_n_restore;
	if (snaplen > res)
		snaplen = res;

	if (sk->sk_type == SOCK_DGRAM) {
		macoff = netoff = TPACKET_ALIGN(po->tp_hdrlen) + 16 +
				  po->tp_reserve;
	} else {
		unsigned maclen = skb_network_offset(skb);
		netoff = TPACKET_ALIGN(po->tp_hdrlen +
				       (maclen < 16 ? 16 : maclen)) +
			po->tp_reserve;
		macoff = netoff - maclen;
	}

	if (macoff + snaplen > po->rx_ring.frame_size) {
		if (po->copy_thresh &&
		    atomic_read(&sk->sk_rmem_alloc) + skb->truesize <
		    (unsigned)sk->sk_rcvbuf) {
			if (skb_shared(skb)) {
				copy_skb = skb_clone(skb, GFP_ATOMIC);
			} else {
				copy_skb = skb_get(skb);
				skb_head = skb->data;
			}
			if (copy_skb)
				skb_set_owner_r(copy_skb, sk);
		}
		snaplen = po->rx_ring.frame_size - macoff;
		if ((int)snaplen < 0)
			snaplen = 0;
	}

	spin_lock(&sk->sk_receive_queue.lock);
	h.raw = packet_current_frame(po, &po->rx_ring, TP_STATUS_KERNEL);
	if (!h.raw)
		goto ring_is_full;
	packet_increment_head(&po->rx_ring);
	po->stats.tp_packets++;
	if (copy_skb) {
		status |= TP_STATUS_COPY;
		__skb_queue_tail(&sk->sk_receive_queue, copy_skb);
	}
	if (!po->stats.tp_drops)
		status &= ~TP_STATUS_LOSING;
	spin_unlock(&sk->sk_receive_queue.lock);

	skb_copy_bits(skb, 0, h.raw + macoff, snaplen);

	switch (po->tp_version) {
	case TPACKET_V1:
		h.h1->tp_len = skb->len;
		h.h1->tp_snaplen = snaplen;
		h.h1->tp_mac = macoff;
		h.h1->tp_net = netoff;
		if ((po->tp_tstamp & SOF_TIMESTAMPING_SYS_HARDWARE)
				&& shhwtstamps->syststamp.tv64)
			tv = ktime_to_timeval(shhwtstamps->syststamp);
		else if ((po->tp_tstamp & SOF_TIMESTAMPING_RAW_HARDWARE)
				&& shhwtstamps->hwtstamp.tv64)
			tv = ktime_to_timeval(shhwtstamps->hwtstamp);
		else if (skb->tstamp.tv64)
			tv = ktime_to_timeval(skb->tstamp);
		else
			do_gettimeofday(&tv);
		h.h1->tp_sec = tv.tv_sec;
		h.h1->tp_usec = tv.tv_usec;
		hdrlen = sizeof(*h.h1);
		break;
	case TPACKET_V2:
		h.h2->tp_len = skb->len;
		h.h2->tp_snaplen = snaplen;
		h.h2->tp_mac = macoff;
		h.h2->tp_net = netoff;
		if ((po->tp_tstamp & SOF_TIMESTAMPING_SYS_HARDWARE)
				&& shhwtstamps->syststamp.tv64)
			ts = ktime_to_timespec(shhwtstamps->syststamp);
		else if ((po->tp_tstamp & SOF_TIMESTAMPING_RAW_HARDWARE)
				&& shhwtstamps->hwtstamp.tv64)
			ts = ktime_to_timespec(shhwtstamps->hwtstamp);
		else if (skb->tstamp.tv64)
			ts = ktime_to_timespec(skb->tstamp);
		else
			getnstimeofday(&ts);
		h.h2->tp_sec = ts.tv_sec;
		h.h2->tp_nsec = ts.tv_nsec;
		if (vlan_tx_tag_present(skb)) {
			h.h2->tp_vlan_tci = vlan_tx_tag_get(skb);
			status |= TP_STATUS_VLAN_VALID;
		} else {
			h.h2->tp_vlan_tci = 0;
		}
		h.h2->tp_padding = 0;
		hdrlen = sizeof(*h.h2);
		break;
	default:
		BUG();
	}

	sll = h.raw + TPACKET_ALIGN(hdrlen);
	sll->sll_halen = dev_parse_header(skb, sll->sll_addr);
	sll->sll_family = AF_PACKET;
	sll->sll_hatype = dev->type;
	sll->sll_protocol = skb->protocol;
	sll->sll_pkttype = skb->pkt_type;
	if (unlikely(po->origdev))
		sll->sll_ifindex = orig_dev->ifindex;
	else
		sll->sll_ifindex = dev->ifindex;

	__packet_set_status(po, h.raw, status);
	smp_mb();
#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE == 1
	{
		u8 *start, *end;

		end = (u8 *)PAGE_ALIGN((unsigned long)h.raw + macoff + snaplen);
		for (start = h.raw; start < end; start += PAGE_SIZE)
			flush_dcache_page(pgv_to_page(start));
	}
#endif

	sk->sk_data_ready(sk, 0);

drop_n_restore:
	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}
drop:
	kfree_skb(skb);
	return 0;

ring_is_full:
	po->stats.tp_drops++;
	spin_unlock(&sk->sk_receive_queue.lock);

	sk->sk_data_ready(sk, 0);
	kfree_skb(copy_skb);
	goto drop_n_restore;
#else
	return 0;
#endif
}


static int tpacket_input(struct mbuf *m,struct packet_dev *dev,struct packet_type *pt,LL_HDR_INFO *llHdr)
{
#if 0
	struct socket *sk;
	struct packetpcb *po;
	struct sockaddr_ll *sll;
	union {
		struct tpacket_hdr *h1;
		struct tpacket2_hdr *h2;
		void *raw;
	} h;
	uint8_t *skb_head = skb->data;
	int skb_len = m->mBlkPktHdr.len;
	unsigned int snaplen, res;
	unsigned long status = TP_STATUS_LOSING|TP_STATUS_USER;
	unsigned short macoff, netoff, hdrlen;
	struct mbuf *copy_skb = NULL;
	struct timeval tv;
	struct timespec ts;
	struct skb_shared_hwtstamps *shhwtstamps = skb_hwtstamps(skb);

	if (m->pkt_type == PACKET_LOOPBACK)
		goto drop;

	po = pt->af_packet_priv;
	sk = po->pp_socket;

	if (!net_eq(dev_net(dev), sock_net(sk)))
		goto drop;

	if (dev->header_ops) {
		if (sk->sk_type != SOCK_DGRAM)
			skb_push(skb, skb->data - skb_mac_header(skb));
		else if (skb->pkt_type == PACKET_OUTGOING) {
			/* Special case: outgoing packets have ll header at head */
			skb_pull(skb, skb_network_offset(skb));
		}
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		status |= TP_STATUS_CSUMNOTREADY;

	snaplen = skb->len;

	res = run_filter(skb, sk, snaplen);
	if (!res)
		goto drop_n_restore;
	if (snaplen > res)
		snaplen = res;

	if (sk->sk_type == SOCK_DGRAM) {
		macoff = netoff = TPACKET_ALIGN(po->tp_hdrlen) + 16 +
				  po->tp_reserve;
	} else {
		unsigned maclen = skb_network_offset(skb);
		netoff = TPACKET_ALIGN(po->tp_hdrlen +
				       (maclen < 16 ? 16 : maclen)) +
			po->tp_reserve;
		macoff = netoff - maclen;
	}

	if (macoff + snaplen > po->rx_ring.frame_size) {
		if (po->copy_thresh &&
		    atomic_read(&sk->sk_rmem_alloc) + skb->truesize <
		    (unsigned)sk->sk_rcvbuf) {
			if (skb_shared(skb)) {
				copy_skb = skb_clone(skb, GFP_ATOMIC);
			} else {
				copy_skb = skb_get(skb);
				skb_head = skb->data;
			}
			if (copy_skb)
				skb_set_owner_r(copy_skb, sk);
		}
		snaplen = po->rx_ring.frame_size - macoff;
		if ((int)snaplen < 0)
			snaplen = 0;
	}

	spin_lock(&sk->sk_receive_queue.lock);
	h.raw = packet_current_frame(po, &po->rx_ring, TP_STATUS_KERNEL);
	if (!h.raw)
		goto ring_is_full;
	packet_increment_head(&po->rx_ring);
	po->stats.tp_packets++;
	if (copy_skb) {
		status |= TP_STATUS_COPY;
		__skb_queue_tail(&sk->sk_receive_queue, copy_skb);
	}
	if (!po->stats.tp_drops)
		status &= ~TP_STATUS_LOSING;
	spin_unlock(&sk->sk_receive_queue.lock);

	skb_copy_bits(skb, 0, h.raw + macoff, snaplen);

	switch (po->tp_version) {
	case TPACKET_V1:
		h.h1->tp_len = skb->len;
		h.h1->tp_snaplen = snaplen;
		h.h1->tp_mac = macoff;
		h.h1->tp_net = netoff;
		if ((po->tp_tstamp & SOF_TIMESTAMPING_SYS_HARDWARE)
				&& shhwtstamps->syststamp.tv64)
			tv = ktime_to_timeval(shhwtstamps->syststamp);
		else if ((po->tp_tstamp & SOF_TIMESTAMPING_RAW_HARDWARE)
				&& shhwtstamps->hwtstamp.tv64)
			tv = ktime_to_timeval(shhwtstamps->hwtstamp);
		else if (skb->tstamp.tv64)
			tv = ktime_to_timeval(skb->tstamp);
		else
			do_gettimeofday(&tv);
		h.h1->tp_sec = tv.tv_sec;
		h.h1->tp_usec = tv.tv_usec;
		hdrlen = sizeof(*h.h1);
		break;
	case TPACKET_V2:
		h.h2->tp_len = skb->len;
		h.h2->tp_snaplen = snaplen;
		h.h2->tp_mac = macoff;
		h.h2->tp_net = netoff;
		if ((po->tp_tstamp & SOF_TIMESTAMPING_SYS_HARDWARE)
				&& shhwtstamps->syststamp.tv64)
			ts = ktime_to_timespec(shhwtstamps->syststamp);
		else if ((po->tp_tstamp & SOF_TIMESTAMPING_RAW_HARDWARE)
				&& shhwtstamps->hwtstamp.tv64)
			ts = ktime_to_timespec(shhwtstamps->hwtstamp);
		else if (skb->tstamp.tv64)
			ts = ktime_to_timespec(skb->tstamp);
		else
			getnstimeofday(&ts);
		h.h2->tp_sec = ts.tv_sec;
		h.h2->tp_nsec = ts.tv_nsec;
		if (vlan_tx_tag_present(skb)) {
			h.h2->tp_vlan_tci = vlan_tx_tag_get(skb);
			status |= TP_STATUS_VLAN_VALID;
		} else {
			h.h2->tp_vlan_tci = 0;
		}
		h.h2->tp_padding = 0;
		hdrlen = sizeof(*h.h2);
		break;
	default:
		BUG();
	}

	sll = h.raw + TPACKET_ALIGN(hdrlen);
	sll->sll_halen = dev_parse_header(skb, sll->sll_addr);
	sll->sll_family = AF_PACKET;
	sll->sll_hatype = dev->type;
	sll->sll_protocol = skb->protocol;
	sll->sll_pkttype = skb->pkt_type;
	if (unlikely(po->origdev))
		sll->sll_ifindex = orig_dev->ifindex;
	else
		sll->sll_ifindex = dev->ifindex;

	__packet_set_status(po, h.raw, status);
	smp_mb();
#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE == 1
	{
		u8 *start, *end;

		end = (u8 *)PAGE_ALIGN((unsigned long)h.raw + macoff + snaplen);
		for (start = h.raw; start < end; start += PAGE_SIZE)
			flush_dcache_page(pgv_to_page(start));
	}
#endif

	sk->sk_data_ready(sk, 0);

	if (sbappendaddr(&last->so_rcv, (struct sockaddr *)&sll, m, (struct mbuf *)0) == 0)
	{
		m_freem(m);
	}
	else
		sorwakeup(last);

drop_n_restore:
	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}
drop:
	m_freem(m);
	return 0;

ring_is_full:
	po->stats.tp_drops++;
	spin_unlock(&sk->sk_receive_queue.lock);

	sk->sk_data_ready(sk, 0);
	m_freem(copy_skb);
	goto drop_n_restore;
#else
	return 0;
#endif
}





/*
 * Generate IP header and pass packet to ip_output.
 * Tack on options user may have setup with control call.
 */



int packet_output(struct socket *so,register struct mbuf *m,struct sockaddr *dst,struct mbuf *control,struct proc *p)
{
	struct packetpcb *inp = sotoppcb(so);
	int s,error = 0;
	uint16_t proto;
	int ifindex;
	struct packet_dev *dev;
	uint8_t *daddr;
	struct ifnet *ifp;
	struct sockaddr_ll *sll = (struct sockaddr_ll *)dst;

	/*
	 *	Get and verify the address. 
	 */
	 
	if(dst == NULL) 
	{
		ifindex	= inp->pp_ifindex;
		proto	= inp->pp_proto;
		daddr	= NULL;
	} else 
	{
		ifindex	= sll->sll_ifindex;
		proto	= sll->sll_protocol;
		daddr	= sll->sll_addr;
	}
	
	dev = packet_dev_get(ifindex);
	if(dev == NULL) 
	{
		error = EADDRNOTAVAIL;
		goto release;
	}


	if(!dev->up)
	{
		printf("the interface %d is down\n",ifindex);
		//error = ENETDOWN;
		//goto release;
	}

	ifp = ifnet_byindex(ifindex);
	if(ifp == NULL)
	{
		printf("can't find ifp\n");
		goto release;
	}


	error = ifp->if_transmit(ifp,m);
	

	//m->mBlkHdr.reserved = proto;
/*
	if (so->so_type == SOCK_DGRAM)
		error = packet_dev_send(dev, m, control, proto, daddr);
	else
		error = packet_dev_raw_send(dev, m);
*/
	return error;
release:
	//if(dev != NULL)
	//	packet_dev_put(dev);
	m_freem(m);
	return (error);
}


static struct page *pgv_to_page(void *addr)
{
#if 0
	if (is_vmalloc_addr(addr))
		return vmalloc_to_page(addr);
	return virt_to_page(addr);
#else
	return addr;
#endif
}

static void __packet_set_status(struct packetpcb *po, void *frame, int status)
{
	union {
		struct tpacket_hdr *h1;
		struct tpacket2_hdr *h2;
		void *raw;
	} h;

	h.raw = frame;
	switch (po->tp_version) {
	case TPACKET_V1:
		h.h1->tp_status = status;
		/*flush_dcache_page(pgv_to_page(&h.h1->tp_status));*/
		break;
	case TPACKET_V2:
		h.h2->tp_status = status;
		/*flush_dcache_page(pgv_to_page(&h.h2->tp_status));*/
		break;
	default:
		printf("TPACKET version not supported\n");
		break;
	}
}

static int __packet_get_status(struct packetpcb *po, void *frame)
{
	union {
		struct tpacket_hdr *h1;
		struct tpacket2_hdr *h2;
		void *raw;
	} h;

	h.raw = frame;
	switch (po->tp_version) {
	case TPACKET_V1:
		/*flush_dcache_page(pgv_to_page(&h.h1->tp_status));*/
		return h.h1->tp_status;
	case TPACKET_V2:
		/*flush_dcache_page(pgv_to_page(&h.h2->tp_status));*/
		return h.h2->tp_status;
	default:
		printf("TPACKET version not supported\n");
		return 0;
	}
}

static void *packet_lookup_frame(struct packetpcb *po,
		struct packet_ring_buffer *rb,
		unsigned int position,
		int status)
{
	unsigned int pg_vec_pos, frame_offset;
	union {
		struct tpacket_hdr *h1;
		struct tpacket2_hdr *h2;
		void *raw;
	} h;

	pg_vec_pos = position / rb->frames_per_block;
	frame_offset = position % rb->frames_per_block;

	h.raw = rb->pg_vec[pg_vec_pos].buffer +
		(frame_offset * rb->frame_size);

	if (status != __packet_get_status(po, h.raw))
		return NULL;

	return h.raw;
}

static void *packet_current_frame(struct packetpcb *po,
		struct packet_ring_buffer *rb,
		int status)
{
	return packet_lookup_frame(po, rb, rb->head, status);
}

static void *packet_previous_frame(struct packetpcb *po,
		struct packet_ring_buffer *rb,
		int status)
{
	unsigned int previous = rb->head ? rb->head - 1 : rb->frame_max;
	return packet_lookup_frame(po, rb, previous, status);
}

static void packet_increment_head(struct packet_ring_buffer *buff)
{
	buff->head = buff->head != buff->frame_max ? buff->head+1 : 0;
}
#if 0
static void tpacket_destruct_skb(struct sk_buff *skb)
{
	struct packet_sock *po = pkt_sk(skb->sk);
	void *ph;

	BUG_ON(skb == NULL);

	if (likely(po->tx_ring.pg_vec)) {
		ph = skb_shinfo(skb)->destructor_arg;
		BUG_ON(__packet_get_status(po, ph) != TP_STATUS_SENDING);
		BUG_ON(atomic_read(&po->tx_ring.pending) == 0);
		atomic_dec(&po->tx_ring.pending);
		__packet_set_status(po, ph, TP_STATUS_AVAILABLE);
	}

	sock_wfree(skb);
}

static int tpacket_fill_skb(struct packet_sock *po, struct sk_buff *skb,
		void *frame, struct net_device *dev, int size_max,
		__be16 proto, unsigned char *addr)
{
	union {
		struct tpacket_hdr *h1;
		struct tpacket2_hdr *h2;
		void *raw;
	} ph;
	int to_write, offset, len, tp_len, nr_frags, len_max;
	struct socket *sock = po->sk.sk_socket;
	struct page *page;
	void *data;
	int err;

	ph.raw = frame;

	skb->protocol = proto;
	skb->dev = dev;
	skb->priority = po->sk.sk_priority;
	skb->mark = po->sk.sk_mark;
	skb_shinfo(skb)->destructor_arg = ph.raw;

	switch (po->tp_version) {
	case TPACKET_V2:
		tp_len = ph.h2->tp_len;
		break;
	default:
		tp_len = ph.h1->tp_len;
		break;
	}
	if (unlikely(tp_len > size_max)) {
		pr_err("packet size is too long (%d > %d)\n", tp_len, size_max);
		return -EMSGSIZE;
	}

	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	skb_reset_network_header(skb);

	data = ph.raw + po->tp_hdrlen - sizeof(struct sockaddr_ll);
	to_write = tp_len;

	if (sock->type == SOCK_DGRAM) {
		err = dev_hard_header(skb, dev, ntohs(proto), addr,
				NULL, tp_len);
		if (unlikely(err < 0))
			return -EINVAL;
	} else if (dev->hard_header_len) {
		/* net device doesn't like empty head */
		if (unlikely(tp_len <= dev->hard_header_len)) {
			pr_err("packet size is too short (%d < %d)\n",
			       tp_len, dev->hard_header_len);
			return -EINVAL;
		}

		skb_push(skb, dev->hard_header_len);
		err = skb_store_bits(skb, 0, data,
				dev->hard_header_len);
		if (unlikely(err))
			return err;

		data += dev->hard_header_len;
		to_write -= dev->hard_header_len;
	}

	err = -EFAULT;
	offset = offset_in_page(data);
	len_max = PAGE_SIZE - offset;
	len = ((to_write > len_max) ? len_max : to_write);

	skb->data_len = to_write;
	skb->len += to_write;
	skb->truesize += to_write;
	atomic_add(to_write, &po->sk.sk_wmem_alloc);

	while (likely(to_write)) {
		nr_frags = skb_shinfo(skb)->nr_frags;

		if (unlikely(nr_frags >= MAX_SKB_FRAGS)) {
			pr_err("Packet exceed the number of skb frags(%lu)\n",
			       MAX_SKB_FRAGS);
			return -EFAULT;
		}

		page = pgv_to_page(data);
		data += len;
		flush_dcache_page(page);
		get_page(page);
		skb_fill_page_desc(skb, nr_frags, page, offset, len);
		to_write -= len;
		offset = 0;
		len_max = PAGE_SIZE;
		len = ((to_write > len_max) ? len_max : to_write);
	}

	return tp_len;
}

#endif

static int tpacket_output(so, m, dst, control, p)
	struct socket *so;
	register struct mbuf *m;
	struct sockaddr *dst;
	struct mbuf *control;
	struct proc *p;
{
#if 0
	struct sk_buff *skb;
	struct net_device *dev;
	__be16 proto;
	int ifindex, err, reserve = 0;
	void *ph;
	struct sockaddr_ll *saddr = (struct sockaddr_ll *)dst;
	int tp_len, size_max;
	unsigned char *addr;
	int len_sum = 0;
	int status = 0;

	mutex_lock(&po->pg_vec_lock);

	err = -EBUSY;
	if (saddr == NULL) {
		ifindex	= po->ifindex;
		proto	= po->num;
		addr	= NULL;
	} else {
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(struct sockaddr_ll))
			goto out;
		if (msg->msg_namelen < (saddr->sll_halen
					+ offsetof(struct sockaddr_ll,
						sll_addr)))
			goto out;
		ifindex	= saddr->sll_ifindex;
		proto	= saddr->sll_protocol;
		addr	= saddr->sll_addr;
	}

	dev = dev_get_by_index(sock_net(&po->sk), ifindex);
	err = -ENXIO;
	if (unlikely(dev == NULL))
		goto out;

	reserve = dev->hard_header_len;

	err = -ENETDOWN;
	if (unlikely(!(dev->flags & IFF_UP)))
		goto out_put;

	size_max = po->tx_ring.frame_size
		- (po->tp_hdrlen - sizeof(struct sockaddr_ll));

	if (size_max > dev->mtu + reserve)
		size_max = dev->mtu + reserve;

	do {
		ph = packet_current_frame(po, &po->tx_ring,
				TP_STATUS_SEND_REQUEST);

		if (unlikely(ph == NULL)) {
			schedule();
			continue;
		}

		status = TP_STATUS_SEND_REQUEST;
		skb = sock_alloc_send_skb(&po->sk,
				LL_ALLOCATED_SPACE(dev)
				+ sizeof(struct sockaddr_ll),
				0, &err);

		if (unlikely(skb == NULL))
			goto out_status;

		tp_len = tpacket_fill_skb(po, skb, ph, dev, size_max, proto,
				addr);

		if (unlikely(tp_len < 0)) {
			if (po->tp_loss) {
				__packet_set_status(po, ph,
						TP_STATUS_AVAILABLE);
				packet_increment_head(&po->tx_ring);
				kfree_skb(skb);
				continue;
			} else {
				status = TP_STATUS_WRONG_FORMAT;
				err = tp_len;
				goto out_status;
			}
		}

		skb->destructor = tpacket_destruct_skb;
		__packet_set_status(po, ph, TP_STATUS_SENDING);
		atomic_inc(&po->tx_ring.pending);

		status = TP_STATUS_SEND_REQUEST;
		err = dev_queue_xmit(skb);
		if (unlikely(err > 0)) {
			err = net_xmit_errno(err);
			if (err && __packet_get_status(po, ph) ==
				   TP_STATUS_AVAILABLE) {
				/* skb was destructed already */
				skb = NULL;
				goto out_status;
			}
			/*
			 * skb was dropped but not destructed yet;
			 * let's treat it like congestion or err < 0
			 */
			err = 0;
		}
		packet_increment_head(&po->tx_ring);
		len_sum += tp_len;
	} while (likely((ph != NULL) ||
			((!(msg->msg_flags & MSG_DONTWAIT)) &&
			 (atomic_read(&po->tx_ring.pending))))
		);

	err = len_sum;
	goto out_put;

out_status:
	__packet_set_status(po, ph, status);
	kfree_skb(skb);
out_put:
	dev_put(dev);
out:
	mutex_unlock(&po->pg_vec_lock);
	return err;
#else
	return 0;
#endif
}

/*
event
1:up
2:down
3:unregister

*/
void packet_notify(int event, struct packet_dev *dev)
{
	struct packetpcb *pp;
	
	list_for_each_entry(pp, &packetpcbinfo.listhead, pp_list)
	{
		switch(event)
		{
		case 1:/*up*/
			if (dev->ifIndex == pp->pp_ifindex && pp->pp_proto &&
			    !pp->pp_running) {
				dev_add_pack(&pp->pp_packet);
				pp->pp_running = 1;
			}
			break;
		case 3:/*unregister*/
			if (pp->pp_mclist)
				packet_dev_mclist(dev, pp->pp_mclist, -1);
			/* fallthrough */
		case 2:/*down*/
			if (dev->ifIndex == pp->pp_ifindex) {
				/*spin_lock(&po->bind_lock);*/
				if (pp->pp_running) {
					dev_remove_pack(&pp->pp_packet);
					pp->pp_running = 0;
					pp->pp_socket->so_error = ENETDOWN;
					sorwakeup(pp->pp_socket);
				}
				if (event == 3) {
					pp->pp_ifindex = -1;
					pp->pp_packet.dev = NULL;
				}
				/*spin_unlock(&po->bind_lock);*/
			}
			break;
		default:
			break;
		}
	}
}
void packet_ctlinput(cmd, sa, ip)
	int cmd;
	struct sockaddr *sa;
	register struct ip *ip;
{
#if 0
	register struct udphdr *uh;
	extern struct in_addr zeroin_addr;
	extern u_char inetctlerrmap[];


	if (!PRC_IS_REDIRECT(cmd) &&
	    ((unsigned)cmd >= PRC_NCMDS || inetctlerrmap[cmd] == 0))
		return;
	if (ip) {
		uh = (struct udphdr *)((caddr_t)ip + (ip->ip_hl << 2));
		packet_pcbnotify(&udb, sa, uh->uh_dport, ip->ip_src, uh->uh_sport,
			cmd, udp_notify);
	} else
		packet_pcbnotify(&udb, sa, 0, zeroin_addr, 0, cmd, udp_notify);
#else
	return;
#endif
}


static void packet_dev_mc(struct packet_dev *dev, struct packet_mclist *i, int what)
{
	switch (i->type) {
	case PACKET_MR_MULTICAST:
	{
	#if 0
		if (what > 0)
			dev_mc_add(dev, i->addr, i->alen, 0);
		else
			dev_mc_delete(dev, i->addr, i->alen, 0);
	#endif
	}
		break;
	case PACKET_MR_PROMISC:
	#if 0
		dev_set_promiscuity(dev, what);
	#endif
		break;
	case PACKET_MR_ALLMULTI:
	#if 0
		dev_set_allmulti(dev, what);
	#endif
		break;
	default:;
	}
}

static void packet_dev_mclist(struct packet_dev *dev, struct packet_mclist *i, int what)
{
	for ( ; i; i=i->next) {
		if (i->ifindex == dev->ifIndex)
			packet_dev_mc(dev, i, what);
	}
}

static int packet_mc_add(struct packetpcb *pcb, struct packet_mreq_max *mreq)
{
	struct packet_mclist *ml, *i;
	struct packet_dev *dev;
	int err;

	/*rtnl_lock();*/

	err = -ENODEV;
	dev = packet_dev_get(mreq->mr_ifindex);
	if (!dev)
		goto done;

	err = -EINVAL;
	if (mreq->mr_alen > dev->addrlen)
		goto done;
#if 0
	err = ENOBUFS;
	i = (struct packet_mclist *)DS_MALLOC(sizeof(*i), 0);
	if (i == NULL)
		goto done;
#endif
	err = 0;
	for (ml = pcb->pp_mclist; ml; ml = ml->next) {
		if (ml->ifindex == mreq->mr_ifindex &&
		    ml->type == mreq->mr_type &&
		    ml->alen == mreq->mr_alen &&
		    memcmp(ml->addr, mreq->mr_address, ml->alen) == 0) {
			ml->count++;
			/* Free the new element ... */
			/*DS_FREE(i, 0/*MT_IFMADDR);*/
			goto done;
		}
	}
#if 0
	i->type = mreq->mr_type;
	i->ifindex = mreq->mr_ifindex;
	i->alen = mreq->mr_alen;
	memcpy(i->addr, mreq->mr_address, i->alen);
	i->count = 1;
	i->next = pcb->pp_mclist;
	pcb->pp_mclist = i;
	packet_dev_mc(dev, i, +1);
#endif
done:
	/*rtnl_unlock();*/
	return err;
}

static int packet_mc_drop(struct packetpcb *pcb, struct packet_mreq_max *mreq)
{
	struct packet_mclist *ml, **mlp;

	/*rtnl_lock();*/

	for (mlp = pcb->pp_mclist; (ml = *mlp) != NULL; mlp = &ml->next) {
		if (ml->ifindex == mreq->mr_ifindex &&
		    ml->type == mreq->mr_type &&
		    ml->alen == mreq->mr_alen &&
		    memcmp(ml->addr, mreq->mr_address, ml->alen) == 0) {
			if (--ml->count == 0) {
				struct packet_dev *dev;
				*mlp = ml->next;
				dev = packet_dev_get(ml->ifindex);
				if (dev) {
					packet_dev_mc(dev, ml, -1);
					packet_dev_put(dev);
				}
				//DS_FREE(ml, 0/*MT_IFMADDR*/);
			}
			/*rtnl_unlock();*/
			return 0;
		}
	}
	/*rtnl_unlock();*/
	return -EADDRNOTAVAIL;
}

static void packet_flush_mclist(struct packetpcb *pcb)
{
	struct packet_mclist *ml;

	if (!pcb->pp_mclist)
		return;

	/*rtnl_lock();*/
	while ((ml = pcb->pp_mclist) != NULL) {
		struct packet_dev *dev;

		pcb->pp_mclist = ml->next;
		if ((dev = packet_dev_get(ml->ifindex)) != NULL) {
			packet_dev_mc(dev, ml, -1);
			packet_dev_put(dev);
		}
		//DS_FREE(ml, 0/*MT_IFMADDR*/);
	}
	/*rtnl_unlock();*/
}

static int packet_set_ring(struct socket *sk, struct tpacket_req *req,
		int closing, int tx_ring)
{
#if 0
	struct pgv *pg_vec = NULL;
	struct packet_sock *po = pkt_sk(sk);
	int was_running, order = 0;
	struct packet_ring_buffer *rb;
	struct sk_buff_head *rb_queue;
	__be16 num;
	int err;

	rb = tx_ring ? &po->tx_ring : &po->rx_ring;
	rb_queue = tx_ring ? &sk->sk_write_queue : &sk->sk_receive_queue;

	err = -EBUSY;
	if (!closing) {
		if (atomic_read(&po->mapped))
			goto out;
		if (atomic_read(&rb->pending))
			goto out;
	}

	if (req->tp_block_nr) {
		/* Sanity tests and some calculations */
		err = -EBUSY;
		if (unlikely(rb->pg_vec))
			goto out;

		switch (po->tp_version) {
		case TPACKET_V1:
			po->tp_hdrlen = TPACKET_HDRLEN;
			break;
		case TPACKET_V2:
			po->tp_hdrlen = TPACKET2_HDRLEN;
			break;
		}

		err = -EINVAL;
		if (unlikely((int)req->tp_block_size <= 0))
			goto out;
		if (unlikely(req->tp_block_size & (PAGE_SIZE - 1)))
			goto out;
		if (unlikely(req->tp_frame_size < po->tp_hdrlen +
					po->tp_reserve))
			goto out;
		if (unlikely(req->tp_frame_size & (TPACKET_ALIGNMENT - 1)))
			goto out;

		rb->frames_per_block = req->tp_block_size/req->tp_frame_size;
		if (unlikely(rb->frames_per_block <= 0))
			goto out;
		if (unlikely((rb->frames_per_block * req->tp_block_nr) !=
					req->tp_frame_nr))
			goto out;

		err = -ENOMEM;
		order = get_order(req->tp_block_size);
		pg_vec = alloc_pg_vec(req, order);
		if (unlikely(!pg_vec))
			goto out;
	}
	/* Done */
	else {
		err = -EINVAL;
		if (unlikely(req->tp_frame_nr))
			goto out;
	}

	lock_sock(sk);

	/* Detach socket from network */
	spin_lock(&po->bind_lock);
	was_running = po->running;
	num = po->num;
	if (was_running) {
		__dev_remove_pack(&po->prot_hook);
		po->num = 0;
		po->running = 0;
		__sock_put(sk);
	}
	spin_unlock(&po->bind_lock);

	synchronize_net();

	err = -EBUSY;
	mutex_lock(&po->pg_vec_lock);
	if (closing || atomic_read(&po->mapped) == 0) {
		err = 0;
		spin_lock_bh(&rb_queue->lock);
		swap(rb->pg_vec, pg_vec);
		rb->frame_max = (req->tp_frame_nr - 1);
		rb->head = 0;
		rb->frame_size = req->tp_frame_size;
		spin_unlock_bh(&rb_queue->lock);

		swap(rb->pg_vec_order, order);
		swap(rb->pg_vec_len, req->tp_block_nr);

		rb->pg_vec_pages = req->tp_block_size/PAGE_SIZE;
		po->prot_hook.func = (po->rx_ring.pg_vec) ?
						tpacket_input : packet_input;
		skb_queue_purge(rb_queue);
		if (atomic_read(&po->mapped))
			pr_err("packet_mmap: vma is busy: %d\n",
			       atomic_read(&po->mapped));
	}
	mutex_unlock(&po->pg_vec_lock);

	spin_lock(&po->bind_lock);
	if (was_running && !po->running) {
		sock_hold(sk);
		po->running = 1;
		po->num = num;
		dev_add_pack(&po->prot_hook);
	}
	spin_unlock(&po->bind_lock);

	release_sock(sk);

	if (pg_vec)
		free_pg_vec(pg_vec, order, req->tp_block_nr);
out:
	return err;
#else
	return 0;
#endif
}


/*
 * packet socket option processing.
 */
int
packet_ctloutput(op, so, level, optname, m)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **m;
{
	struct packetpcb *inp = sotoppcb(so);
	int error = OK;
	int len, optval = 0;


	//if (level != SOL_PACKET)
	//	return ENOPROTOOPT;

#define OPTSET(bit) \
do { \
	if (optval) \
		inp->pp_flags |= (bit); \
	else \
		inp->pp_flags &= ~(bit); \
} while (0)
#define OPTBIT(bit) (inp->pp_flags & (bit) ? 1 : 0)
	switch (op)
	{
		case PRCO_SETOPT:
			len = (*m)->m_len;

			switch (optname) {
			case PACKET_ADD_MEMBERSHIP:
			case PACKET_DROP_MEMBERSHIP:
			{
				struct packet_mreq_max mreq;
				
				memset(&mreq, 0, sizeof(mreq));
				if (len < sizeof(struct packet_mreq))
				{
					error = EINVAL;
					break;
				}
				if (len > sizeof(mreq))
					len = sizeof(mreq);
				if (len < (mreq.mr_alen + offsetof(struct packet_mreq, mr_address)))
				{
					error = EINVAL;
					break;
				}
				if (optname == PACKET_ADD_MEMBERSHIP)
					error = packet_mc_add(inp, &mreq);
				else
					error = packet_mc_drop(inp, &mreq);
				break;
			}
			case PACKET_RX_PKTINFO:
				if (len != sizeof(int))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				OPTSET(PACKETCB_PKTINFO);
				break;
			case PACKET_ORIGDEV:
				if (len != sizeof(int))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				inp->pp_origdev= optval;
				break;
			case PACKET_RX_RING:
			case PACKET_TX_RING:
			{
				struct tpacket_req req;

				if (len < sizeof(req))
				{
					error = EINVAL;
					break;
				}
			#if 0
				if (pkt_sk(sk)->has_vnet_hdr)
					return -EINVAL;
			#endif
				error = packet_set_ring(so, &req, 0, optname == PACKET_TX_RING);
				break;
			}
			case PACKET_COPY_THRESH:
			{

				if (len != sizeof(optval))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				inp->copy_thresh = optval;
				break;
			}
			case PACKET_VERSION:
			{

				if (len != sizeof(optval))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				
				if (inp->rx_ring.pg_vec || inp->tx_ring.pg_vec)
				{
					error = EBUSY;
					break;
				}
				switch (optval) {
				case TPACKET_V1:
				case TPACKET_V2:
					inp->tp_version = optval;
					break;
				default:
					error = EINVAL;
					break;
				}
				break;
			}
			case PACKET_RESERVE:
			{
				if (len != sizeof(optval))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				if (inp->rx_ring.pg_vec || inp->tx_ring.pg_vec)
				{
					error = EBUSY;
					break;
				}
				inp->tp_reserve = optval;
				break;
			}
			case PACKET_LOSS:
			{
				if (len != sizeof(optval))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				if (inp->rx_ring.pg_vec || inp->tx_ring.pg_vec)
				{
					error = EBUSY;
					break;
				}
				inp->tp_loss = !!optval;
				break;
			}
			case PACKET_AUXDATA:
			{
				if (len < sizeof(optval))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				inp->auxdata = !!optval;
				break;
			}
		#if 0
			case PACKET_ORIGDEV:
			{
				if (len < sizeof(optval))
				{
					error = EINVAL;
					break;
				}

				inp->origdev = !!optval;
				break;
			}
	
			case PACKET_VNET_HDR:
			{
				if (so->so_type != SOCK_RAW)
				{
					error = EINVAL;
					break;
				}
				if (inp->rx_ring.pg_vec || inp->tx_ring.pg_vec)
				{
					error = EBUSY;
					break;
				}
				if (len < sizeof(optval))
				{
					error = EINVAL;
					break;
				}
			
				inp->has_vnet_hdr = !!optval;
				break;
			}
		#endif
			case PACKET_TIMESTAMP:
			{
				if (len != sizeof(optval))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				inp->tp_tstamp = optval;
				break;
			}
			case PACKET_RXMODE:
			{
				if (len != sizeof(optval))
				{
					error = EINVAL;
					break;
				}
				optval = *mtod((*m), int *);
				inp->pp_packet.rxMode = optval;
				break;
			}
			/*
			case PACKET_COPYDATA:
			{
				if (len != sizeof(optval))
				{
					error = EINVAL;
					break;
				}

				optval = *mtod((*m), int *);
				inp->pp_packet.copyData = optval;
				break;
			}
			*/
			default:
				return ENOPROTOOPT;
			}
			break;
		case PRCO_GETOPT:
			switch (optname) {
			case PACKET_RX_PKTINFO:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = OPTBIT(PACKETCB_PKTINFO);
				break;
			case PACKET_ORIGDEV:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->pp_origdev;
				break;
			case PACKET_STATISTICS:
			{
				struct tpacket_stats *st = mtod((*m), struct tpacket_stats *);
				(*m)->m_len = sizeof(struct tpacket_stats);
				//memcpy(st, &inp->stats, sizeof(*st));
				//memset(&inp->stats, 0, sizeof(*st));
				st->tp_packets += st->tp_drops;
			}
				break;
			case PACKET_AUXDATA:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->auxdata;
				break;
		#if 0
			case PACKET_ORIGDEV:
				if (len > sizeof(int))
					len = sizeof(int);
				*mtod((*m), int *) = inp->origdev;
				break;
		#endif
			case PACKET_VNET_HDR:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->has_vnet_hdr;
				break;
			case PACKET_VERSION:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->tp_version;
				break;
			case PACKET_HDRLEN:
				switch (optval) {
				case TPACKET_V1:
					optval = sizeof(struct tpacket_hdr);
					break;
				case TPACKET_V2:
					optval = sizeof(struct tpacket2_hdr);
					break;
				default:
					return EINVAL;
				}
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = optval;
				break;
			case PACKET_RESERVE:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->tp_reserve;
				break;
			case PACKET_LOSS:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->tp_loss;
				break;
			case PACKET_TIMESTAMP:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->tp_tstamp;
				break;
			case PACKET_RXMODE:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->pp_packet.rxMode;
				break;
			/*
			case PACKET_COPYDATA:
				(*m)->m_len = sizeof(int);
				*mtod((*m), int *) = inp->pp_packet.copyData;
				break;
			*/
			default:
				return ENOPROTOOPT;
			}
		default:
			return ENOPROTOOPT;
	}
	return error;
}


int packet_ctloutput2(struct socket *so,struct sockopt *sopt)
{
	int status = OK;
	struct mbuf *m = NULL;
	//m = netTupleGet (_pNetDpool, sopt->sopt_valsize, M_DONTWAIT, MT_SOOPTS, TRUE);

	if (m == NULL)
	    return ENOBUFS;

	if(sopt->sopt_dir == PRCO_SETOPT)
	{
		bcopy(sopt->sopt_val, mtod(m, caddr_t), sopt->sopt_valsize);
	}
	m->m_len = sopt->sopt_valsize;

		
	status = packet_ctloutput(sopt->sopt_dir, so,
		sopt->sopt_level, sopt->sopt_name, &m);

	if(sopt->sopt_dir == PRCO_GETOPT)
	{
		bcopy(mtod(m, caddr_t), sopt->sopt_val, m->m_len);
	}

	m_freem(m);

	return status;
}


/*
 * Generic internet control operations (ioctl's).
 * Ifp is 0 if not an interface-specific ioctl.
 */
/* ARGSUSED */
int
packet_control(so, cmd, data, dev)
	struct socket *so;
	u_long cmd;
	caddr_t data;
	struct packet_dev *dev;
{
	dev = dev;
	switch(cmd)
	{
	default:
		return (EOPNOTSUPP);
		break;
	}
	return 0;
}

static int packet_attach(struct socket *so, int proto, struct proc *p)
{
	struct packetpcb *inp = sotoppcb(so);
	int error = 0;

	if (inp)
	{
		panic("packet_attach");
		return EINVAL;
	}
	//if ((so->so_state & SS_PRIV) == 0) {
	//	return EACCES;
	//}
	if (error = soreserve(so, packet_sendspace, packet_recvspace))
		return error;
	if (error = packet_pcballoc(so, &packetpcbinfo))
		return error;

	inp = (struct packetpcb *)so->so_pcb;
	inp->pp_proto = proto;
	
	inp->pp_packet.af_packet_priv = inp;

	inp->pp_packet.func = packet_input;

	inp->pp_packet.rxMode = PACKET_BRIDGEMODE;

	if (so->so_type == SOCK_PACKET)
		inp->pp_packet.func = packet_input_spkt;
	
	if (proto) {
		inp->pp_packet.type = proto;
		dev_add_pack(&inp->pp_packet);
		inp->pp_running = 1;
	}
	return error;
}

static int packet_detach(struct socket *so)
{
	struct packetpcb *inp = sotoppcb(so);

	if (inp == NULL)
	{
		panic("packet_detach");
		return EINVAL;
	}
	
	/*
	 *	Unhook packet receive handler.
	 */

	if(inp->pp_running)
	{
		/*
		 *	Remove the protocol hook
		 */
		inp->pp_running = 0;
		inp->pp_proto = 0;
		dev_remove_pack(&inp->pp_packet);
	}
	packet_pcbdetach(inp);

	return 0;
}


static int packet_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct packetpcb *inp = sotoppcb(so);
	int s, error,proto;

	struct sockaddr_ll *sll = (struct sockaddr_ll *)nam;
	struct packet_dev *dev=NULL;

	if (sll->sll_family != AF_PACKET)
	{
		error = EINVAL;
		return error;
	}
	if (sll->sll_ifindex)
	{
		dev = packet_dev_get(sll->sll_ifindex);
		if (dev == NULL)
		{
			error = ENODEV;
			return error;
		}
	}
	/*
	 *	Unhook packet receive handler.
	 */

	if(inp->pp_running)
	{
		/*
		 *	Remove the protocol hook
		 */
		inp->pp_running = 0;
		inp->pp_proto = 0;
		dev_remove_pack(&inp->pp_packet);
	}
	
	proto = sll->sll_protocol?sll->sll_protocol:inp->pp_proto;
	
	inp->pp_ifindex = sll->sll_ifindex;
	inp->pp_proto = proto;
	
	inp->pp_packet.type = proto;
	inp->pp_packet.dev = dev;
	inp->pp_packet.af_packet_priv = inp;

	dev_add_pack(&inp->pp_packet);
	
	inp->pp_running = 1;

	return OK;
}

static int packet_listen(struct socket *so, struct proc *p)
{
	return EOPNOTSUPP;
}

static int packet_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	return EOPNOTSUPP;
}

static int packet_accept(struct socket *so, struct sockaddr **nam)
{
	return EOPNOTSUPP;
}

static int packet_disconnect(struct socket *so)
{
	struct packetpcb *inp = sotoppcb(so);

	if (inp)
	{
		panic("packet_disconnect");
		return EINVAL;
	}
	else
	{
		return 0;
	}

	/*
	 *	Unhook packet receive handler.
	 */

	if(inp->pp_running)
	{
		/*
		 *	Remove the protocol hook
		 */
		inp->pp_running = 0;
		inp->pp_proto = 0;
		dev_remove_pack(&inp->pp_packet);
	}

	packet_pcbdisconnect(inp);
	so->so_state &= ~SS_ISCONNECTED;
	soisdisconnected(so);

	packet_pcbdetach(inp);

	return 0;
}

static int packet_shutdown(struct socket *so)
{
	socantsendmore(so);
	return 0;
}


static int packet_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	    struct mbuf *control, struct proc *p)
{
	struct packetpcb *inp = sotoppcb(so);
	int error = 0;

	if (inp == 0) {
		m_freem(m);
		return EINVAL;
	}

	error = packet_output(so, m, addr, control, p);

	if (control)
		m_freem(control);		/* XXX */
	
	return 0/*error*/;
}


static int packet_sense_null(struct socket *so, struct stat *sb)
{
	//sb->st_blksize = so->so_snd.sb_hiwat;
	return 0;
}

static int packet_notsupp(struct socket *so, struct mbuf *m, int flags)
{
	return EOPNOTSUPP;
}

static int packet_abort(struct socket *so)
{
	struct packetpcb *inp = sotoppcb(so);
	int s;

	if (inp == 0)
		return EINVAL;	/* ??? possible? panic instead? */
	soisdisconnected(so);
	packet_pcbdetach(inp);
	return 0;
}

static int _packet_setsockaddr(struct socket *so, struct sockaddr *nam)
{
	struct sockaddr_ll *sll = (struct sockaddr_ll *)nam;
	struct packetpcb *inp = sotoppcb(so);
	struct packet_dev *dev = NULL;
	
	if (inp == 0)
	{
		return EINVAL;
	}
	
	sll->sll_family = AF_PACKET;
	sll->sll_ifindex = inp->pp_ifindex;
	sll->sll_protocol = inp->pp_proto;
	sll->sll_pkttype = 0;
	
	dev = packet_dev_get(inp->pp_ifindex);
	if (dev) {
		sll->sll_hatype = dev->type;
		sll->sll_halen = dev->addrlen;
		memcpy(sll->sll_addr, dev->addr, dev->addrlen);
	} else {
		sll->sll_hatype = 0;	/* Bad: we have no ARPHRD_UNSPEC */
		sll->sll_halen = 0;
	}
	sll->sll_len = offsetof(struct sockaddr_ll, sll_addr) + sll->sll_halen;
	return 0;
}

static int packet_setsockaddr(struct socket *so, struct sockaddr **nam)
{
	struct sockaddr_ll *sll = (struct sockaddr_ll *)nam;
	struct packetpcb *inp = sotoppcb(so);
	struct packet_dev *dev = NULL;
	
	if (inp == 0)
	{
		return EINVAL;
	}
	
	sll = (struct sockaddr_ll *)malloc(sizeof(struct sockaddr_ll),M_DEVBUF, M_WAITOK|M_ZERO);
	if (sll == NULL)
		return (ENOBUFS);
	bzero(sll, sizeof(*sll));
	if(_packet_setsockaddr(so, sll))
	{
		//DS_FREE(sll,2);
		return ECONNRESET;
	}
	*nam = (struct sockaddr *)sll;
	return 0;
}

static int packet_setpeeraddr(struct socket *so, struct sockaddr **nam)
{
	return EOPNOTSUPP;
}


static unsigned int packet_poll(struct socket *so, int events, struct ucred *cred, struct proc *p)
{
#if 0
	struct sock *sk = sock->sk;
	struct packet_sock *po = pkt_sk(sk);
	unsigned int mask = datagram_poll(file, sock, wait);

	spin_lock_bh(&sk->sk_receive_queue.lock);
	if (po->rx_ring.pg_vec) {
		if (!packet_previous_frame(po, &po->rx_ring, TP_STATUS_KERNEL))
			mask |= POLLIN | POLLRDNORM;
	}
	spin_unlock_bh(&sk->sk_receive_queue.lock);
	spin_lock_bh(&sk->sk_write_queue.lock);
	if (po->tx_ring.pg_vec) {
		if (packet_current_frame(po, &po->tx_ring, TP_STATUS_AVAILABLE))
			mask |= POLLOUT | POLLWRNORM;
	}
	spin_unlock_bh(&sk->sk_write_queue.lock);
	return mask;
#else
	return 0;
#endif
}



/*ARGSUSED*/
int
packet_usrreq(so, req, m, nam, control)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
{
	int error = 0;
	struct packetpcb *inp = sotoppcb(so);
	struct sockaddr_ll *sll;

	if (req == PRU_CONTROL)
		return (packet_control(so, (u_long)m, (caddr_t)nam,
                    (struct packet_dev *)control));

	switch (req) {

	case PRU_ATTACH:
		error = packet_attach(so, (int32_t)nam, 0);
		break;
	case PRU_DETACH:
		error = packet_detach(so);
		break;
	case PRU_BIND:
		sll = mtod(nam, struct sockaddr_ll *);

		if (nam->m_len != sizeof(struct sockaddr_ll))
		{
			error = EINVAL;
			break;
		}
		
		error = packet_bind(so, (struct sockaddr *)sll, 0);
		break;
	case PRU_LISTEN:
		error = packet_listen(so, 0);
		break;
	case PRU_CONNECT:
	case PRU_CONNECT2:
		sll = mtod(nam, struct sockaddr_ll *);

		if (nam->m_len != sizeof(struct sockaddr_ll))
		{
			error = EINVAL;
			break;
		}
	    error = packet_connect(so, (struct sockaddr *)sll, 0);
		break;
	case PRU_ACCEPT:
		error = packet_accept(so, (struct sockaddr *)nam);
		break;
	case PRU_DISCONNECT:
		error = packet_disconnect(so);
		break;
	case PRU_SHUTDOWN:
		error = packet_shutdown(so);
		break;

	/*
	 * Ship a packet out.  The appropriate raw output
	 * routine handles any massaging necessary.
	 */
	case PRU_SEND:
		if(nam != NULL)
		{
			sll = mtod(nam, struct sockaddr_ll *);
			if (nam->m_len != sizeof(struct sockaddr_ll))
				sll = NULL;
		}
		else
			sll = NULL;
		error = packet_send(so, 0, m, (struct sockaddr *)sll, control, 0);
		m = NULL;
		break;
	case PRU_SENSE:
	{
		/*
		 * stat: don't bother with a blocksize.
		 */
		//struct stat sb;
		//return packet_sense_null(so, &sb);
	}
		break;

	/*
	 * Not supported.
	 */
	case PRU_RCVOOB:
	case PRU_RCVD:
	case PRU_SENDOOB:
		error = packet_notsupp(so, m, control);
		break;
	case PRU_ABORT:
		error = packet_abort(so);
		break;
	case PRU_SOCKADDR:
		sll = mtod(nam, struct sockaddr_ll *);
		error = _packet_setsockaddr(so, (struct sockaddr *)sll);
		break;
	case PRU_PEERADDR:
		error = EOPNOTSUPP;
		break;

	default:
		panic("packet_usrreq");
	}
	if (m != NULL)
		m_freem(m);

	return (error);
}


struct pr_usrreqs packet_usrreqs = {
	.pru_abort =		packet_abort,
	.pru_attach =		packet_attach,
	.pru_bind =			packet_bind,
	.pru_connect =		packet_connect,
	.pru_control =		packet_control,
	.pru_detach =		packet_detach,
	.pru_disconnect =	packet_disconnect,
	.pru_peeraddr =		packet_setpeeraddr,
	.pru_send =			packet_send,
	.pru_shutdown =		packet_shutdown,
	.pru_sockaddr =		packet_setsockaddr,
	.pru_soreceive =	soreceive_dgram,
	.pru_sosend =		sosend_dgram,
	//.pru_sosetlabel =	in_pcbsosetlabel,
	//.pru_close =		udp6_close
};

struct protosw 	packetsw [] = {
{
	.pr_type =		SOCK_DGRAM,
	.pr_domain =		&packetsw,
	.pr_protocol =		0,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		NULL,
	.pr_ctlinput =		NULL,
	.pr_ctloutput =		NULL,
	.pr_init =		packet_init,
	.pr_usrreqs =		&packet_usrreqs
},
{
	.pr_type =		SOCK_RAW,
	.pr_domain =		&packetsw,
	.pr_protocol =		0,
	.pr_flags = 	PR_ATOMIC|PR_ADDR,
	.pr_input = 	NULL,
	.pr_ctlinput =		NULL,
	.pr_ctloutput = 	NULL,
	.pr_init =		NULL,
	.pr_usrreqs =		&packet_usrreqs
},

};



void packet_init();

STATUS packetRawInit (void)
{
	struct protosw	* pProtoSwitch; 

	if (_packetSwIndex >= sizeof(packetsw)/sizeof(packetsw[0]))
		return (ERROR) ;

	pProtoSwitch = &packetsw[_packetSwIndex]; 

	if (pProtoSwitch->pr_domain != NULL)
		return (OK); 				/* already initialized */

	pProtoSwitch->pr_type   	=  SOCK_RAW;
	pProtoSwitch->pr_domain   	=  &packetdomain;
	pProtoSwitch->pr_protocol   =  0;
	pProtoSwitch->pr_flags	=  PR_ATOMIC | PR_ADDR;
	pProtoSwitch->pr_input	=  0;
	pProtoSwitch->pr_output	=  packet_output;
	pProtoSwitch->pr_ctlinput	=  packet_ctlinput;
	pProtoSwitch->pr_ctloutput	=  packet_ctloutput2;
	pProtoSwitch->pr_usrreqs	=  &packet_usrreqs;
	pProtoSwitch->pr_init	=  0;
	pProtoSwitch->pr_fasttimo	=  0;
	pProtoSwitch->pr_slowtimo	=  0;
	pProtoSwitch->pr_drain	=  0;


	_packetSwIndex++; 
	return (OK); 
}

STATUS packetDgramInit (void)
{
	struct protosw	* pProtoSwitch; 

	if (_packetSwIndex >= sizeof(packetsw)/sizeof(packetsw[0]))
		return (ERROR) ;

	pProtoSwitch = &packetsw[_packetSwIndex]; 

	if (pProtoSwitch->pr_domain != NULL)
		return (OK); 				/* already initialized */

	pProtoSwitch->pr_type   	=  SOCK_DGRAM;
	pProtoSwitch->pr_domain   	=  &packetdomain;
	pProtoSwitch->pr_protocol   =  0;
	pProtoSwitch->pr_flags	=  PR_ATOMIC | PR_ADDR;
	pProtoSwitch->pr_input	=  0;
	pProtoSwitch->pr_output	=  packet_output;
	pProtoSwitch->pr_ctlinput	=  packet_ctlinput; 

	pProtoSwitch->pr_ctloutput	=  packet_ctloutput2;
	pProtoSwitch->pr_usrreqs	=  &packet_usrreqs;

	pProtoSwitch->pr_init	=  packet_init;
	pProtoSwitch->pr_fasttimo	=  0;
	pProtoSwitch->pr_slowtimo	=  0;
	pProtoSwitch->pr_drain	=  0;

	_packetSwIndex++; 
	return (OK); 
}

void packetDomainInit(struct domain *dp)
{
	struct protosw *pr;

	if (dp->dom_init)
		(*dp->dom_init)();
	for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++)
		if (pr->pr_init)
			(*pr->pr_init)();
}



STATUS packetProtoInit (int autoLoadPort)
{
	int s;

	//if (sockLibAdd ((FUNCPTR) bsdSockLibInit, AF_PACKET, AF_PACKET) == ERROR)
	//	return (ERROR);

	packetDgramInit ();       /* icmp protocol initialization */

	packetRawInit ();

	s = splnet();
	//addDomain (&packetdomain);
	packetDomainInit(&packetdomain);
	splx (s);

	packetDevInit(autoLoadPort);
	
	return (OK);
}

void afSocketBufStatsShow(void)
{
	struct packetpcb *pp;
	int s;


	
	list_for_each_entry(pp, &packetpcbinfo.listhead, pp_list)
	{
		printf("packet socket : sb_lowat=%d,sb_mb=%#x,sbspace(so_rcv)=%d,sb_hiwat=%d,sbspace(so_snd)=%d,sb_hiwat=%d\n\r",
				pp->pp_socket->so_rcv.sb_lowat,pp->pp_socket->so_rcv.sb_mb,
				sbspace(&pp->pp_socket->so_rcv),pp->pp_socket->so_rcv.sb_hiwat,sbspace(&pp->pp_socket->so_snd),pp->pp_socket->so_snd.sb_hiwat);		
	}

	return;

}





struct domain packetdomain = {
	.dom_family =		AF_PACKET,
	.dom_name =		"packet",
	.dom_protosw =		packetsw,
	.dom_protoswNPROTOSW =	&packetsw[nitems(packetsw)],

};



VNET_DOMAIN_SET(packet);


/*
uspIfInitApp 1
packetProtoInit 1

admin
12345
con
int fa 1/1
no shut
exit
send packet fastethernet 1/1 0x88cc 00.04.67.90.99.00 


lldpPktTst_1

*/
