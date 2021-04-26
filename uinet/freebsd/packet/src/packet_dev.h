

/* packet_dev.h */ 

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

#ifndef __PACKET_DEV_H
#define __PACKET_DEV_H

#include "avl.h"
#include "list.h"

struct packet_dev {

	avl_node_t		node;

	uint32_t		ifIndex;
	uint32_t		type;
	uint16_t		tpid;
	uint8_t			up;
	uint8_t			addrlen;
	uint8_t			addr[16];
	uint32_t		refcnt;
	
	uint8_t			nptFlag;

	void			*cookie;
	
	int (*if_hard_start_xmit)		/*send frame. as muxSend*/
		(struct packet_dev *dev,struct mbuf *);
	int (*if_hard_header_parse)		/*send frame. as muxSend*/
		(struct packet_dev *dev, struct mbuf *);
	int (*if_hard_header)		/*build hard header*/
		(struct packet_dev *dev,
		struct mbuf *,
		u_short type,
		void *daddr,
		void *saddr,
		u_int len,
		u_short vid,
		int pri);
};


struct packet_type {
	struct list_head	node;	/*挂在packet_dev*/
	uint16_t		type;	/* This is really htons(ether_type). */
	uint8_t			rxMode;
				/*
				取值参见if_packet.h中PACKET_BRIDGEMODE和PACKET_ROUTERMODE.
				
				
				该字段缺省值为PACKET_BRIDGEMODE.
				可以通过PACKET_RXMODE选项进行设置.
				
				*/
	uint8_t		copyData:1,
				res:7;
	struct packet_dev	*dev;	/* NULL is wildcarded here	     */
	void			*af_packet_priv;	/*指向packet_cb*/
	int			(*func) (struct mbuf *,
					 struct packet_dev *,
					 struct packet_type *,
					 void *);
};

#if 1
/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
} ETHER_PACKED;

/* Ether header for tagged frames */
struct  ether_tag_header {
        u_char  ether_dhost[6];
        u_char  ether_shost[6];
	u_short ether_type;
	u_short ether_tag;
	u_short proto_type;
};
#endif

#define PTYPE_HASH_SIZE	(16)
#define PTYPE_HASH_MASK	(PTYPE_HASH_SIZE - 1)


#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
#define ETH_P_AX25	0x0002		/* Dummy protocol id for AX.25  */
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
#define ETH_P_802_2	0x0004		/* 802.2 frames			*/
#define ETH_P_SNAP	0x0005		/* Internal only		*/
#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009		/* Localtalk pseudo type	*/
#define ETH_P_PPPTALK	0x0010		/* Dummy type for Atalk over PPP*/
#define ETH_P_TR_802_2	0x0011i		/* 802.2 frames			*/
#define ETH_P_MOBITEX	0x0015		/* Mobitex (kaz@cafe.net)	*/
#define ETH_P_CONTROL	0x0016		/* Card specific control frames */
#define ETH_P_IRDA	0x0017		/* Linux-IrDA			*/
#define ETH_P_ECONET	0x0018		/* Acorn Econet			*/

#define DEBUG_PACKET_INPKT  0x01
#define DEBUG_PACKET_IN        0x02
#define DEBUG_PACKET_INPKT_TK        0x04
#define DEBUG_PACKET_ERR	0x08
#define DEBUG_PACKET_ALL 0xff
#define DEBUG_PACKET_NO 0
#endif

