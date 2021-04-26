/* packet_cb.h - packet control block header file */


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

#ifndef __INCpacket_pcbh
#define __INCpacket_pcbh

#ifdef __cplusplus
extern "C" {
#endif

#include "list.h"
#include "packet_dev.h"
//#include "linux/if_packet.h"


#define OK 0
#define ERROR -1
#define STATUS int
#define FAST register
#define TORNADO_VERSION 221

typedef struct
{
	uint8_t *pBuf;
	uint32_t len;
}octetstring;


struct sockaddr_ll {
	uint8_t		sll_len;
	uint8_t		sll_family;
	uint16_t	sll_protocol;
	uint32_t	sll_ifindex;
	uint16_t	sll_hatype;
	uint8_t		sll_pkttype;
	uint8_t		sll_halen;
	uint8_t		sll_addr[8];	/*dest mac addr*/
};

typedef struct llHdrInfo
    {
    int		destAddrOffset;		/* destination addr offset in mBlk */
    int		destSize; 		/* destination address size */
    int		srcAddrOffset;		/* source address offset in mBlk */
    int		srcSize;		/* source address size */
    int		ctrlAddrOffset;		/* control info offset in mBlk */
    int		ctrlSize;		/* control info size */
    int		pktType;		/* type of the packet */
    int		dataOffset;		/* data offset in the mBlk */
    } LL_HDR_INFO;




/* Packet types */

#define PACKET_HOST		0		/* To us		*/
#define PACKET_BROADCAST	1		/* To all		*/
#define PACKET_MULTICAST	2		/* To group		*/
#define PACKET_OTHERHOST	3		/* To someone else 	*/
#define PACKET_OUTGOING		4		/* Outgoing of any type */
/* These ones are invisible by user level */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	*/

/* Packet socket options */

#define PACKET_ADD_MEMBERSHIP		1
#define PACKET_DROP_MEMBERSHIP		2
#define PACKET_RECV_OUTPUT		3
/* Value 4 is still used by obsolete turbo-packet. */
#define PACKET_RX_RING			5
#define PACKET_STATISTICS		6
#define PACKET_COPY_THRESH		7
#define PACKET_AUXDATA			8
#define PACKET_ORIGDEV			9
#define PACKET_VERSION			10
#define PACKET_HDRLEN			11
#define PACKET_RESERVE			12
#define PACKET_TX_RING			13
#define PACKET_LOSS			14
#define PACKET_VNET_HDR			15
#define PACKET_TX_TIMESTAMP		16
#define PACKET_TIMESTAMP		17
#define PACKET_FANOUT			18
#define PACKET_TX_HAS_OFF		19
#define PACKET_RX_PKTINFO		20	/*参数为int,liulei add 2014-04-08**/
#define PACKET_TX_PKTINFO		21	/*参数为struct packet_txpktinfo*/
#define PACKET_RXMODE			22	/*参数为int,liulei add 2014-05-14**/

#define PACKET_FANOUT_HASH		0
#define PACKET_FANOUT_LB		1
#define PACKET_FANOUT_CPU		2
#define PACKET_FANOUT_ROLLOVER		3
#define PACKET_FANOUT_RND		4
#define PACKET_FANOUT_FLAG_ROLLOVER	0x1000
#define PACKET_FANOUT_FLAG_DEFRAG	0x8000





struct tpacket_stats
{
	u_int	tp_packets;
	u_int	tp_drops;
};

struct tpacket_hdr
{
	uint32_t	tp_status;
#define TP_STATUS_KERNEL	0
#define TP_STATUS_USER		1
#define TP_STATUS_COPY		2
#define TP_STATUS_LOSING	4
#define TP_STATUS_CSUMNOTREADY	8
	uint32_t	tp_len;
	uint32_t	tp_snaplen;
	uint16_t	tp_mac;
	uint16_t	tp_net;
	uint32_t	tp_sec;
	uint32_t	tp_usec;
};

#define TPACKET_ALIGNMENT	16
#define TPACKET_ALIGN(x)	(((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
#define TPACKET_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + sizeof(struct sockaddr_ll))


struct tpacket2_hdr {
	uint32_t		tp_status;
	uint32_t		tp_len;
	uint32_t		tp_snaplen;
	uint16_t		tp_mac;
	uint16_t		tp_net;
	uint32_t		tp_sec;
	uint32_t		tp_nsec;
	uint16_t		tp_vlan_tci;
	uint16_t		tp_padding;
};

#define TPACKET2_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket2_hdr)) + sizeof(struct sockaddr_ll))

enum tpacket_versions {
	TPACKET_V1,
	TPACKET_V2,
};


#define PACKET_MR_MULTICAST	0
#define PACKET_MR_PROMISC	1
#define PACKET_MR_ALLMULTI	2
#define PACKET_MR_UNICAST	3

#define PACKET_BRIDGEMODE	0
#define PACKET_ROUTERMODE	1




/*
   Frame structure:

   - Start. Frame must be aligned to TPACKET_ALIGNMENT=16
   - struct tpacket_hdr
   - pad to TPACKET_ALIGNMENT=16
   - struct sockaddr_ll
   - Gap, chosen so that packet data (Start+tp_net) alignes to TPACKET_ALIGNMENT=16
   - Start+tp_mac: [ Optional MAC header ]
   - Start+tp_net: Packet data, aligned to TPACKET_ALIGNMENT=16.
   - Pad to align to TPACKET_ALIGNMENT=16
 */

struct tpacket_req
{
	u_int	tp_block_size;	/* Minimal size of contiguous block */
	u_int	tp_block_nr;	/* Number of blocks */
	u_int	tp_frame_size;	/* Size of frame */
	u_int	tp_frame_nr;	/* Total number of frames */
};



struct packet_mreq
{
	int		mr_ifindex;
	u_short	mr_type;
	u_short	mr_alen;
	u_char	mr_address[8];
};

#define PACKET_MR_MULTICAST	0
#define PACKET_MR_PROMISC	1
#define PACKET_MR_ALLMULTI	2


/*!
uspMuxTkSend函数指定pSpareData参数。
用于指定是否发送的端口。
*/
typedef struct
{
#define MUX_ENCAP_ETHERNET2	0
#define MUX_ENCAP_RAW	1		/*802.3 frame format*/
#define MUX_ENCAP_SAP	2		/*802.3 frame format with 802.2 protocol*/
#define MUX_ENCAP_SNAP		3			/*802.3 frame format with 802.2 SNAP*/
#define MUX_ENCAP_L2TP		4			/*l2tp封装格式,用于va向tunnel接口发包封装时使用*/
	int32_t encapType;

#define MUX_PORTFILTER	0x1
#define MUX_PORTINCLUDE	0x2
#define MUX_PORTEXCLUDE	0x4
#define MUX_SRCMAC		0x8
#define MUX_OUTERVLANTAG	0x10
#define MUX_INNERVLANTAG	0x20
	int32_t type;


	uint8_t	dsap;		/*llc dsap,当封装类型为MUX_ENCAP_SAP,MUX_ENCAP_SNAP时传入*/
	uint8_t	ssap;		/*llc ssap,当封装类型为MUX_ENCAP_SAP,MUX_ENCAP_SNAP时传入*/
	uint8_t ctrl;		/*llc control,当封装类型为MUX_ENCAP_SAP,MUX_ENCAP_SNAP时传入*/

	int8_t include;	/*取值为1表示include，否则为exclude*/
	
	
	uint32_t *ports;
	int16_t portNum;
	
	uint8_t mac[6];

	/*
	outerVid和innverVid字段主要是为了解决以太网子接口发包参数问题.由于以太网子接口可以终结一层或双层vlan包,
	因此arp学习需要支持同时保存内外双层vlan,在发包时携带vlan信息给mux接口,实现单播包的单播发送.
	*/
	uint16_t outerVid:12,
			outerPri:4;
	uint16_t innerVid:12,
			innerPri:4;
}tMuxNptPktParam;



struct skb_pktinfo {
#define PACKET_ENCAP		0x1
#define PACKET_PORTINCLUDE	0x2
#define PACKET_PORTEXCLUDE	0x4
#define PACKET_SRCMAC		0x8
#define PACKET_OUTERVLANTAG	0x10
#define PACKET_INNERVLANTAG	0x20

	unsigned int pkt_op;
	unsigned int		refcnt;
	
#define PACKET_ENCAP_ETHERNET2	0
#define PACKET_ENCAP_RAW		1		/*802.3 frame format*/
#define PACKET_ENCAP_SAP		2		/*802.3 frame format with 802.2 protocol*/
#define PACKET_ENCAP_SNAP		3		/*802.3 frame format with 802.2 SNAP*/

	unsigned int  pkt_encaptype;
	unsigned char	pkt_dsap;		/*llc dsap,μ±·a×°ààDí?aPACKET_ENCAP_SAP,PACKET_ENCAP_SNAPê±′?è?*/
	unsigned char	pkt_ssap;		/*llc ssap,μ±·a×°ààDí?aPACKET_ENCAP_SAP,PACKET_ENCAP_SNAPê±′?è?*/
	unsigned char pkt_ctrl;		/*llc control,μ±·a×°ààDí?aPACKET_ENCAP_SAP,PACKET_ENCAP_SNAPê±′?è?*/
	unsigned char pkt_portnum;

	unsigned char pkt_srcmac[8];
	
	unsigned int  pkt_ports[0];
};





struct packet_rxpktinfo {
	uint32_t	pkt_inport;	/*如果是vlan ip则表示收包的物理接口*/
	uint8_t		pkt_srcaddr[8];	/*dest mac addr*/
	uint16_t	pkt_outervid;
	uint16_t	pkt_innervid;
	uint8_t		pkt_dataoffset;
	uint8_t		pkt_outerpri;
	uint8_t		pkt_innerpri;
	uint8_t		pkt_cblen;
	uint8_t		pkt_cb[32];
	uint32_t	pkt_flags;
#define PACKET_FLAG_SLFTOCPU		0x1
#define PACKET_FLAG_SFLOWINGRESSTOCPU	0x2
#define PACKET_FLAG_SFLOWEGRESSTOCPU	0x4
#define PACKET_FLAG_IPFIXINGRESSTOCPU		0x8
#define PACKET_FLAG_IPFIXEGRESSTOCPU	0x10
#define PACKET_FLAG_TIMESTAMP	0x20
#define PACKET_FLAG_PONONUATTR	0x40
};

struct packet_txpktinfo {

#define PACKET_ENCAP		0x1
#define PACKET_PORTINCLUDE	0x2
#define PACKET_PORTEXCLUDE	0x4
#define PACKET_SRCMAC		0x8
#define PACKET_OUTERVLANTAG	0x10
#define PACKET_INNERVLANTAG	0x20

	int32_t pkt_op;

	uint16_t	pkt_outervid;
	uint16_t	pkt_innervid;
	uint8_t		pkt_outerpri;
	uint8_t		pkt_innerpri;
	uint16_t	res;
	
#define PACKET_ENCAP_ETHERNET2	0
#define PACKET_ENCAP_RAW		1		/*802.3 frame format*/
#define PACKET_ENCAP_SAP		2		/*802.3 frame format with 802.2 protocol*/
#define PACKET_ENCAP_SNAP		3		/*802.3 frame format with 802.2 SNAP*/

	int32_t pkt_encaptype;
	uint8_t	pkt_dsap;		/*llc dsap,当封装类型为PACKET_ENCAP_SAP,PACKET_ENCAP_SNAP时传入*/
	uint8_t	pkt_ssap;		/*llc ssap,当封装类型为PACKET_ENCAP_SAP,PACKET_ENCAP_SNAP时传入*/
	uint8_t pkt_ctrl;		/*llc control,当封装类型为PACKET_ENCAP_SAP,PACKET_ENCAP_SNAP时传入*/
	uint8_t pkt_portnum;

	uint8_t pkt_srcmac[8];
	
	uint32_t pkt_ports[0];
};




#if ((CPU_FAMILY==I960) && (defined __GNUC__))
#pragma align 1                 /* tell gcc960 not to optimize alignments */
#endif	/* CPU_FAMILY==I960 */

#define MAX_ADDR_LEN	32
struct packet_mclist
{
	struct packet_mclist	*next;
	int			ifindex;
	int			count;
	unsigned short		type;
	unsigned short		alen;
	unsigned char		addr[MAX_ADDR_LEN];
	unsigned short vid;
	unsigned short pad;
};
/* identical to struct packet_mreq except it has
 * a longer address field.
 */
struct packet_mreq_max
{
	int		mr_ifindex;
	unsigned short	mr_type;
	unsigned short	mr_alen;
	unsigned char	mr_address[MAX_ADDR_LEN];
	unsigned short vid;
	unsigned short pad;
};


struct pgv {
	char *buffer;
};

struct packet_ring_buffer {
	struct pgv		*pg_vec;
	unsigned int		head;
	unsigned int		frames_per_block;
	unsigned int		frame_size;
	unsigned int		frame_max;

	unsigned int		pg_vec_order;
	unsigned int		pg_vec_pages;
	unsigned int		pg_vec_len;

	/*atomic_t		pending;*/
};

/*
 * Common structure pcb for internet protocol implementation.
 * Here are stored pointers to local and foreign host table
 * entries, local and foreign socket numbers, and pointers
 * up (to a socket structure) and down (to a protocol-specific)
 * control block.
 */


struct packetpcb {
	struct list_head pp_list;	/* list for all PCBs of this proto */
	struct list_head pp_hash;	/* hash list */
	struct	packetpcbinfo *pp_pcbinfo;
	struct	socket *pp_socket;	/* back pointer to socket */

	//struct tpacket_stats	stats;
	struct packet_ring_buffer	rx_ring;
	struct packet_ring_buffer	tx_ring;
	
	caddr_t	pp_ppcb;		/* pointer to per-protocol pcb */
	u_short pp_proto;		/* protocol type */
	u_short pp_vid:13,
	          pp_tos:3;
	u_int pp_running:1,
		 auxdata:1,
		 pp_origdev:1,
		 has_vnet_hdr:1;

	struct packet_type pp_packet;
	int pp_ifindex;
	int pp_flags;		/* generic IP/datagram flags */
	struct packet_mclist	*pp_mclist; /* multicast address */
	int	tp_version;
	unsigned int		tp_hdrlen;
	unsigned int		tp_reserve;
	unsigned int		tp_loss:1;
	unsigned int		tp_tstamp;
	int			copy_thresh;
};

#define	PACKETCB_PKTINFO		0x01 /* receive IP6 dst and I/F */

struct packetpcbinfo {
	struct list_head listhead;
	struct list_head *hashbase;
	unsigned long hashmask;
};


#if ((CPU_FAMILY==I960) && (defined __GNUC__))
#pragma align 0                 /* turn off alignment requirement */
#endif  /* CPU_FAMILY==I960 */


#define PACKET_PCBHASH( proto, port, mask) \
	(((proto) ^ (port)) & (mask))

#define	sotoppcb(so)	((struct packetpcb *)(so)->so_pcb)


extern int packet_pcballoc(struct socket *so, struct packetpcbinfo *pcbinfo);
extern void packet_pcbdetach (struct packetpcb *);
extern void packet_pcbdisconnect (struct packetpcb *);
extern void packet_pcbinshash (struct packetpcb *);
extern void packet_pcbrehash (struct packetpcb *);

#ifdef __cplusplus
}
#endif

#endif /* __INCpacket_pcbh */
