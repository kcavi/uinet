

/* packet_dev.c */ 

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
#include <notifier.h>


typedef struct packetDevInfo
{
	avl_tree_t devTbl;
	int32_t autoLoadDev;
}tPacketDevInfo;

tPacketDevInfo gPacketDevInfo;


extern struct list_head ptype_base[PTYPE_HASH_SIZE];
extern struct list_head ptype_all;	/* Taps */

#if 1
int32_t gPacketDebug=0;
#define packetPrintf(lvl, _x)	{ if ( lvl & gPacketDebug ) printf _x;}
#endif

static int packetRcv(struct mbuf *m,
		     struct packet_dev *dev,
		     LL_HDR_INFO *llHdrInfo)
{
#if 0
	struct packet_type *pt,*lastpt=NULL;
	uint16_t type = llHdrInfo->pktType;
	int rc = FALSE;
	struct mbuf * copym;
	STDHDR_OBJ *pHdrObj = (STDHDR_OBJ*)PCOOKIE_TO_ENDOBJ(dev->cookie);
	int s = splnet();

	/*
	分包规则:
	一:对于lacp/lldp等仅使能物理接口的协议,需要设置为PACKET_BRIDGEMODE(即缺省值,可以不用显式set).
	   该类型帧的终结由uspEthEnd的收包函数显式终结(即判断如为两种类型调用收包函数,然后直接return
	   出收包函数不再进行后续的分包处理,因此这两种帧在下面的分包中可以不用显式考虑.)
	二:对于三层应用(即需要处理router模式的接口)仅当收包模式为PACKET_ROUTERMODE,端口模式为USP_IF_ROUTERMODE
		时才允许收包.inet和inet6在ptype的初始化需设置为PACKET_ROUTERMODE,类似isis的应用socket模式设置
		为PACKET_ROUTERMODE.
	三:对于二层应用分为几种类型:一如lacp类型的;二如stp类型的.这两种类型均要在物理口收包,socket模式
		均需要设置为PACKET_BRIDGEMODE,但两种协议在分包过程中的流程是不一样的.lacp类型的应用如规则一所述,
		stp类型的应用设置为PACKET_BRIDGEMODE会从两种接口收到包:一是物理口;二是聚合口.因此对stp此类型的应用
		设置的分包原则是第一次分包标记没有置位即为二层应用收包点.
	*/
	list_for_each_entry(pt, &ptype_all, node)
	{
		if(((NULL == pt->dev) &&
			  (((pt->rxMode == PACKET_ROUTERMODE) && (pHdrObj->workMode == USP_IF_ROUTERMODE)) ||
			  ((pt->rxMode == PACKET_BRIDGEMODE) && (!(m->m_flags & M_DELIVERED))))) ||
			(pt->dev == dev))
		{
			if(pt->copyData >0)
			{
				copym = netTupleGet (_pNetDpool, m->m_pkthdr.len, M_DONTWAIT, MT_DATA, TRUE);
				if(NULL == copym)
				{ 
					if(gPacketDebug&DEBUG_PACKET_ERR)
						printf("\n\r[packet]type all netTupleGet is NULL \n\r");
					break;
				}
				copym->m_pkthdr.len = m->m_pkthdr.len;
				M_COPY_PKTHDR(copym, m);
				copym->m_len = m->m_len;
				m_copydata(m, 0, m->m_pkthdr.len, mtod(copym, caddr_t));
			}
			else
			{
				copym=m_copy(m, 0, (int)M_COPYALL);
			}
			if(copym==NULL)
				break;

		#if (TORNADO_VERSION <= 220)
			copym->mBlkHdr.reserved = m->mBlkHdr.reserved;
		#endif
			pt->func(copym, dev, pt, llHdrInfo);
		}
	}
	
	list_for_each_entry(pt, &ptype_base[type & PTYPE_HASH_MASK], node)
	{
		if(pt->type != htons(type))
			continue;
		if(((NULL == pt->dev) &&
			  (((pt->rxMode == PACKET_ROUTERMODE) && (pt->rxMode == pHdrObj->workMode)) ||
			  ((pt->rxMode == PACKET_BRIDGEMODE) && (!(m->m_flags & M_DELIVERED))))) ||
			(pt->dev == dev))
		{
			if(pt->copyData >0)
			{
				copym = netTupleGet (_pNetDpool, m->m_pkthdr.len, M_DONTWAIT, MT_DATA, TRUE);
				if(NULL == copym)
				{
					if(gPacketDebug&DEBUG_PACKET_ERR)
						printf("\n\r[packet]type %d netTupleGet is NULL \n\r", type);
					break;
				}
				copym->m_pkthdr.len = m->m_pkthdr.len;
				M_COPY_PKTHDR(copym, m);
				copym->m_len = m->m_len;
				m_copydata(m, 0, m->m_pkthdr.len, mtod(copym, caddr_t));
			}
			else
			{
				copym=m_copy(m, 0, (int)M_COPYALL);
			}
			if(copym==NULL)
				break;
			
		#if (TORNADO_VERSION <= 220)
			copym->mBlkHdr.reserved = m->mBlkHdr.reserved;
		#endif
						
			pt->func(copym, dev, pt, llHdrInfo);
		#if 0
			rc = TRUE;
		#endif
		}
	}

	if(!(m->m_flags & M_DELIVERED))
	{
		m->m_flags |= M_DELIVERED;
	}
	splx(s);
	return rc;
#endif
}

static int packetRecvRtn
(
	void *cookie,
	long type,
	struct mbuf *pMblk,
	LL_HDR_INFO *llHdrInfo,
	void *pSpare
)
{
#if 0
	/*此处进行packet input处理操作*/
	struct packet_dev *dev=(struct packet_dev *)pSpare;
	if(gPacketDebug&DEBUG_PACKET_INPKT)
	{
		printf("\n\r packetRecvRtn: ifIndex %x, len %d, type %x\n\r", 
			dev->ifIndex,	pMblk->mBlkPktHdr.len, htons(llHdrInfo->pktType));
		uspPrintfPkt(pMblk, 0, pMblk->mBlkPktHdr.len);
	}
	
	return packetRcv(pMblk, dev, llHdrInfo);
#endif
}

static int packetTkRecvRtn
    (
    void * callbackId,      /* Sent down in muxTkBind call. */
    long         type,        /* Protocol type.  */
    struct mbuf *pMblk,       /* The whole packet. */
    void *       pSpareData   /* out of band data */
    )
{
	/*此处进行packet input处理操作*/
	struct packet_dev *dev=(struct packet_dev *)callbackId;
	
	if(gPacketDebug&DEBUG_PACKET_INPKT_TK)
	{
		printf("\n\r packetTkRecvRtn: dev ifIndex %x, len %d\n\r", dev->ifIndex, pMblk->m_len);
		//uspPrintfPkt(pMblk, 0, pMblk->m_len);
	}
	return packetRcv(pMblk, dev, pSpareData);
}
    
#if 0

/*处理热插拔*/
static STATUS packetShutdownRtn(void * netCallbackId,void *pSpare)
{
	struct packet_dev *dev = (struct packet_dev *)pSpare;
	
	if(dev == NULL)
		return ERROR;

	printf(LLDP_DEBUG_CFG,"PACKET shutdown port:%#x\r\n",dev->if_unit);
	

	if(lldpDelPort(lldp_port->if_unit) != OK)
	{	
		semGive(lldp_localdata.lldpMutex );
		return ERROR;
	}
	if (pp->pp_mclist)
		packet_dev_mclist(dev, pp->pp_mclist, -1);

	return OK;
}


static void lldpErrRtn(void * netCallbackId,END_ERR * pError,void *pSpare)
{

	struct packet_dev *dev = (struct packet_dev *)pSpare;
	if(dev==NULL)
		return ;
	
	printf("\r\n[LLDP]packet port(%#x) %02x\r\n",dev->ifIndex,pError->errCode);
	

	switch(pError->errCode)
	{
		case END_ERR_DOWN:
			if (dev->if_index == pp->pp_ifindex) {
				/*spin_lock(&po->bind_lock);*/
				if (pp->pp_running) {
					if_remove_pack(dev, &pp->pp_packet);
					pp->pp_running = 0;
					pp->pp_socket->so_error = ENETDOWN;
					sorwakeup(pp->pp_socket);
				}
				if (msg == NETDEV_UNREGISTER) {
					pp->pp_ifindex = -1;
					pp->pp_packet.ifp = NULL;
				}
				/*spin_unlock(&po->bind_lock);*/
			}
			break;
		case END_ERR_UP:
			/*spin_lock(&po->bind_lock);*/
			if (dev->if_index == pp->pp_ifindex && pp->pp_proto&&
			    !pp->pp_running) {
				if_add_pack(dev, &pp->pp_packet);
				pp->pp_running = 1;
			}
			/*spin_unlock(&po->bind_lock);*/
			break;
		default:
			semGive(lldp_localdata.lldpMutex );
			return ERROR;
			break;
	}

	return OK;
}

#endif

static struct list_head *ptype_head(const struct packet_type *pt)
{
	if (pt->type == htons(ETH_P_ALL))
		return &ptype_all;
	else
		return &ptype_base[ntohs(pt->type) & PTYPE_HASH_MASK];
}

int dev_add_pack(struct packet_type *pt)
{
	struct list_head *head = ptype_head(pt);
		
	list_add(&pt->node, head);
	return (OK);
}

int dev_remove_pack(struct packet_type *pt)
{
	struct list_head *head = ptype_head(pt);
	struct packet_type *pt1;

	list_for_each_entry(pt1, head, node) {
		if (pt == pt1) {
			list_del(&pt->node);
			goto out;
		}
	}
out:
	return (OK);
}

/*处理热插拔*/
STATUS packetShutdownRtn(void * netCallbackId,void *pSpare)
{
	struct packet_dev *dev = (struct packet_dev *)pSpare;
	
	if(dev == NULL)
		return ERROR;

    packet_notify(3, dev);

	if(packet_dev_del(dev) != OK)
	{
		printf("packet dev del error\r\n");
	}

	return OK;
}

/*处理热插拔*/
STATUS packetShutdownTkRtn(void * netCallbackId)
{
    struct packet_dev *dev = (struct packet_dev *)netCallbackId;
    
    if(dev == NULL)
        return ERROR;

    packet_notify(3, dev);

    if(packet_dev_del(dev) != OK)
    {
        printf("packet dev del error\r\n");
    }

    return OK;
}

struct packet_dev *packet_dev_add(uint32_t ifIndex)
{
	struct packet_dev *dev=NULL;
	int32_t flag=0;
	octetstring octet;

	dev = (struct packet_dev *)malloc(sizeof(struct packet_dev),M_DEVBUF, M_WAITOK|M_ZERO);
	if(dev == NULL)
		return NULL;
	
	dev->ifIndex = ifIndex;

	/*add avl tree*/
	avl_add(&gPacketDevInfo.devTbl, dev);
#if 0
	if(uspIfGetApi(ifIndex, SYS_IF_ISNPTEND, &flag) != OK)
	{
		DS_FREE(dev, 0/*MT_DATA*/);
		return NULL;
	}
		
	dev->nptFlag = flag?1:0;
	dev->ifIndex = ifIndex;

	flag = 0;
	uspIfGetApi(ifIndex, SYS_IF_OPER_STATUS, &flag);
	dev->up = (flag == 1)?1:0;


	octet.pBuf = dev->addr;
	octet.len = sizeof(dev->addr);
	if(uspIfGetApi(ifIndex, SYS_IF_PHYADDR, &octet) != OK)
	{
		DS_FREE(dev, 0/*MT_DATA*/);
		return NULL;
	}
	dev->addrlen = octet.len;

	if(!dev->nptFlag)
	{
		dev->cookie = uspMuxBind(dev->ifIndex, packetRecvRtn, packetShutdownRtn, NULL, NULL/*lldpErrRtn*/, MUX_PROTO_SNARF, "af_packet", (void *)dev);
	}
	else
	{
		dev->cookie = uspMuxTkBind(dev->ifIndex, packetTkRecvRtn, packetShutdownTkRtn, NULL, NULL/*lldpErrRtn*/, MUX_PROTO_SNARF, "af_packet", (void *)dev, NULL, NULL);
	}
	if(dev->cookie == NULL)
	{
		DS_FREE(dev, 0/*MT_DATA*/);
		return NULL;
	}

	/*add avl tree*/
	avl_add(&gPacketDevInfo.devTbl, dev);
#endif
	return dev;
}

int packet_dev_del(struct packet_dev *dev)
{
	
	avl_remove(&gPacketDevInfo.devTbl, dev);

	return OK;
}

struct packet_dev *packet_dev_get(uint32_t ifIndex)
{
	struct packet_dev *dev=NULL,entry;

	entry.ifIndex = ifIndex;

	dev = avl_find(&gPacketDevInfo.devTbl, &entry, NULL);

	return dev;
}


void packet_dev_hold(struct packet_dev *dev)
{
	dev->refcnt++;
}

void packet_dev_put(struct packet_dev *dev)
{
	dev->refcnt--;
	if(dev->refcnt == 0)
		packet_dev_del(dev);
}

int packet_dev_send(struct packet_dev *dev, struct mbuf *m, struct mbuf *control, uint16_t proto, uint8_t *dstAddr)
{
	tMuxNptPktParam pktParam={MUX_ENCAP_ETHERNET2,0,0,0,0};
	int32_t rc=OK;
	int32_t outerVid=0;
	uint8_t *srcAddr = dev->addr;
	struct packet_txpktinfo *pktinfo=NULL;

	bzero((char *)&pktParam, sizeof(pktParam));
#if 0
	if(control)
	{
		struct cmsghdr *cm = 0;
			
		for (; control->m_len; control->m_data += CMSG_ALIGN(cm->cmsg_len),
		     control->m_len -= CMSG_ALIGN(cm->cmsg_len)) {
		     
			cm = mtod(control, struct cmsghdr *);
			
			if (cm->cmsg_len == 0 || cm->cmsg_len > control->m_len)
			{
				netMblkClChainFree(m);
				return(EINVAL);
			}
			if (cm->cmsg_level != SOL_PACKET)
				continue;

			/*
			 * XXX should check if RFC2292 API is mixed with 2292bis API
			 */
			switch (cm->cmsg_type) {
			case PACKET_TX_PKTINFO:
				if (cm->cmsg_len < CMSG_LEN(sizeof(struct packet_txpktinfo)))
				{
					netMblkClChainFree(m);
					return(EINVAL);
				}
				pktinfo = (struct packet_txpktinfo *)CMSG_DATA(cm);

				if((pktinfo->pkt_op&PACKET_PORTINCLUDE) &&
					(pktinfo->pkt_op&PACKET_PORTEXCLUDE))
				{
					netMblkClChainFree(m);
					return(EINVAL);
				}
				if(pktinfo->pkt_op&PACKET_ENCAP)
				{
					pktParam.encapType = pktinfo->pkt_encaptype;
					pktParam.dsap = pktinfo->pkt_dsap;
					pktParam.ssap = pktinfo->pkt_ssap;
					pktParam.ctrl = pktinfo->pkt_ctrl;
				}
				if(pktinfo->pkt_op&PACKET_PORTINCLUDE)
				{
					pktParam.portNum = pktinfo->pkt_portnum;
					pktParam.ports = &pktinfo->pkt_ports[0];
					pktParam.type |= MUX_PORTINCLUDE;
				}
				if(pktinfo->pkt_op&PACKET_PORTEXCLUDE)
				{
					pktParam.portNum = pktinfo->pkt_portnum;
					pktParam.ports = &pktinfo->pkt_ports[0];
					pktParam.type |= MUX_PORTEXCLUDE;
				}
				if(pktinfo->pkt_op&PACKET_SRCMAC)
				{
					memcpy(pktParam.mac, pktinfo->pkt_srcmac, sizeof(pktParam.mac));
					srcAddr = pktParam.mac;
					pktParam.type |= MUX_SRCMAC;
				}
				if(pktinfo->pkt_op&PACKET_OUTERVLANTAG)
				{
					pktParam.outerVid = outerVid = pktinfo->pkt_outervid;
					pktParam.outerPri = pktinfo->pkt_outerpri;
					pktParam.type |= MUX_OUTERVLANTAG;
				}
				if(pktinfo->pkt_op&PACKET_INNERVLANTAG)
				{
					pktParam.innerVid = pktinfo->pkt_innervid;
					pktParam.innerPri = pktinfo->pkt_innerpri;
					pktParam.type |= MUX_INNERVLANTAG;
				}
				break;
			default:
				rc = ENOPROTOOPT;
				break;
			}
		}
	}
	
	if(!dev->nptFlag)
	{
		if((outerVid == 0) && (uspIfGetApi(dev->ifIndex, SYS_IF_DFLTVID, &outerVid) == OK) &&
			(outerVid>0))
		{
			pktParam.outerVid = outerVid;
			pktParam.outerPri = 7;
			pktParam.type |= MUX_OUTERVLANTAG;
		}

		/*其实可以组包后直接调用uspMuxSend函数发送，但组包太麻烦就放在hlSendRtn中做吧*/
		rc = ((STDHDR_OBJ *)PCOOKIE_TO_ENDOBJ(dev->cookie))->hlSendRtn(PCOOKIE_TO_ENDOBJ(dev->cookie), m, dstAddr, proto, &pktParam, srcAddr);
	}
	else
	{
		rc = uspMuxTkSend(dev->cookie, m, dstAddr, proto, &pktParam);
	}
		
	if(rc != OK)
		netMblkClChainFree(m);
#endif
	return rc;
}

int packet_dev_raw_send(struct packet_dev *dev, struct mbuf *m)
{
	int rc=OK;
#if 0
	if(dev->nptFlag)
	{
		rc = ENOTSUP;
	}
	else
	{
		rc = uspMuxSend(dev->cookie, m);
	}
	if(rc != OK)
		netMblkClChainFree(m);
#endif
	return rc;
}

static int packetDevCompare(const void *if1, const void *if2)
{
	const struct packet_dev *a = if1, *b = if2;

	if (a->ifIndex == b->ifIndex)
		return (0);

	if (a->ifIndex > b->ifIndex)
		return (1);

	else
		return (-1);
}

static int packet_notifier(struct notifier_block *this, uint32_t event, void *ptr)
{
	struct ifnet *ifp = netdev_notifier_info_to_dev(ptr);

	switch (event)
	{
	case NETDEV_UP:
		if(ifp)
		{
			printf("dev:%s up\n",ifp->if_xname);
			printf("dev index:%d\n",ifp->if_index);
		}
		break;
	}
	
#if 0
	STDHDR_OBJ*pHdrObj = (STDHDR_OBJ *)ptr;
	uint32_t unit = HDROBJ_UNIT(ptr);
	struct packet_dev *dev=NULL;
	octetstring *octet;

	packetPrintf(1,("packet_notifier: if(%s) msg = %s\r\n",pHdrObj->descr,notifier_msgstr(event)));
	/*read_lock(&net->packet.sklist_lock);*/


	switch (event)
	{
	case NETDEV_REGISTER:
		if(!gPacketDevInfo.autoLoadDev)
			break;
		if(HDROBJ_ENDTYPE(ptr) == USP_END_TUNNEL)
			break;
		if((dev = packet_dev_get(unit)) != NULL)
			break;
		if(packet_dev_add(unit) == NULL)
		{
			printf("packet dev %u add error\r\n",unit);
			break;
		}
		break;
	case NETDEV_UNREGISTER:
		if((dev = packet_dev_get(unit)) == NULL)
			break;

		packet_notify(3, dev);

		if(packet_dev_del(dev) != OK)
		{
			printf("packet dev del error\r\n");
			break;
		}
		break;
	case NETDEV_DOWN:
		if((dev = packet_dev_get(unit)) == NULL)
			break;
		dev->up = 0;
		
		packet_notify(2, dev);
		break;
	case NETDEV_UP:
		if((dev = packet_dev_get(unit)) == NULL)
			break;
		dev->up = 1;
		
		packet_notify(1, dev);
		break;
	case NETDEV_CHANGEADDR:

		if((dev = packet_dev_get(unit)) == NULL)
			break;
/*		if(DEVHDR_FLAGS_ISSET(pHdrObj, IF_IS_STACKAGG))
		{
			octetstring octetstr;
			char buf[16];

			octetstr.pBuf= buf;
			octetstr.len=sizeof(buf);
			uspScalarGetApi(NULL, SYS_HA_PHYADDR, &octetstr);
			dev->addrlen = sizeof(dev->addr);
			if(octet->len < sizeof(dev->addr))
				dev->addrlen = octetstr.len;
			memcpy(dev->addr, octetstr.pBuf, dev->addrlen);
		}
		else*/
			octet = (octetstring *)data;
			dev->addrlen = sizeof(dev->addr);
			if(octet->len < sizeof(dev->addr))
				dev->addrlen = octet->len;
			memcpy(dev->addr, octet->pBuf, dev->addrlen);
		break;
	case NETDEV_CHANGEOUTERTPID:
		if((dev = packet_dev_get(unit)) == NULL)
			break;

		dev->tpid = (uint32_t)data;
		break;
	}

	/*read_unlock(&net->packet.sklist_lock);*/
	return NOTIFY_DONE;
#endif
	return NOTIFY_DONE;
}


static struct notifier_block packet_netdev_notifier = {
	.notifier_call =	 packet_notifier,
};


int packetDevInit(int autoLoadPort)
{
	int32_t i;

	INIT_LIST_HEAD(&ptype_all);
	for (i = 0; i < PTYPE_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ptype_base[i]);
	
	avl_create(&gPacketDevInfo.devTbl,
		packetDevCompare,         /* entry comparison function  */
		sizeof(struct packet_dev),       /* entry size  */
		offsetof(struct packet_dev, node));	/* avl_node_t offset */

	gPacketDevInfo.autoLoadDev = autoLoadPort?1:0;
	register_netdevice_notifier(&packet_netdev_notifier);

	//wyq test
	packet_dev_add(2);
	return 0;
}





int32_t packetDevShow()
{
	struct packet_dev *dev;
	struct packet_type *pt;
	int32_t i;
	

	printf("tree format output\r\n");
	dev = (struct packet_dev *)avl_first (&gPacketDevInfo.devTbl);
	while(dev != NULL)
	{
		printf("unit:%#lx, up:%s\r\n", dev->ifIndex, dev->up?"True":"False");
		
		printf("mac: %02x:%02x:%02x:%02x:%02x:%02x \r\n", 
		dev->addr[0],dev->addr[1],dev->addr[2],dev->addr[3],dev->addr[4],dev->addr[5]);

		dev = (struct packet_dev *)avl_next(&gPacketDevInfo.devTbl, dev);
	}

	list_for_each_entry(pt, &ptype_all, node)
	{
		printf("pt->dev=%#x,pt->type=%#x,pt->func=%#x\r\n",pt->dev,pt->type,pt->func);
	}
	for(i=0;i<PTYPE_HASH_SIZE;i++)
	{
		list_for_each_entry(pt, &ptype_base[i & PTYPE_HASH_MASK], node)
		{
			printf("pt->dev=%#x,pt->type=%#x,pt->func=%#x\r\n",pt->dev,pt->type,pt->func);
		}
	}



	return 0;
}



