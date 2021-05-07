/*
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
 */
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>


#include "ff_dpdk_if.h"
#include "ff_config.h"
#include "ff_veth.h"
#include "ff_host_interface.h"
#include "ff_msg.h"
#include "ff_api.h"

#include "errno.h"

#define MEMPOOL_CACHE_SIZE 256

#define DISPATCH_RING_SIZE 2048

#define MSG_RING_SIZE 32

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_QUEUE_SIZE 512
#define TX_QUEUE_SIZE 512

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define MAX_TX_BURST    (MAX_PKT_BURST / 2)

#define NB_SOCKETS 8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET    3

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128


enum FilterReturn {
    FILTER_UNKNOWN = -1,
    FILTER_ARP = 1,
    FILTER_KNI = 2,
};



#define ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */
#define ETHER_TYPE_LEN  2 /**< Length of Ethernet type field. */
#define ETHER_CRC_LEN   4 /**< Length of Ethernet CRC. */
#define ETHER_HDR_LEN   \
	(ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN) /**< Length of Ethernet header. */
#define ETHER_MIN_LEN   64    /**< Minimum frame len, including CRC. */
#define ETHER_MAX_LEN   1518  /**< Maximum frame len, including CRC. */
#define ETHER_MTU       \
	(ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN) /**< Ethernet MTU. */

#define ETHER_MAX_VLAN_FRAME_LEN \
	(ETHER_MAX_LEN + 4) /**< Maximum VLAN frame length, including CRC. */

#define ETHER_MAX_JUMBO_FRAME_LEN \
	0x3F00 /**< Maximum Jumbo frame length, including CRC. */

#define ETHER_MAX_VLAN_ID  4095 /**< Maximum VLAN ID. */

#define ETHER_MIN_MTU 68 /**< Minimum MTU for IPv4 packets, see RFC 791. */


struct ether_addr {
	uint8_t addr_bytes[ETHER_ADDR_LEN]; /**< Addr bytes in tx order */
} __attribute__((__packed__));


/**
 * Ethernet header: Contains the destination address, source address
 * and frame type.
 */
struct ether_hdr {
	struct ether_addr d_addr; /**< Destination address. */
	struct ether_addr s_addr; /**< Source address. */
	uint16_t ether_type;      /**< Frame type. */
} __attribute__((__packed__));



/* Ethernet frame types */
#define ETHER_TYPE_IPv4 0x0800 /**< IPv4 Protocol. */
#define ETHER_TYPE_IPv6 0x86DD /**< IPv6 Protocol. */
#define ETHER_TYPE_ARP  0x0806 /**< Arp Protocol. */
#define ETHER_TYPE_RARP 0x8035 /**< Reverse Arp Protocol. */
#define ETHER_TYPE_VLAN 0x8100 /**< IEEE 802.1Q VLAN tagging. */
#define ETHER_TYPE_QINQ 0x88A8 /**< IEEE 802.1ad QinQ tagging. */
#define ETHER_TYPE_1588 0x88F7 /**< IEEE 802.1AS 1588 Precise Time Protocol. */
#define ETHER_TYPE_SLOW 0x8809 /**< Slow protocols (LACP and Marker). */
#define ETHER_TYPE_TEB  0x6558 /**< Transparent Ethernet Bridging. */
#define ETHER_TYPE_LLDP 0x88CC /**< LLDP Protocol. */


static dispatch_func_t packet_dispatcher;

struct ff_dpdk_if_context {
    void *sc;
    void *ifp;
    uint16_t port_id;
    struct ff_hw_features hw_features;
} /*__rte_cache_aligned*/;

static struct ff_dpdk_if_context *veth_ctx[32];

static struct ff_top_args ff_top_status;
static struct ff_traffic_args ff_traffic;

extern void ff_hardclock(void);


/************************************clock process***************************/

#define UHI_CLOCK_REALTIME		0
#define UHI_CLOCK_MONOTONIC		4
#define UHI_CLOCK_MONOTONIC_FAST       12

#define UHI_NSEC_PER_SEC	(1000ULL * 1000ULL * 1000ULL)

#define UHI_TS_TO_NSEC(ts) (uint64_t)((uint64_t)((ts).tv_sec) * UHI_NSEC_PER_SEC + (ts).tv_nsec)
#define UHI_MAKE_TS(ts,sec,nsec) (ts).tv_sec = sec; (ts).tv_nsec = nsec



#define	timespecclear(tvp)	((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#define	timespecisset(tvp)	((tvp)->tv_sec || (tvp)->tv_nsec)
#define	timespeccmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#define timespecadd(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec += (uvp)->tv_sec;				\
		(vvp)->tv_nsec += (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec >= 1000000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_nsec -= 1000000000;			\
		}							\
	} while (0)
#define timespecsub(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec -= (uvp)->tv_sec;				\
		(vvp)->tv_nsec -= (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_nsec += 1000000000;			\
		}							\
	} while (0)
			
	


#define HZ 100


extern int     sched_get_priority_max(int);
extern int     sched_get_priority_min(int);


static void
clock_task(void *arg)
{
	struct timespec base_tick_period, tick_period;
	struct timespec start, target_period, delta;
	int64_t sec;
	long nsec;
	int hardclocks;
	const int calibration_period = 5;
	int i;

	/* XXX arbitrary prioritization: If able to schedule as a real-time
	 * thread, set to ~80% max real-time priority, otherwise set to max
	 * time-sharing priority.
	 */

	if (0 != uhi_thread_setprio_rt(80)) {
		printf("Warning: Timer interrupt thread will not run at real-time priority.\n");
		if (0 != uhi_thread_setprio(80))
			printf("Warning: Timer interrupt thread priority could not be adjusted.\n");
	}

	ff_th_init("clock_task");

	nsec = 1000000000UL / HZ;
	
	delta.tv_sec = 0;
	delta.tv_nsec = 0;

	base_tick_period.tv_sec = 0;
	base_tick_period.tv_nsec = nsec;

	target_period.tv_sec = 0;
	target_period.tv_nsec = 0;
	for (i = 0; i < calibration_period; i++) {
		timespecadd(&target_period, &base_tick_period);
	}

	hardclocks = 0;
	tick_period = base_tick_period;

	uhi_clock_gettime(UHI_CLOCK_MONOTONIC, &sec, &nsec);
	start.tv_sec = sec;
	start.tv_nsec = nsec;
	while (1) {
		uhi_nanosleep(UHI_TS_TO_NSEC(tick_period));

		ff_hardclock();

		hardclocks++;
		if (hardclocks == calibration_period) {
			struct timespec now, elapsed, correction;

			hardclocks = 0;

			uhi_clock_gettime(CLOCK_MONOTONIC, &sec, &nsec);
			now.tv_sec = sec;
			now.tv_nsec = nsec;

			elapsed = now;
			timespecsub(&elapsed, &start);
			start = now;

			/* 
			 * This will accumulate the residuals over a series
			 * of too-long periods.
			 */
			timespecadd(&elapsed, &delta);

			if (timespeccmp(&elapsed, &target_period, >=)) {
				/* 
				 * Period was too long.  Revise sleep time
				 * downward and issue any missed ticks.
				 */

				delta = elapsed;
				timespecsub(&delta, &target_period);
				
				correction = delta;
				correction.tv_nsec /= calibration_period * 2;

				if (timespeccmp(&tick_period, &correction, >=)) {
						timespecsub(&tick_period, &correction);
				}

				while (timespeccmp(&delta, &base_tick_period, >=)) {
					timespecsub(&delta, &base_tick_period);
					ff_hardclock();
				}
			} else {
				/*
				 * Period was too short.  Revise sleep time
				 * upward and sleep now for the remainder of
				 * the period.
				 */

				delta = target_period;
				timespecsub(&delta, &elapsed);

				/*
				 * Don't include this catch-up sleep in the
				 * measurement of the next period.
				 */
				timespecadd(&start, &delta);

				correction = delta;
				correction.tv_nsec /= calibration_period * 2;
				timespecadd(&tick_period, &correction);

				uhi_nanosleep(UHI_TS_TO_NSEC(delta));

				delta.tv_sec = 0;
				delta.tv_nsec = 0;
			}

		}
	}
}


struct ff_dpdk_if_context *
ff_dpdk_register_if(void *sc, void *ifp, struct ff_port_cfg *cfg)
{
    struct ff_dpdk_if_context *ctx;

    ctx = calloc(1, sizeof(struct ff_dpdk_if_context));
    if (ctx == NULL)
        return NULL;

    ctx->sc = sc;
    ctx->ifp = ifp;
    ctx->port_id = cfg->port_id;
    ctx->hw_features = cfg->hw_features;

    return ctx;
}

void
ff_dpdk_deregister_if(struct ff_dpdk_if_context *ctx)
{
    free(ctx);
}


int ff_veth_input(const char *pkt, int len, int port)
{
    uint8_t rx_csum = 0; 
    void *data = (void *)pkt;

    void *hdr = ff_mbuf_gethdr((void *)pkt, len, data, len, rx_csum);
    if (hdr == NULL) {
        //rte_pktmbuf_free(pkt);
        return -1;
    }

    ff_veth_process_packet(veth_ctx[0]->ifp, hdr);

}

static enum FilterReturn
protocol_filter(const void *data, uint16_t len)
{
    if(len < 14)
        return FILTER_UNKNOWN;

    const struct ether_hdr *hdr;
    hdr = (const struct ether_hdr *)data;

    if(ntohs(hdr->ether_type) == ETHER_TYPE_ARP)
        return FILTER_ARP;

#ifndef FF_KNI
    return FILTER_UNKNOWN;
#else
    if (!enable_kni) {
        return FILTER_UNKNOWN;
    }

    if(ntohs(hdr->ether_type) != ETHER_TYPE_IPv4)
        return FILTER_UNKNOWN;

    return ff_kni_proto_filter(data + ETHER_HDR_LEN,
        len - ETHER_HDR_LEN);
#endif
}



static inline void
handle_sysctl_msg(struct ff_msg *msg)
{	
    int ret = usp_sysctl(msg->sysctl.name, msg->sysctl.namelen,
        msg->sysctl.old, msg->sysctl.oldlenp, msg->sysctl.new,
        msg->sysctl.newlen);

    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }
}

static inline void
handle_ioctl_msg(struct ff_msg *msg)
{
    int fd, ret;
    fd = usp_socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ret = -1;
        goto done;
    }

    ret = usp_ioctl_freebsd(fd, msg->ioctl.cmd, msg->ioctl.data);

    usp_close(fd);

done:
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }
}

static inline void
handle_route_msg(struct ff_msg *msg)
{
    int ret = ff_rtioctl(msg->route.fib, msg->route.data,
        &msg->route.len, msg->route.maxlen);
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }
}

static inline void
handle_top_msg(struct ff_msg *msg)
{
    msg->top = ff_top_status;
    msg->result = 0;
}

#ifdef FF_NETGRAPH
static inline void
handle_ngctl_msg(struct ff_msg *msg)
{
    int ret = ff_ngctl(msg->ngctl.cmd, msg->ngctl.data);
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
        msg->ngctl.ret = ret;
    }
}
#endif

#ifdef FF_IPFW
static inline void
handle_ipfw_msg(struct ff_msg *msg)
{
    int fd, ret;
    fd = usp_socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        ret = -1;
        goto done;
    }

    switch (msg->ipfw.cmd) {
        case FF_IPFW_GET:
            ret = usp_getsockopt_freebsd(fd, msg->ipfw.level,
                msg->ipfw.optname, msg->ipfw.optval,
                msg->ipfw.optlen);
            break;
        case FF_IPFW_SET:
            ret = usp_setsockopt_freebsd(fd, msg->ipfw.level,
                msg->ipfw.optname, msg->ipfw.optval,
                *(msg->ipfw.optlen)); 
            break;
        default:
            ret = -1;
            errno = ENOTSUP;
            break;
    }

    ff_close(fd);

done:
    if (ret < 0) {
        msg->result = errno;
    } else {
        msg->result = 0;
    }
}
#endif

static inline void
handle_traffic_msg(struct ff_msg *msg)
{
    msg->traffic = ff_traffic;
    msg->result = 0;
}

static inline void
handle_default_msg(struct ff_msg *msg)
{
    msg->result = ENOTSUP;
}

void handle_msg(struct ff_msg *msg, uint16_t proc_id)
{
    switch (msg->msg_type) {
        case FF_SYSCTL:
            handle_sysctl_msg(msg);
            break;
        case FF_IOCTL:
            handle_ioctl_msg(msg);
            break;
        case FF_ROUTE:
            handle_route_msg(msg);
            break;
        case FF_TOP:
            handle_top_msg(msg);
            break;
#ifdef FF_NETGRAPH
        case FF_NGCTL:
            handle_ngctl_msg(msg);
            break;
#endif
#ifdef FF_IPFW
        case FF_IPFW_CTL:
            handle_ipfw_msg(msg);
            break;
#endif
        case FF_TRAFFIC:
            handle_traffic_msg(msg);
            break;
        default:
            handle_default_msg(msg);
            break;
    }

}



#define	RTE_MBUF_DEFAULT_DATAROOM	2048
int packet_sys_send(char *pkt, int len ,int port);

int ff_dpdk_if_send(struct ff_dpdk_if_context *ctx, void *m, int total)
{
    char buf[65536] = {0};
    int off = 0;
    char *data = buf;
	int sendlen = total;

    while(total > 0) {
        int len = total > RTE_MBUF_DEFAULT_DATAROOM ? RTE_MBUF_DEFAULT_DATAROOM : total;
        int ret = ff_mbuf_copydata(m, data, off, len);
        if (ret < 0) {
            ff_mbuf_free(m);
            return -1;
        }
        data += len;
        off += len;
        total -= len;
    }

    ff_mbuf_free(m);

    return packet_sys_send(buf, sendlen ,0);


}

extern void msg_loop(void);
extern void nlmsg_notify_task(void *arg);


int ff_dpdk_if_up(void) 
{
    pthread_t pid;
	  
    veth_ctx[0] = ff_veth_attach(&ff_global_cfg.port_cfgs[0]);

    pthread_create(&pid,NULL,(void *)msg_loop ,NULL);
	pthread_create(&pid,NULL,(void *)clock_task ,NULL);

	pthread_create(&pid,NULL,(void *)nlmsg_notify_task ,NULL);

    return 0;
}



void
ff_dpdk_pktmbuf_free(void *m)
{
	free(m);
}

static uint32_t
toeplitz_hash(unsigned keylen, const uint8_t *key,
    unsigned datalen, const uint8_t *data)
{
    uint32_t hash = 0, v;
    u_int i, b;

    /* XXXRW: Perhaps an assertion about key length vs. data length? */

    v = (key[0]<<24) + (key[1]<<16) + (key[2] <<8) + key[3];
    for (i = 0; i < datalen; i++) {
        for (b = 0; b < 8; b++) {
            if (data[i] & (1<<(7-b)))
                hash ^= v;
            v <<= 1;
            if ((i + 4) < keylen &&
                (key[i+4] & (1<<(7-b))))
                v |= 1;
        }
    }
    return (hash);
}

int
ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport)
{
	return 0;
}

void
ff_regist_packet_dispatcher(dispatch_func_t func)
{
    packet_dispatcher = func;
}


