/*-
 * Copyright (c) 1982, 1985, 1986, 1988, 1993, 1994
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
 *	@(#)socket.h	8.4 (Berkeley) 2/21/94
 * $FreeBSD$
 */

#ifndef _RSP_SYS_SOCKET_H_
#define	_RSP_SYS_SOCKET_H_
#include "rsp_select.h"
#include "rsp_poll.h"


#define RSP_SOL_IP		0
/* #define SOL_ICMP	1	No-no-no! Due to Linux :-) we cannot use SOL_ICMP=1 */
#define RSP_SOL_TCP		6
#define RSP_SOL_UDP		17
#define RSP_SOL_IPV6	41
#define RSP_SOL_ICMPV6	58
#define RSP_SOL_SCTP	132
#define RSP_SOL_UDPLITE	136     /* UDP-Lite (RFC 3828) */
#define RSP_SOL_RAW		255
#define RSP_SOL_IPX		256
#define RSP_SOL_AX25	257
#define RSP_SOL_ATALK	258
#define RSP_SOL_NETROM	259
#define RSP_SOL_ROSE	260
#define RSP_SOL_DECNET	261
#define	RSP_SOL_X25		262
#define RSP_SOL_PACKET	263
#define RSP_SOL_ATM		264	/* ATM layer (cell level) */
#define RSP_SOL_AAL		265	/* ATM Adaption Layer (packet level) */
#define RSP_SOL_IRDA        266
#define RSP_SOL_NETBEUI	267
#define RSP_SOL_LLC		268
#define RSP_SOL_DCCP	269
#define RSP_SOL_NETLINK	270
#define RSP_SOL_TIPC	271
#define RSP_SOL_RXRPC	272
#define RSP_SOL_PPPOL2TP	273
#define RSP_SOL_BLUETOOTH	274
#define RSP_SOL_PNPIPE	275
#define RSP_SOL_RDS		276
#define RSP_SOL_IUCV	277
#define RSP_SOL_CAIF	278
#define RSP_SOL_ALG		279
#define RSP_SOL_NFC		280


/*
 * Types
 */
#define	RSP_SOCK_STREAM	1		/* stream socket */
#define	RSP_SOCK_DGRAM	2		/* datagram socket */
#define	RSP_SOCK_RAW	3		/* raw-protocol interface */
#define	RSP_SOCK_RDM	4		/* reliably-delivered message */
#define	RSP_SOCK_SEQPACKET	5		/* sequenced packet stream */
#define RSP_SOCK_PACKET	6

/*
 * Creation flags, OR'ed into socket() and socketpair() type argument.
 */
#define	RSP_SOCK_CLOEXEC	0x10000000
#define	RSP_SOCK_NONBLOCK	0x20000000


/*
 * Option flags per-socket.
 */
#define	RSP_SO_DEBUG	0x0001		/* turn on debugging info recording */
#define	RSP_SO_ACCEPTCONN	0x0002		/* socket has had listen() */
#define	RSP_SO_REUSEADDR	0x0004		/* allow local address reuse */
#define	RSP_SO_KEEPALIVE	0x0008		/* keep connections alive */
#define	RSP_SO_DONTROUTE	0x0010		/* just use interface addresses */
#define	RSP_SO_BROADCAST	0x0020		/* permit sending of broadcast msgs */

#define	RSP_SO_USELOOPBACK	0x0040		/* bypass hardware when possible */

#define	RSP_SO_LINGER	0x0080		/* linger on close if data present */
#define	RSP_SO_OOBINLINE	0x0100		/* leave received OOB data in line */

#define	RSP_SO_REUSEPORT	0x0200		/* allow local address & port reuse */
#define	RSP_SO_TIMESTAMP	0x0400		/* timestamp received dgram traffic */
#define	RSP_SO_NOSIGPIPE	0x0800		/* no SIGPIPE from EPIPE */
#define	RSP_SO_ACCEPTFILTER	0x1000		/* there is an accept filter */
#define	RSP_SO_BINTIME	0x2000		/* timestamp received dgram traffic */

#define	RSP_SO_NO_OFFLOAD	0x4000		/* socket cannot be offloaded */
#define	RSP_SO_NO_DDP	0x8000		/* disable direct data placement */

/*
 * Additional options, not kept in so_options.
 */
#define	RSP_SO_SNDBUF	0x1001		/* send buffer size */
#define	RSP_SO_RCVBUF	0x1002		/* receive buffer size */
#define	RSP_SO_SNDLOWAT	0x1003		/* send low-water mark */
#define	RSP_SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define	RSP_SO_SNDTIMEO	0x1005		/* send timeout */
#define	RSP_SO_RCVTIMEO	0x1006		/* receive timeout */
#define	RSP_SO_ERROR	0x1007		/* get error status and clear */
#define	RSP_SO_TYPE		0x1008		/* get socket type */

#define	RSP_SO_LABEL	0x1009		/* socket's MAC label */
#define	RSP_SO_PEERLABEL	0x1010		/* socket's peer's MAC label */
#define	RSP_SO_LISTENQLIMIT	0x1011		/* socket's backlog limit */
#define	RSP_SO_LISTENQLEN	0x1012		/* socket's complete queue length */
#define	RSP_SO_LISTENINCQLEN	0x1013	/* socket's incomplete queue length */
#define	RSP_SO_SETFIB	0x1014		/* use this FIB to route */
#define	RSP_SO_USER_COOKIE	0x1015		/* user cookie (dummynet etc.) */
#define	RSP_SO_PROTOCOL	0x1016		/* get socket protocol (Linux name) */
#define	RSP_SO_PROTOTYPE	SO_PROTOCOL	/* alias for SO_PROTOCOL (SunOS name) */


/*
 * Space reserved for new socket options added by third-party vendors.
 * This range applies to all socket option levels.  New socket options
 * in FreeBSD should always use an option value less than SO_VENDOR.
 */

#define	RSP_SO_VENDOR	0x80000000




/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	RSP_SOL_SOCKET	0xffff		/* options for socket level */

/*
 * Address families.
 */
#define	RSP_AF_UNSPEC	0		/* unspecified */
#define	RSP_AF_LOCAL	RSP_AF_UNIX		/* local to host (pipes, portals) */
#define	RSP_AF_UNIX		1		/* standardized name for AF_LOCAL */
#define	RSP_AF_INET		2		/* internetwork: UDP, TCP, etc. */
#define	RSP_AF_IMPLINK	3		/* arpanet imp addresses */
#define	RSP_AF_PUP		4		/* pup protocols: e.g. BSP */
#define	RSP_AF_CHAOS	5		/* mit CHAOS protocols */
#define	RSP_AF_NETBIOS	6		/* SMB protocols */
#define	RSP_AF_ISO		7		/* ISO protocols */
#define	RSP_AF_OSI		RSP_AF_ISO
#define	RSP_AF_ECMA		8		/* European computer manufacturers */
#define	RSP_AF_DATAKIT	9		/* datakit protocols */
#define	RSP_AF_INET6	10		/* IPv6 */
#define	RSP_AF_SNA		11		/* IBM SNA */
#define RSP_AF_DECnet	12		/* DECnet */
#define RSP_AF_DLI		13		/* DEC Direct data link interface */
#define RSP_AF_LAT		14		/* LAT */
#define	RSP_AF_HYLINK	15		/* NSC Hyperchannel */
#define	RSP_AF_NETLINK	16		/* Internal Routing Protocol */
#define RSP_AF_PACKET	17	    /* Packet family		*/
#define	RSP_AF_LINK		18		/* Link layer interface */
#define	RSP_AF_ROUTE	19		/* eXpress Transfer Protocol (no AF) */
#define	RSP_AF_COIP		20		/* connection-oriented IP, aka ST II */
#define	RSP_AF_CNT		21		/* Computer Network Technology */
#define RSP_pseudo_AF_RTIP	22		/* Help Identify RTIP packets */
#define	RSP_AF_IPX		23		/* Novell Internet Protocol */
#define	RSP_AF_SIP		24		/* Simple Internet Protocol */
#define	RSP_pseudo_AF_PIP	25		/* Help Identify PIP packets */
#define	RSP_AF_ISDN		26		/* Integrated Services Digital Network*/
#define	RSP_AF_E164		AF_ISDN		/* CCITT E.164 recommendation */
#define	RSP_pseudo_AF_KEY	27		/* Internal key-management function */

#define	RSP_AF_CCITT	28		/* CCITT protocols, X.25 etc */

#define	RSP_AF_NATM		29		/* native ATM access */
#define	RSP_AF_ATM		30		/* ATM */
#define RSP_pseudo_AF_HDRCMPLT 31		/* Used by BPF to not rewrite headers
					 * in interface output routine
					 */
#define	RSP_AF_NETGRAPH	32		/* Netgraph sockets */
#define	RSP_AF_SLOW		33		/* 802.3ad slow protocol */
#define	RSP_AF_SCLUSTER	34		/* Sitara cluster protocol */
#define	RSP_AF_ARP		35
#define	RSP_AF_BLUETOOTH	36		/* Bluetooth sockets */
#define	RSP_AF_IEEE80211	37		/* IEEE 802.11 protocol */
#define	RSP_AF_INET_SDP	40		/* OFED Socket Direct Protocol ipv4 */
#define	RSP_AF_INET6_SDP	42		/* OFED Socket Direct Protocol ipv6 */
#define	RSP_AF_APPLETALK	43		/* Apple Talk */
#define	RSP_AF_MAX		43


/*
 * Structure used by kernel to store most
 * addresses.
 */
struct rsp_sockaddr {
	unsigned char	sa_len;		/* total length */
	uint8_t	sa_family;	/* address family */
	char		sa_data[14];	/* actually longer; address value */
};

#define	RSP_SOCK_MAXADDRLEN	255		/* longest possible addresses */

/*
 * Structure used by kernel to pass protocol
 * information in raw sockets.
 */
struct rsp_sockproto {
	unsigned short	sp_family;		/* address family */
	unsigned short	sp_protocol;		/* protocol */
};


/* Socket address, internet style. */
struct rsp_sockaddr_in {
	uint8_t	sin_len;
	uint8_t	sin_family;
	in_port_t	sin_port;
	struct	in_addr sin_addr;
	char	sin_zero[8];
};



struct rsp_sockaddr_nl {
	uint8_t		nl_len;
	uint8_t		nl_family;	/* AF_NETLINK	*/
	unsigned short	nl_pad;		/* zero		*/
	uint32_t		nl_pid;		/* port ID	*/
	uint32_t		nl_groups;	/* multicast groups mask */
};


struct rsp_sockaddr_in6 {
	uint8_t		sin6_len;	/* length of this struct */
	uint8_t	sin6_family;	/* AF_INET6 */
	in_port_t	sin6_port;	/* Transport layer port # */
	uint32_t	sin6_flowinfo;	/* IP6 flow information */
	struct in6_addr	sin6_addr;	/* IP6 address */
	uint32_t	sin6_scope_id;	/* scope zone index */
};




struct rsp_sockaddr_ll {
	uint8_t		sll_len;
	uint8_t		sll_family;
	uint16_t	sll_protocol;
	uint32_t	sll_ifindex;
	uint16_t	sll_hatype;
	uint8_t		sll_pkttype;
	uint8_t		sll_halen;
	uint8_t		sll_addr[8];	/*dest mac addr*/
};


/*
 * Definitions for UNIX IPC domain.
 */
struct rsp_sockaddr_un {
	unsigned char	sun_len;	/* sockaddr len including null */
	uint8_t	sun_family;	/* AF_UNIX */
	char	sun_path[104];		/* path name (gag) */
};


/*
 * Definitions for network related sysctl, CTL_NET.
 *
 * Second level is protocol family.
 * Third level is protocol number.
 *
 * Further levels are defined by the individual families.
 */

/*
 * PF_ROUTE - Routing table
 *
 * Three additional levels are defined:
 *	Fourth: address family, 0 is wildcard
 *	Fifth: type of info, defined below
 *	Sixth: flag(s) to mask with for NET_RT_FLAGS
 */
#define RSP_NET_RT_DUMP	1		/* dump; may limit to a.f. */
#define RSP_NET_RT_FLAGS	2		/* by flags, e.g. RESOLVING */
#define RSP_NET_RT_IFLIST	3		/* survey interface list */
#define	RSP_NET_RT_IFMALIST	4		/* return multicast address list */
#define	RSP_NET_RT_IFLISTL	5		/* Survey interface list, using 'l'en
					 * versions of msghdr structs. */


/*
 * Maximum queue length specifiable by listen.
 */
#define	RSP_SOMAXCONN	128

/*
 * Message header for recvmsg and sendmsg calls.
 * Used value-result for recvmsg, value only for sendmsg.
 */
struct rsp_msghdr {
	void		*msg_name;		/* optional address */
	socklen_t	 msg_namelen;		/* size of address */
	struct iovec	*msg_iov;		/* scatter/gather array */
	int		 msg_iovlen;		/* # elements in msg_iov */
	void		*msg_control;		/* ancillary data, see below */
	socklen_t	 msg_controllen;	/* ancillary data buffer len */
	int		 msg_flags;		/* flags on received message */
};

#define	RSP_MSG_OOB		0x1		/* process out-of-band data */
#define	RSP_MSG_PEEK	0x2		/* peek at incoming message */
#define	RSP_MSG_DONTROUTE	0x4		/* send without using routing tables */
#define	RSP_MSG_EOR		0x8		/* data completes record */
#define	RSP_MSG_TRUNC	0x10		/* data discarded before delivery */
#define	RSP_MSG_CTRUNC	0x20		/* control data lost before delivery */
#define	RSP_MSG_WAITALL	0x40		/* wait for full request or error */

#define	RSP_MSG_NOSIGNAL	0x20000		/* do not generate SIGPIPE on EOF */


#define	RSP_MSG_DONTWAIT	0x80		/* this message should be nonblocking */
#define	RSP_MSG_EOF		0x100		/* data completes connection */
#define	RSP_MSG_NOTIFICATION 0x2000         /* SCTP notification */
#define	RSP_MSG_NBIO	0x4000		/* FIONBIO mode, used by fifofs */
#define	RSP_MSG_COMPAT      0x8000		/* used in sendit() */
#define	RSP_MSG_CMSG_CLOEXEC 0x40000	/* make received fds close-on-exec */
#define	RSP_MSG_WAITFORONE	0x80000		/* for recvmmsg() */

#define	RSP_MSG_SOCALLBCK   0x10000		/* for use by socket callbacks - soreceive (TCP) */


/*
 * Header for ancillary data objects in msg_control buffer.
 * Used for additional information with/about a datagram
 * not expressible by flags.  The format is a sequence
 * of message elements headed by cmsghdr structures.
 */
struct rsp_cmsghdr {
	socklen_t	cmsg_len;		/* data byte count, including hdr */
	int		cmsg_level;		/* originating protocol */
	int		cmsg_type;		/* protocol-specific type */
/* followed by	u_char  cmsg_data[]; */
};



/* given pointer to struct cmsghdr, return pointer to data */
#define	RSP_CMSG_DATA(cmsg)		((unsigned char *)(cmsg) + \
				 _ALIGN(sizeof(struct rsp_cmsghdr)))

/* given pointer to struct cmsghdr, return pointer to next cmsghdr */
#define	RSP_CMSG_NXTHDR(mhdr, cmsg)	\
	((char *)(cmsg) == (char *)0 ? RSP_CMSG_FIRSTHDR(mhdr) : \
	    ((char *)(cmsg) + _ALIGN(((struct rsp_cmsghdr *)(cmsg))->cmsg_len) + \
	  _ALIGN(sizeof(struct rsp_cmsghdr)) > \
	    (char *)(mhdr)->msg_control + (mhdr)->msg_controllen) ? \
	    (struct rsp_cmsghdr *)0 : \
	    (struct rsp_cmsghdr *)(void *)((char *)(cmsg) + \
	    _ALIGN(((struct rsp_cmsghdr *)(cmsg))->cmsg_len)))

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#define	RSP_CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= sizeof(struct rsp_cmsghdr) ? \
	 (struct rsp_cmsghdr *)(mhdr)->msg_control : \
	 (struct rsp_cmsghdr *)0)


#define	RSP_CMSG_SPACE(l)		(_ALIGN(sizeof(struct rsp_cmsghdr)) + _ALIGN(l))
#define	RSP_CMSG_LEN(l)		(_ALIGN(sizeof(struct rsp_cmsghdr)) + (l))



#define	RSP_CMSG_ALIGN(n)	_ALIGN(n)



struct rsp_ifaddrmsg {
	uint8_t		ifa_family;
	uint8_t		ifa_prefixlen;	/* The prefix length		*/
	uint8_t		ifa_flags;	/* Flags			*/
	uint8_t		ifa_scope;	/* Address scope		*/
	uint32_t		ifa_index;	/* Link index			*/
};


struct rsp_ifa_cacheinfo {
	uint32_t	ifa_prefered;
	uint32_t	ifa_valid;
	uint32_t	cstamp; /* created timestamp, hundredths of seconds */
	uint32_t	tstamp; /* updated timestamp, hundredths of seconds */
};



int rsp_fcntl(int fd, int cmd, ...);

int rsp_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);

int rsp_ioctl(int fd, unsigned long request, ...);

int rsp_socket(int domain, int type, int protocol);

int rsp_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen);

int rsp_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen);

int rsp_listen(int s, int backlog);
int rsp_bind(int s, const struct rsp_sockaddr *addr, socklen_t addrlen);
int rsp_accept(int s, struct rsp_sockaddr *addr, socklen_t *addrlen);
int rsp_connect(int s, const struct rsp_sockaddr *name, socklen_t namelen);
int rsp_close(int fd);
int rsp_shutdown(int s, int how);

int rsp_getpeername(int s, struct rsp_sockaddr *name,
    socklen_t *namelen);
int rsp_getsockname(int s, struct rsp_sockaddr *name,
    socklen_t *namelen);
int rsp_open(const char *pathname, int flags, mode_t mode);
ssize_t rsp_read(int d, void *buf, size_t nbytes);
ssize_t rsp_readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t rsp_write(int fd, const void *buf, size_t nbytes);
ssize_t rsp_writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t rsp_send(int s, const void *buf, size_t len, int flags);
ssize_t rsp_sendto(int s, const void *buf, size_t len, int flags,
    const struct rsp_sockaddr *to, socklen_t tolen);
ssize_t rsp_sendmsg(int s, const struct msghdr *msg, int flags);

ssize_t rsp_recv(int s, void *buf, size_t len, int flags);
ssize_t rsp_recvfrom(int s, void *buf, size_t len, int flags,
    struct rsp_sockaddr *from, socklen_t *fromlen);
ssize_t rsp_recvmsg(int s, struct msghdr *msg, int flags);

int rsp_openpty(int *amaster, int *aslave, char *name);

int rsp_select(int nfds, rsp_fd_set *readfds, rsp_fd_set *writefds, rsp_fd_set *exceptfds,
    struct timeval *timeout);

int rsp_poll(struct rsp_pollfd fds[], rsp_nfds_t nfds, int timeout);


/* internal api begin */

/* FreeBSD style calls. Used for tools. */
int rsp_ioctl_freebsd(int fd, unsigned long request, ...);
int rsp_setsockopt_freebsd(int s, int level, int optname,
    const void *optval, socklen_t optlen);
int rsp_getsockopt_freebsd(int s, int level, int optname,
    void *optval, socklen_t *optlen);


#endif /* !_SYS_SOCKET_H_ */
