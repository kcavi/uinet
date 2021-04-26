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

#ifndef _USP_SYS_SOCKET_H_
#define	_USP_SYS_SOCKET_H_
#include "usp_select.h"
#include "usp_poll.h"


#define USP_SOL_IP		0
/* #define SOL_ICMP	1	No-no-no! Due to Linux :-) we cannot use SOL_ICMP=1 */
#define USP_SOL_TCP		6
#define USP_SOL_UDP		17
#define USP_SOL_IPV6	41
#define USP_SOL_ICMPV6	58
#define USP_SOL_SCTP	132
#define USP_SOL_UDPLITE	136     /* UDP-Lite (RFC 3828) */
#define USP_SOL_RAW		255
#define USP_SOL_IPX		256
#define USP_SOL_AX25	257
#define USP_SOL_ATALK	258
#define USP_SOL_NETROM	259
#define USP_SOL_ROSE	260
#define USP_SOL_DECNET	261
#define	USP_SOL_X25		262
#define USP_SOL_PACKET	263
#define USP_SOL_ATM		264	/* ATM layer (cell level) */
#define USP_SOL_AAL		265	/* ATM Adaption Layer (packet level) */
#define USP_SOL_IRDA        266
#define USP_SOL_NETBEUI	267
#define USP_SOL_LLC		268
#define USP_SOL_DCCP	269
#define USP_SOL_NETLINK	270
#define USP_SOL_TIPC	271
#define USP_SOL_RXRPC	272
#define USP_SOL_PPPOL2TP	273
#define USP_SOL_BLUETOOTH	274
#define USP_SOL_PNPIPE	275
#define USP_SOL_RDS		276
#define USP_SOL_IUCV	277
#define USP_SOL_CAIF	278
#define USP_SOL_ALG		279
#define USP_SOL_NFC		280


/*
 * Types
 */
#define	USP_SOCK_STREAM	1		/* stream socket */
#define	USP_SOCK_DGRAM	2		/* datagram socket */
#define	USP_SOCK_RAW	3		/* raw-protocol interface */
#define	USP_SOCK_RDM	4		/* reliably-delivered message */
#define	USP_SOCK_SEQPACKET	5		/* sequenced packet stream */
#define USP_SOCK_PACKET	6

/*
 * Creation flags, OR'ed into socket() and socketpair() type argument.
 */
#define	USP_SOCK_CLOEXEC	0x10000000
#define	USP_SOCK_NONBLOCK	0x20000000


/*
 * Option flags per-socket.
 */
#define	USP_SO_DEBUG	0x0001		/* turn on debugging info recording */
#define	USP_SO_ACCEPTCONN	0x0002		/* socket has had listen() */
#define	USP_SO_REUSEADDR	0x0004		/* allow local address reuse */
#define	USP_SO_KEEPALIVE	0x0008		/* keep connections alive */
#define	USP_SO_DONTROUTE	0x0010		/* just use interface addresses */
#define	USP_SO_BROADCAST	0x0020		/* permit sending of broadcast msgs */

#define	USP_SO_USELOOPBACK	0x0040		/* bypass hardware when possible */

#define	USP_SO_LINGER	0x0080		/* linger on close if data present */
#define	USP_SO_OOBINLINE	0x0100		/* leave received OOB data in line */

#define	USP_SO_REUSEPORT	0x0200		/* allow local address & port reuse */
#define	USP_SO_TIMESTAMP	0x0400		/* timestamp received dgram traffic */
#define	USP_SO_NOSIGPIPE	0x0800		/* no SIGPIPE from EPIPE */
#define	USP_SO_ACCEPTFILTER	0x1000		/* there is an accept filter */
#define	USP_SO_BINTIME	0x2000		/* timestamp received dgram traffic */

#define	USP_SO_NO_OFFLOAD	0x4000		/* socket cannot be offloaded */
#define	USP_SO_NO_DDP	0x8000		/* disable direct data placement */

/*
 * Additional options, not kept in so_options.
 */
#define	USP_SO_SNDBUF	0x1001		/* send buffer size */
#define	USP_SO_RCVBUF	0x1002		/* receive buffer size */
#define	USP_SO_SNDLOWAT	0x1003		/* send low-water mark */
#define	USP_SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define	USP_SO_SNDTIMEO	0x1005		/* send timeout */
#define	USP_SO_RCVTIMEO	0x1006		/* receive timeout */
#define	USP_SO_ERROR	0x1007		/* get error status and clear */
#define	USP_SO_TYPE		0x1008		/* get socket type */

#define	USP_SO_LABEL	0x1009		/* socket's MAC label */
#define	USP_SO_PEERLABEL	0x1010		/* socket's peer's MAC label */
#define	USP_SO_LISTENQLIMIT	0x1011		/* socket's backlog limit */
#define	USP_SO_LISTENQLEN	0x1012		/* socket's complete queue length */
#define	USP_SO_LISTENINCQLEN	0x1013	/* socket's incomplete queue length */
#define	USP_SO_SETFIB	0x1014		/* use this FIB to route */
#define	USP_SO_USER_COOKIE	0x1015		/* user cookie (dummynet etc.) */
#define	USP_SO_PROTOCOL	0x1016		/* get socket protocol (Linux name) */
#define	USP_SO_PROTOTYPE	SO_PROTOCOL	/* alias for SO_PROTOCOL (SunOS name) */


/*
 * Space reserved for new socket options added by third-party vendors.
 * This range applies to all socket option levels.  New socket options
 * in FreeBSD should always use an option value less than SO_VENDOR.
 */

#define	USP_SO_VENDOR	0x80000000




/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	USP_SOL_SOCKET	0xffff		/* options for socket level */

/*
 * Address families.
 */
#define	USP_AF_UNSPEC	0		/* unspecified */
#define	USP_AF_LOCAL	USP_AF_UNIX		/* local to host (pipes, portals) */
#define	USP_AF_UNIX		1		/* standardized name for AF_LOCAL */
#define	USP_AF_INET		2		/* internetwork: UDP, TCP, etc. */
#define	USP_AF_IMPLINK	3		/* arpanet imp addresses */
#define	USP_AF_PUP		4		/* pup protocols: e.g. BSP */
#define	USP_AF_CHAOS	5		/* mit CHAOS protocols */
#define	USP_AF_NETBIOS	6		/* SMB protocols */
#define	USP_AF_ISO		7		/* ISO protocols */
#define	USP_AF_OSI		USP_AF_ISO
#define	USP_AF_ECMA		8		/* European computer manufacturers */
#define	USP_AF_DATAKIT	9		/* datakit protocols */
#define	USP_AF_INET6	10		/* IPv6 */
#define	USP_AF_SNA		11		/* IBM SNA */
#define USP_AF_DECnet	12		/* DECnet */
#define USP_AF_DLI		13		/* DEC Direct data link interface */
#define USP_AF_LAT		14		/* LAT */
#define	USP_AF_HYLINK	15		/* NSC Hyperchannel */
#define	USP_AF_NETLINK	16		/* Internal Routing Protocol */
#define USP_AF_PACKET	17	    /* Packet family		*/
#define	USP_AF_LINK		18		/* Link layer interface */
#define	USP_AF_ROUTE	19		/* eXpress Transfer Protocol (no AF) */
#define	USP_AF_COIP		20		/* connection-oriented IP, aka ST II */
#define	USP_AF_CNT		21		/* Computer Network Technology */
#define USP_pseudo_AF_RTIP	22		/* Help Identify RTIP packets */
#define	USP_AF_IPX		23		/* Novell Internet Protocol */
#define	USP_AF_SIP		24		/* Simple Internet Protocol */
#define	USP_pseudo_AF_PIP	25		/* Help Identify PIP packets */
#define	USP_AF_ISDN		26		/* Integrated Services Digital Network*/
#define	USP_AF_E164		AF_ISDN		/* CCITT E.164 recommendation */
#define	USP_pseudo_AF_KEY	27		/* Internal key-management function */

#define	USP_AF_CCITT	28		/* CCITT protocols, X.25 etc */

#define	USP_AF_NATM		29		/* native ATM access */
#define	USP_AF_ATM		30		/* ATM */
#define USP_pseudo_AF_HDRCMPLT 31		/* Used by BPF to not rewrite headers
					 * in interface output routine
					 */
#define	USP_AF_NETGRAPH	32		/* Netgraph sockets */
#define	USP_AF_SLOW		33		/* 802.3ad slow protocol */
#define	USP_AF_SCLUSTER	34		/* Sitara cluster protocol */
#define	USP_AF_ARP		35
#define	USP_AF_BLUETOOTH	36		/* Bluetooth sockets */
#define	USP_AF_IEEE80211	37		/* IEEE 802.11 protocol */
#define	USP_AF_INET_SDP	40		/* OFED Socket Direct Protocol ipv4 */
#define	USP_AF_INET6_SDP	42		/* OFED Socket Direct Protocol ipv6 */
#define	USP_AF_APPLETALK	43		/* Apple Talk */
#define	USP_AF_MAX		43


/*
 * Structure used by kernel to store most
 * addresses.
 */
struct usp_sockaddr {
	unsigned char	sa_len;		/* total length */
	uint8_t	sa_family;	/* address family */
	char		sa_data[14];	/* actually longer; address value */
};

#define	USP_SOCK_MAXADDRLEN	255		/* longest possible addresses */

/*
 * Structure used by kernel to pass protocol
 * information in raw sockets.
 */
struct usp_sockproto {
	unsigned short	sp_family;		/* address family */
	unsigned short	sp_protocol;		/* protocol */
};


/* Socket address, internet style. */
struct usp_sockaddr_in {
	uint8_t	sin_len;
	uint8_t	sin_family;
	in_port_t	sin_port;
	struct	in_addr sin_addr;
	char	sin_zero[8];
};



struct usp_sockaddr_nl {
	uint8_t		nl_len;
	uint8_t		nl_family;	/* AF_NETLINK	*/
	unsigned short	nl_pad;		/* zero		*/
	uint32_t		nl_pid;		/* port ID	*/
	uint32_t		nl_groups;	/* multicast groups mask */
};


struct usp_sockaddr_in6 {
	uint8_t		sin6_len;	/* length of this struct */
	uint8_t	sin6_family;	/* AF_INET6 */
	in_port_t	sin6_port;	/* Transport layer port # */
	uint32_t	sin6_flowinfo;	/* IP6 flow information */
	struct in6_addr	sin6_addr;	/* IP6 address */
	uint32_t	sin6_scope_id;	/* scope zone index */
};




struct usp_sockaddr_ll {
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
struct usp_sockaddr_un {
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
#define USP_NET_RT_DUMP	1		/* dump; may limit to a.f. */
#define USP_NET_RT_FLAGS	2		/* by flags, e.g. RESOLVING */
#define USP_NET_RT_IFLIST	3		/* survey interface list */
#define	USP_NET_RT_IFMALIST	4		/* return multicast address list */
#define	USP_NET_RT_IFLISTL	5		/* Survey interface list, using 'l'en
					 * versions of msghdr structs. */


/*
 * Maximum queue length specifiable by listen.
 */
#define	USP_SOMAXCONN	128

/*
 * Message header for recvmsg and sendmsg calls.
 * Used value-result for recvmsg, value only for sendmsg.
 */
struct usp_msghdr {
	void		*msg_name;		/* optional address */
	socklen_t	 msg_namelen;		/* size of address */
	struct iovec	*msg_iov;		/* scatter/gather array */
	int		 msg_iovlen;		/* # elements in msg_iov */
	void		*msg_control;		/* ancillary data, see below */
	socklen_t	 msg_controllen;	/* ancillary data buffer len */
	int		 msg_flags;		/* flags on received message */
};

#define	USP_MSG_OOB		0x1		/* process out-of-band data */
#define	USP_MSG_PEEK	0x2		/* peek at incoming message */
#define	USP_MSG_DONTROUTE	0x4		/* send without using routing tables */
#define	USP_MSG_EOR		0x8		/* data completes record */
#define	USP_MSG_TRUNC	0x10		/* data discarded before delivery */
#define	USP_MSG_CTRUNC	0x20		/* control data lost before delivery */
#define	USP_MSG_WAITALL	0x40		/* wait for full request or error */

#define	USP_MSG_NOSIGNAL	0x20000		/* do not generate SIGPIPE on EOF */


#define	USP_MSG_DONTWAIT	0x80		/* this message should be nonblocking */
#define	USP_MSG_EOF		0x100		/* data completes connection */
#define	USP_MSG_NOTIFICATION 0x2000         /* SCTP notification */
#define	USP_MSG_NBIO	0x4000		/* FIONBIO mode, used by fifofs */
#define	USP_MSG_COMPAT      0x8000		/* used in sendit() */
#define	USP_MSG_CMSG_CLOEXEC 0x40000	/* make received fds close-on-exec */
#define	USP_MSG_WAITFORONE	0x80000		/* for recvmmsg() */

#define	USP_MSG_SOCALLBCK   0x10000		/* for use by socket callbacks - soreceive (TCP) */


/*
 * Header for ancillary data objects in msg_control buffer.
 * Used for additional information with/about a datagram
 * not expressible by flags.  The format is a sequence
 * of message elements headed by cmsghdr structures.
 */
struct usp_cmsghdr {
	socklen_t	cmsg_len;		/* data byte count, including hdr */
	int		cmsg_level;		/* originating protocol */
	int		cmsg_type;		/* protocol-specific type */
/* followed by	u_char  cmsg_data[]; */
};



/* given pointer to struct cmsghdr, return pointer to data */
#define	USP_CMSG_DATA(cmsg)		((unsigned char *)(cmsg) + \
				 _ALIGN(sizeof(struct usp_cmsghdr)))

/* given pointer to struct cmsghdr, return pointer to next cmsghdr */
#define	USP_CMSG_NXTHDR(mhdr, cmsg)	\
	((char *)(cmsg) == (char *)0 ? USP_CMSG_FIRSTHDR(mhdr) : \
	    ((char *)(cmsg) + _ALIGN(((struct usp_cmsghdr *)(cmsg))->cmsg_len) + \
	  _ALIGN(sizeof(struct usp_cmsghdr)) > \
	    (char *)(mhdr)->msg_control + (mhdr)->msg_controllen) ? \
	    (struct usp_cmsghdr *)0 : \
	    (struct usp_cmsghdr *)(void *)((char *)(cmsg) + \
	    _ALIGN(((struct usp_cmsghdr *)(cmsg))->cmsg_len)))

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#define	USP_CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= sizeof(struct usp_cmsghdr) ? \
	 (struct usp_cmsghdr *)(mhdr)->msg_control : \
	 (struct usp_cmsghdr *)0)


#define	USP_CMSG_SPACE(l)		(_ALIGN(sizeof(struct usp_cmsghdr)) + _ALIGN(l))
#define	USP_CMSG_LEN(l)		(_ALIGN(sizeof(struct usp_cmsghdr)) + (l))



#define	USP_CMSG_ALIGN(n)	_ALIGN(n)



struct usp_ifaddrmsg {
	uint8_t		ifa_family;
	uint8_t		ifa_prefixlen;	/* The prefix length		*/
	uint8_t		ifa_flags;	/* Flags			*/
	uint8_t		ifa_scope;	/* Address scope		*/
	uint32_t		ifa_index;	/* Link index			*/
};


struct usp_ifa_cacheinfo {
	uint32_t	ifa_prefered;
	uint32_t	ifa_valid;
	uint32_t	cstamp; /* created timestamp, hundredths of seconds */
	uint32_t	tstamp; /* updated timestamp, hundredths of seconds */
};



int usp_fcntl(int fd, int cmd, ...);

int usp_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);

int usp_ioctl(int fd, unsigned long request, ...);

int usp_socket(int domain, int type, int protocol);

int usp_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen);

int usp_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen);

int usp_listen(int s, int backlog);
int usp_bind(int s, const struct usp_sockaddr *addr, socklen_t addrlen);
int usp_accept(int s, struct usp_sockaddr *addr, socklen_t *addrlen);
int usp_connect(int s, const struct usp_sockaddr *name, socklen_t namelen);
int usp_close(int fd);
int usp_shutdown(int s, int how);

int usp_getpeername(int s, struct usp_sockaddr *name,
    socklen_t *namelen);
int usp_getsockname(int s, struct usp_sockaddr *name,
    socklen_t *namelen);
int usp_open(const char *pathname, int flags, mode_t mode);
ssize_t usp_read(int d, void *buf, size_t nbytes);
ssize_t usp_readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t usp_write(int fd, const void *buf, size_t nbytes);
ssize_t usp_writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t usp_send(int s, const void *buf, size_t len, int flags);
ssize_t usp_sendto(int s, const void *buf, size_t len, int flags,
    const struct usp_sockaddr *to, socklen_t tolen);
ssize_t usp_sendmsg(int s, const struct msghdr *msg, int flags);

ssize_t usp_recv(int s, void *buf, size_t len, int flags);
ssize_t usp_recvfrom(int s, void *buf, size_t len, int flags,
    struct usp_sockaddr *from, socklen_t *fromlen);
ssize_t usp_recvmsg(int s, struct msghdr *msg, int flags);

int usp_openpty(int *amaster, int *aslave, char *name);

int usp_select(int nfds, usp_fd_set *readfds, usp_fd_set *writefds, usp_fd_set *exceptfds,
    struct timeval *timeout);

int usp_poll(struct usp_pollfd fds[], usp_nfds_t nfds, int timeout);


/* internal api begin */

/* FreeBSD style calls. Used for tools. */
int usp_ioctl_freebsd(int fd, unsigned long request, ...);
int usp_setsockopt_freebsd(int s, int level, int optname,
    const void *optval, socklen_t optlen);
int usp_getsockopt_freebsd(int s, int level, int optname,
    void *optval, socklen_t *optlen);


#endif /* !_SYS_SOCKET_H_ */
