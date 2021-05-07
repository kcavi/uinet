# 
# Copyright (c) 2013 Patrick Kelsey. All rights reserved.
# Copyright (C) 2017 THL A29 Limited, a Tencent company.
# All rights reserved.
#
# Derived in part from libuinet's Makefile.
#
# Derived from FreeBSD auto-generated kernel Makefile and
# machine-specific Makefile templates
#

TOPDIR?=${CURDIR}/..
S=${TOPDIR}/freebsd
OVERRIDE_INCLUDES_ROOT:=${CURDIR}/include

HOST_OS:=$(shell uname -s)


DEBUG=-g

C_DIALECT= -std=c99 
CFLAGS=	 ${C_DIALECT} ${DEBUG} -DFSTACK
KERNEL_CFLAGS=  -D_KERNEL  -include opt_global.h -fno-builtin

INCLUDES+= -I${OVERRIDE_INCLUDES_ROOT} -I. -I$S
INCLUDES+= -I./machine_include
INCLUDES+= -I./opt
INCLUDES+= -I${TOPDIR}/osal/h
INCLUDES+= -I${TOPDIR}/uspif/inc
NORMAL_C= ${CC} -c ${CFLAGS} ${KERNEL_CFLAGS} ${INCLUDES} $< -o $@


# Include search path for files that only include host OS headers
HOST_INCLUDES= -I.
HOST_CFLAGS = ${DEBUG} 
HOST_C= ${CC} -c $(HOST_CFLAGS) ${HOST_INCLUDES}  $<





VPATH+= $S/kern
VPATH+= $S/crypto
VPATH+= $S/crypto/siphash
VPATH+= $S/net
VPATH+= $S/netinet
VPATH+= $S/netinet6
VPATH+= $S/packet/src
VPATH+= $S/netinet/libalias
VPATH+= $S/netinet/cc
VPATH+= $S/netipsec
VPATH+= $S/opencrypto
VPATH+= $S/vm
VPATH+= $S/libkern
VPATH+= ${TOPDIR}/uspif/src

FF_SRCS+=                     \
	ff_compat.c           \
	ff_glue.c             \
	ff_freebsd_init.c     \
	ff_init_main.c        \
	ff_kern_condvar.c     \
	ff_kern_environment.c \
	ff_kern_intr.c        \
	ff_kern_subr.c        \
	ff_kern_synch.c       \
	ff_kern_timeout.c     \
	ff_lock.c             \
	ff_syscall_wrapper.c  \
	ff_subr_prf.c         \
	ff_vfs_ops.c          \
	ff_veth.c             \
	ff_route.c            \
	ff_kern_rwlock.c      \
	avl.c                 \
	notifier.c
	
#ff_kern_sx.c          

FF_HOST_SRCS+=              \
	ff_host_interface.c \
	ff_config.c         \
	ff_ini_parser.c     \
	ff_dpdk_if.c        \
	ff_epoll.c          \
	ff_init.c          \
	packet_process.c



CRYPTO_SRCS+=               \
	sha1.c              \
	siphash.c

KERN_SRCS+=                 \
	kern_descrip.c      \
	kern_event.c        \
	kern_fail.c         \
	kern_khelp.c        \
	kern_hhook.c        \
	kern_linker.c       \
	kern_mbuf.c         \
	kern_module.c       \
	kern_mtxpool.c      \
	kern_ntptime.c      \
	kern_osd.c          \
	kern_sysctl.c       \
	kern_tc.c           \
	kern_uuid.c         \
	link_elf.c          \
	md5c.c              \
	subr_capability.c   \
	subr_counter.c      \
	subr_eventhandler.c \
	subr_kobj.c         \
	subr_lock.c         \
	subr_module.c       \
	subr_param.c        \
	subr_pcpu.c         \
	subr_sbuf.c         \
	subr_taskqueue.c    \
	subr_unit.c         \
	sys_capability.c    \
	sys_generic.c       \
	sys_socket.c        \
	uipc_accf.c         \
	uipc_mbuf.c         \
	uipc_mbuf2.c        \
	uipc_domain.c       \
	uipc_sockbuf.c      \
	uipc_socket.c       \
	uipc_syscalls.c     \
	uipc_usrreq.c       \
	vfs_syscalls.c      \
	tty_pts.c           \
	tty.c               \
	tty_ttydisc.c       \
	tty_outq.c          \
	tty_inq.c           \
	pty.c               \
	kern_conf.c         \
	devfs_devs.c        \
	devfs_dir.c         \
	devfs_vnops.c       \
	subr_uio.c

#devfs_vfsops.c      	
#devfs_vnops.c

#tty_info.c
#vfs_lookup.c


KERN_MHEADERS+=		\
	bus_if.m	\
	device_if.m	\
	linker_if.m


KERN_MSRCS+=		\
	linker_if.m


LIBKERN_SRCS+=		 \
	bcd.c		 \
	crc32.c          \
	inet_ntoa.c	 \
	jenkins_hash.c   \
	strlcpy.c	 \
	strnlen.c        \
	zlib.c


MACHINE_SRCS+=		 \
	in_cksum.c


NET_SRCS+=		 \
	bpf.c		 \
	bridgestp.c      \
	if.c		 \
	if_bridge.c      \
	if_clone.c	 \
	if_dead.c	 \
	if_ethersubr.c	 \
	if_loop.c	 \
	if_llatbl.c	 \
	if_media.c       \
	if_spppfr.c      \
	if_spppsubr.c    \
	if_vlan.c        \
	if_vxlan.c       \
	in_fib.c	 \
	in_gif.c         \
	ip_reass.c	 \
	netisr.c	 \
	pfil.c		 \
	radix.c		 \
	raw_cb.c	 \
	raw_usrreq.c	 \
	route.c		 \
	rtsock.c         \
	slcompress.c    \
	af_netlink.c   \
	netlink_cb.c

NETINET_SRCS+=		\
	if_ether.c	\
	if_gif.c        \
	igmp.c		\
	in.c		\
	in_mcast.c	\
	in_pcb.c	\
	in_proto.c	\
	in_rmx.c	\
	ip_carp.c	\
	ip_divert.c     \
	ip_ecn.c        \
	ip_encap.c	\
	ip_fastfwd.c	\
	ip_icmp.c	\
	ip_id.c		\
	ip_input.c	\
	ip_mroute.c     \
	ip_options.c	\
	ip_output.c	\
	raw_ip.c	\
	tcp_debug.c	\
	tcp_fastopen.c	\
	tcp_hostcache.c	\
	tcp_input.c	\
	tcp_lro.c	\
	tcp_offload.c	\
	tcp_output.c	\
	tcp_reass.c	\
	tcp_sack.c	\
	tcp_subr.c	\
	tcp_syncache.c	\
	tcp_timer.c	\
	tcp_timewait.c	\
	tcp_usrreq.c	\
	udp_usrreq.c	\
	cc.c		\
	cc_newreno.c    \
	cc_htcp.c       \
	cc_cubic.c      \
	alias.c         \
	alias_db.c      \
	alias_mod.c     \
	alias_proxy.c   \
	alias_sctp.c    \
	alias_util.c



# only if TCP_SIGNTAURE is defined
#xform_tcp.c

NETINET6_SRCS+=		\
	dest6.c  \
	in6.c        \
	in6_pcb.c       \
	in6_rmx.c  \
	ip6_forward.c  \
	ip6_input.c   \
	ip6_output.c  \
	route6.c        \
	send.c  \
	frag6.c  \
	in6_cksum.c  \
	in6_ifattach.c  \
	in6_pcbgroup.c  \
	mld6.c        \
	nd6_rtr.c  \
	scope6.c        \
	udp6_usrreq.c  \
	icmp6.c  \
	in6_fib.c    \
	in6_mcast.c     \
	in6_proto.c     \
	in6_src.c  \
	ip6_id.c       \
	ip6_mroute.c  \
	nd6.c         \
	raw_ip6.c  \
	nd6_nbr.c  \
	in6_gif.c       

#in6_rss.c  
#	ip6_gre.c      
#	ip6_ipsec.c   
#	sctp6_usrreq.c 



PACKET_SRCS+=		\
	af_packet.c \
	packet_cb.c   \
	packet_dev.c 
#packet_tst.c  
	

VM_SRCS+=		\
	uma_core.c


MHEADERS= bus_if.h device_if.h linker_if.h vnode_if.h vnode_if_newproto.h vnode_if_typedef.h cryptodev_if.h
MSRCS= linker_if.c cryptodev_if.c

SRCS=  ${FF_SRCS} ${CRYPTO_SRCS} ${KERN_SRCS} ${LIBKERN_SRCS} ${MACHINE_SRCS}
SRCS+= ${MSRCS} ${NET_SRCS} ${NETGRAPH_SRCS} ${NETINET_SRCS} ${NETINET6_SRCS} ${PACKET_SRCS}
SRCS+= ${NETIPSEC_SRCS} ${NETIPFW_SRCS} ${OPENCRYPTO_SRCS} ${VM_SRCS}



# If witness is enabled.
# SRCS+= ${KERN_WITNESS_SRCS}


HOST_SRCS = ${FF_HOST_SRCS}


OBJS+= $(patsubst %.c,%.o,${SRCS})
HOST_OBJS+= $(patsubst %.c,%.o,${HOST_SRCS})

all: libfstack.a


#
# The library is built by first incrementally linking all the object
# to resolve internal references.  Then, all symbols are made local.
# Then, only the symbols that are part of the  API are made
# externally available.
#

libfstack.a:  ${HOST_OBJS}  ${OBJS}
	ar -cqs $@ ${OBJS} ${HOST_OBJS}



${HOST_OBJS}: %.o: %.c
	${HOST_C}


${OBJS}: %.o: %.c
	${NORMAL_C}


.PHONY: clean
clean:
	rm -f libfstack.a
	rm -f  ${HOST_OBJS} ${OBJS} ${PROGRAM} 

