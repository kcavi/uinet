#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <linux/un.h>
#include "ff_msg.h"



#include "ff_config.h"
#define FSTACK_SOCKET_PATH		"/tmp/fstak.socket"
int packet_debug = 0;

int ff_veth_input(const char *pkt, int len, int port);
void handle_msg(struct ff_msg *msg, uint16_t proc_id);
void ff_thread_set_name(const char *name);

long vm_max_kernel_address;



int set_port_mac(char *machex,const char *macstr)
{
	sscanf(macstr,"%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned int *)&machex[0],
		(unsigned int *)&machex[1],
		(unsigned int *)&machex[2],
		(unsigned int *)&machex[3],
		(unsigned int *)&machex[4],
		(unsigned int *)&machex[5]);
	
}


/*
 * Find Last Set bit
 */
int
fls(int mask)
{
	int bit;

	if (mask == 0)
		return (0);
	for (bit = 1; mask != 1; bit++)
		mask = (unsigned int)mask >> 1;
	return (bit);
}


/*
 * Find Last Set bit
 */
int
flsl(long mask)
{
	int bit;

	if (mask == 0)
		return (0);
	for (bit = 1; mask != 1; bit++)
		mask = (unsigned long)mask >> 1;
	return (bit);
}


void
kick_proc0(void)
{

	//wakeup(&proc0);
	printf("%s %d\n",__func__,__LINE__);
}


/* split string into tokens */
int
rte_strsplit(char *string, int stringlen,
	     char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
		goto einval_error;

	for (i = 0; i < stringlen; i++) {
		if (string[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &string[i];
		}
		if (string[i] == delim) {
			string[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;

einval_error:
	errno = EINVAL;
	return -1;
}




/*******************************************************************************/
int packet_fd=0;
int get_ifindex(char *interface)
{
	int fd;
	char ifr_buf[sizeof(struct ifreq)];
	struct ifreq *const ifr = (void *)ifr_buf;

	if(!interface)
		return 0;
	memset(ifr, 0, sizeof(*ifr));
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	ifr->ifr_addr.sa_family = AF_INET;
	strcpy(ifr->ifr_name, interface);
	
	if (ioctl(fd, SIOCGIFINDEX, ifr) != 0) {
		close(fd);
		return -1;
	}
	close(fd);
	return ifr->ifr_ifindex;

}

#define FSTACK_SHM_KEY 0x11223388

void msg_loop(void) 
{
	int sock=-1, n;
	unsigned char buffer[10240];
	int i;
	int cmdSocket;
	int packet_len=1518;
	int if_index=0;
	char *device=ff_global_cfg.dpdk.packet_bind_dev;
	
	unsigned int  protocol=0;
	int count_flags=0;
	int timeval;
	int packet_num = 0;
	struct sockaddr_ll sock_addr;
	struct sockaddr_un cmdAddr;
	fd_set rfd;
	int maxFd = 0;
	struct timeval waittime;
	socklen_t addrlen;
	int ret;
	struct ff_msg * msg ,*msg_tmp;
	int ch;
	char *tmp;
	int shm_id;
	char *recv_buf;

	ff_thread_set_name("msg_loop");

	tmp = malloc(10240);
		
	if ( (packet_fd=socket(PF_PACKET,SOCK_RAW,protocol != 0?htons(protocol):htons(ETH_P_ALL)))<0) {
		perror("create socket failed");
		return;
	}

	cmdSocket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(0 >= cmdSocket)
	{
		perror("create cmdSock failed!");
		return;		
	}

	unlink(FSTACK_SOCKET_PATH);
	bzero((char *)(&cmdAddr), sizeof(cmdAddr));
	cmdAddr.sun_family = AF_UNIX;
	strcpy(cmdAddr.sun_path, FSTACK_SOCKET_PATH);
	if(0 != bind(cmdSocket, (struct sockaddr *)(&cmdAddr), sizeof(cmdAddr))) 
	{
		perror("bind failed!");
		return;
	}
	
#if 0
	if(0 != listen(cmdSocket, 10))
	{
		perror("listen failed!");
		return;
	}
#endif
	if( (if_index = get_ifindex(device)) < 0)
	{
		printf("invalid interface\n");
		return;
	}
	
	memset(&sock_addr,0,sizeof(sock_addr));
	sock_addr.sll_family = AF_PACKET;
	sock_addr.sll_protocol = (protocol != 0?htons(protocol):htons(ETH_P_ALL));
	sock_addr.sll_ifindex = if_index;
	sock_addr.sll_halen = 6;
	if (bind(packet_fd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_ll)) < 0) {
		perror("bind call failed\n");
		return;
	}


	shm_id = shmget(FSTACK_SHM_KEY,20480,IPC_CREAT|0600);
	if(shm_id == -1)
	{
		perror("shmget error");
		return;
	}
	
	char *share_addr = NULL /* (char *)0x7ffff1000000*/;
	msg_tmp = (struct ff_msg *)shmat(shm_id,share_addr,0);
	if( (void *) -1 == msg_tmp)
	{
		perror("shmat error");
		return;
	}


	while(1)
	{
		FD_ZERO(&rfd);
		FD_SET(packet_fd,&rfd);
		maxFd = packet_fd;
		FD_SET(cmdSocket, &rfd);
		if(maxFd < cmdSocket)
			maxFd = cmdSocket;

		waittime.tv_sec= 1;
		waittime.tv_usec = 0;
		
		
		ret = select(maxFd+1,&rfd,NULL,NULL,&waittime);
		if(ret <= 0)
			continue;
		
		if(FD_ISSET(packet_fd,&rfd))
		{
			n = recv(packet_fd,buffer, sizeof(buffer), 0);
			
			
			packet_num++;
		
			if(packet_debug == 1)
			{
				printf("packet %3d:\n",packet_num);
				for(i=0;i<(n>packet_len?packet_len:n);i++)
					printf("%02x ",buffer[i]);
				printf("\n");
			}

			
			recv_buf = malloc(2000);
			memset(recv_buf,0,2000);
			
			memcpy(recv_buf,buffer,n>2000?2000:n);
			ff_veth_input(recv_buf,n,0);
			
		}

		if(FD_ISSET(cmdSocket, &rfd))
		{
			addrlen = sizeof(cmdAddr);
			memset(buffer,0,sizeof(buffer));
			memset(&cmdAddr,0,sizeof(cmdAddr));
			n = recvfrom(cmdSocket,buffer, sizeof(buffer), 0,
				(struct sockaddr *)&cmdAddr,&addrlen);

#if 0
			//printf("cmd addr=%s addrlen=%d\n",cmdAddr.sun_path,addrlen);
			msg = (struct ff_msg *)buffer;
			//printf("msg len=%d\n",sizeof(struct ff_msg));
			msg->buf_addr = (msg + 1);
			//memcpy(tmp,msg->buf_addr,8192);
			//msg->buf_addr = tmp;
			//msg->buf_len =10112;
			msg->sysctl.name = msg->buf_addr;
			//msg->sysctl.new = msg->sysctl.name + msg->sysctl.namelen*sizeof(int);
			msg->sysctl.oldlenp  = (char *)(msg->sysctl.name) + msg->sysctl.namelen*sizeof(int);
#endif

			
			msg = msg_tmp;

			#if 0
			printf("msg = %p \n",msg);
			printf("msg->msg_type=%d\n", msg->msg_type);
			printf("msg->buf_addr=%p\n", msg->buf_addr);	
			printf("msg->buf_len=%lu\n", msg->buf_len);
			printf("msg->sysctl.name=%p\n", msg->sysctl.name);
			printf("msg->sysctl.namelen=%d\n", msg->sysctl.namelen);
			printf("msg->sysctl.old=%p\n", msg->sysctl.old);
			printf("msg->sysctl.oldlenp=%p\n", msg->sysctl.oldlenp);
			printf("msg->sysctl.new=%p\n",	msg->sysctl.new);
			printf("msg->sysctl.newlen=%lu\n",	msg->sysctl.newlen);
			fflush(NULL);
			#endif
			
			handle_msg(msg, 0);

			#if 0
			printf("\n\n\n");
			printf("msg->msg_type=%d\n", msg->msg_type);
			printf("msg->buf_addr=%p\n", msg->buf_addr);	
			printf("msg->buf_len=%lu\n", msg->buf_len);
			printf("msg->sysctl.name=%p\n", msg->sysctl.name);
			printf("msg->sysctl.namelen=%d\n", msg->sysctl.namelen);
			printf("msg->sysctl.old=%p\n", msg->sysctl.old);
			printf("msg->sysctl.oldlenp=%p\n", msg->sysctl.oldlenp);
			printf("msg->sysctl.new=%p\n",	msg->sysctl.new);
			printf("msg->sysctl.newlen=%lu\n",	msg->sysctl.newlen);
			#endif
			
			sendto(cmdSocket,buffer, sizeof(buffer), 0,
				(struct sockaddr *)&cmdAddr,addrlen);
		}

	}
	
	return;

}

int packet_sys_send(char *pkt, int len ,int port)
{
    int n,i;

	if(packet_debug == 1)
	{
	    printf("packet_send len=%d\n",len);

	    for(i=0;i<len;i++)
	         printf("%02x ",(unsigned char )pkt[i]);
	    printf("\n");
	}
    n = send(packet_fd, pkt, len, 0);
	return n;
}



