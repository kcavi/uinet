
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

#include <errno.h>
#include <assert.h>
#include <pthread.h>

#include "ff_config.h"
#include "ff_api.h"
#include "usp_socket.h"


#define MAX_EVENTS 512


/* kevent set */
struct kevent kevSet;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;

char html[] = 
"HTTP/1.1 200 OK\r\n"
"Server: F-Stack\r\n"
"Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
"Content-Type: text/html\r\n"
"Content-Length: 439\r\n"
"Last-Modified: Tue, 21 Feb 2017 09:44:03 GMT\r\n"
"Connection: keep-alive\r\n"
"Accept-Ranges: bytes\r\n"
"\r\n"
"<!DOCTYPE html>\r\n"
"<html>\r\n"
"<head>\r\n"
"<title>Welcome to F-Stack!</title>\r\n"
"<style>\r\n"
"    body {  \r\n"
"        width: 35em;\r\n"
"        margin: 0 auto; \r\n"
"        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n"
"    }\r\n"
"</style>\r\n"
"</head>\r\n"
"<body>\r\n"
"<h1>Welcome to F-Stack!</h1>\r\n"
"\r\n"
"<p>For online documentation and support please refer to\r\n"
"<a href=\"http://F-Stack.org/\">F-Stack.org</a>.<br/>\r\n"
"\r\n"
"<p><em>Thank you for using F-Stack.</em></p>\r\n"
"</body>\r\n"
"</html>";

int kevent_loop(void *arg)
{
    /* Wait for events to happen */
    unsigned nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    unsigned i;

    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;

        /* Handle disconnect */
        if (event.flags & EV_EOF) {
            /* Simply close socket */
            usp_close(clientfd);
        } else if (clientfd == sockfd) {
            int available = (int)event.data;
            do {
                int nclientfd = usp_accept(sockfd, NULL, NULL);
                if (nclientfd < 0) {
                    printf("usp_accept failed:%d, %s\n", errno,
                        strerror(errno));
                    break;
                }

                /* Add to event list */
                EV_SET(&kevSet, nclientfd, EVFILT_READ, EV_ADD, 0, 0, NULL);

                if(ff_kevent(kq, &kevSet, 1, NULL, 0, NULL) < 0) {
                    printf("ff_kevent error:%d, %s\n", errno,
                        strerror(errno));
                    return -1;
                }

                available--;
            } while (available);
        } else if (event.filter == EVFILT_READ) {
            char buf[256];
            size_t readlen = usp_read(clientfd, buf, sizeof(buf));

            usp_write(clientfd, html, sizeof(html));
        } else {
            printf("unknown event: %8.8X\n", event.flags);
        }
    }
}
int kevent_test()
{
	EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);

	assert((kq = ff_kqueue()) > 0);

	/* Update kqueue */
	ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);

	while(1)
	{
		kevent_loop(NULL);
	}

}

int tcp_html_select_loop(int fd)
{
    unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
    USP_FD_ZERO(&rset);	
    USP_FD_SET(fd, &rset);	
    int maxfd=fd; 


	while (1)		 
    {	  
		waittime.tv_sec	= 10;		   
		waittime.tv_usec = 0;
		USP_FD_ZERO(&rset);	
		USP_FD_SET(fd, &rset);
		maxfd=fd;
		//printf("clientfd=%d\n",clientfd);
		if(clientfd > 0)
		{
			USP_FD_SET(clientfd, &rset);
			if(clientfd > maxfd)
				maxfd = clientfd;
		} 
		//printf("%s %d\n",__func__,__LINE__);
		ret=usp_select(maxfd+1,&rset,NULL,NULL,&waittime); 
		//printf("%s %d\n",__func__,__LINE__);
		if(ret > 0)
		{
			if(USP_FD_ISSET(fd,&rset))
			{
				//printf("%s %d\n",__func__,__LINE__);
                int clientfd1 = usp_accept(fd, NULL, NULL);
                if (clientfd1 < 0) 
				{
                    printf("usp_accept failed:%d, %s\n", errno,strerror(errno));
                    break;
                }

				//printf("%s %d\n",__func__,__LINE__);
            	char buf[256];
            	size_t readlen = usp_read(clientfd1, buf, sizeof(buf));

            	usp_write(clientfd1, html, sizeof(html));
				close(clientfd1);
				
			}

			if(USP_FD_ISSET(clientfd,&rset))
			{
				printf("%s %d\n",__func__,__LINE__);
            	char buf[256];
            	size_t readlen = usp_read(clientfd, buf, sizeof(buf));

            	usp_write(clientfd, html, sizeof(html));
				//clientfd  = 0;
				
        	} 
    	}
	}
}




int tcp_echo_select_loop(int fd)
{
    unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
    USP_FD_ZERO(&rset);	
    USP_FD_SET(fd, &rset);	
    int maxfd=fd; 
	char buf[2560];


	while (1)		 
    {	  
		waittime.tv_sec	= 10;		   
		waittime.tv_usec = 0;
		USP_FD_ZERO(&rset);	
		USP_FD_SET(fd, &rset);
		maxfd=fd;
		//printf("clientfd=%d\n",clientfd);
		if(clientfd > 0)
		{
			USP_FD_SET(clientfd, &rset);
			if(clientfd > maxfd)
				maxfd = clientfd;
		} 
		//printf("%s %d\n",__func__,__LINE__);
		ret=usp_select(maxfd+1,&rset,NULL,NULL,&waittime); 
		//printf("%s %d\n",__func__,__LINE__);
		if(ret > 0)
		{
			if(USP_FD_ISSET(fd,&rset))
			{
				printf("%s %d\n",__func__,__LINE__);
                clientfd = usp_accept(fd, NULL, NULL);
                if (clientfd < 0) 
				{
                    printf("usp_accept failed:%d, %s\n", errno,strerror(errno));
                    break;
                }

				printf("%s %d clientfd=%d\n",__func__,__LINE__,clientfd);
            	//char buf[256];
            	//size_t readlen = usp_read(clientfd1, buf, sizeof(buf));

            	//usp_write(clientfd1, html, sizeof(html));
				//close(clientfd1);
				
			}

			if(USP_FD_ISSET(clientfd,&rset))
			{
				//printf("%s %d\n",__func__,__LINE__);
            	size_t readlen = usp_read(clientfd, buf, sizeof(buf));
				//printf("%s %d readlen=%lu\n",__func__,__LINE__,readlen);
				if(readlen <= 0)
				{
					usp_close(clientfd);
					clientfd = 0;
					continue;
				}
				//printf("buf:%s\n",buf);
            	usp_write(clientfd, buf, readlen);
				//clientfd  = 0;
				
        	} 
    	}
	}
}



int loop_udp1(int fd)
{
    /* Wait for events to happen */
    unsigned nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    unsigned i,j;
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);

    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;
		printf("clientfd=%d\n",clientfd);

        if (event.filter == EVFILT_READ) {
            char buf[256];
            size_t readlen = usp_recvfrom(clientfd, buf, sizeof(buf),0, &from, &fromlen);
			printf("loop_udp recv packet:\n");

            for(j=0;j<readlen;j++)
                printf("%02x ",buf[j]);
            printf("\n");
			
            //usp_write(clientfd, html, sizeof(html));
            usp_sendto(clientfd, buf, readlen,0, &from, fromlen);
        } else {
            printf("unknown event: %8.8X\n", event.flags);
        }
    }
}



int loop_udp(int fd)
{
   unsigned i,j;
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	 char buf[2560];

    while(1)
	{
		//printf("loop_udp start recv packets\n");
        int readlen = usp_recvfrom(fd, buf, sizeof(buf),0, &from, &fromlen);
		
		if(readlen <= 0)
			continue;

		//printf("loop_udp recv packet: readlen=%d\n",readlen);
#if 0
        for(j=0;j<readlen;j++)
            printf("%02x ",buf[j]);
        printf("\n");
#endif	
        //usp_write(clientfd, html, sizeof(html));
        usp_sendto(fd, buf, readlen,0, &from, fromlen);
	}
}



void *udp_socket_test(void *arg)
{
	int on = 1;

	ff_th_init("udp_socket_test");
    int sockfd = usp_socket(USP_AF_INET, USP_SOCK_DGRAM, 0);
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0) {
        printf("usp_socket failed\n");
        exit(1);
    }

    struct usp_sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_len = sizeof(my_addr);
    my_addr.sin_family = USP_AF_INET;
    my_addr.sin_port = htons(8010);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	usp_setsockopt (sockfd, USP_SOL_SOCKET, USP_SO_REUSEPORT,(char *) &on, sizeof (on));		

    int ret = usp_bind(sockfd, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("udp_socket_test usp_bind failed ret=%d\n",ret);
        exit(1);
    }
	
/*
    ret = usp_listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("usp_listen failed\n");
        exit(1);
    }
*/

#if 0

    EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);

    assert((kq = ff_kqueue()) > 0);

    /* Update kqueue */
    ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);

    //ff_run(loop, NULL);
#endif

    while(1)
    {
        loop_udp(sockfd);
    }
    return 0;
}

void *rtsocket_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	char buf[2560];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
	struct usp_sockaddr_nl rtAddr;

	ff_th_init("rtsocket_test");
    
	int rtsockfd = usp_socket(USP_AF_NETLINK, USP_SOCK_RAW, NETLINK_ROUTE);
	if (rtsockfd < 0) 
	{
		printf("rt_socket failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}

	printf("af_netlink sockfd:%d\n", rtsockfd);

	bzero((char *)(&rtAddr), sizeof(rtAddr));
	rtAddr.nl_len = sizeof(rtAddr);
	rtAddr.nl_family = USP_AF_NETLINK;
	rtAddr.nl_pad = 0;
	rtAddr.nl_pid = 0;
	rtAddr.nl_groups = 0;
	if(0 != usp_bind(rtsockfd, (struct usp_sockaddr*)(&rtAddr), sizeof(rtAddr)))
	{
		printf("rtSocekt bind failed!\n\r");
		return NULL;
	}

	while(1)
	{
		ret = usp_recv(rtsockfd,buf,sizeof(buf),0);
		printf("net link sock ret = %d\n",ret);
		
	}
}




void *open_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	char buf[256];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
	int fd;

	ff_th_init("open_test");

#if 0
	fd = open("testfile", O_CREAT|O_RDWR, 666);
	if (fd < 0) 
	{
		printf("open fd failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}


	printf("fd:%d\n", fd);


	printf("buf=%p,len=%d\n",buf,sizeof(buf));
	while(1)
	{
		ret = read(fd,buf,sizeof(buf));
		printf("buf:%s\n",buf);
		printf("ret =%d\n",ret);
		sleep(10);
		
	}



#endif

	//printf("flags=%x mode=%x\n",O_CREAT|O_RDWR,666);

	
	fd = usp_open("testfile", O_CREAT|O_RDWR, 666);
	if (fd < 0) 
	{
		printf("open fd failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}


	printf("fd:%d\n", fd);


	ret = usp_write(fd,"nnnnnnnnnnnnmmmmmmhhhh",10);
	printf("write ret = %d\n",ret);
	
	while(1)
	{
		ret = usp_read(fd,buf,sizeof(buf));
		printf("buf:%s\n",buf);
		printf("read ret =%d\n",ret);
		sleep(10);
		
	}
}




int amaster;
int aslave;


void *pty_read_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	char buf[2560];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;

	ff_th_init("pty_read_test");

	ret = usp_openpty(&amaster, &aslave,NULL);
	if (ret < 0) 
	{
		printf("open fd failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}


	printf("amaster:%d  aslave:%d\n", amaster,aslave);

	while(1)
	{
		memset(buf,0,sizeof(buf));
		ret = usp_read(amaster,buf,sizeof(buf));
		//printf("read ret =%d msg:%s\n",ret,buf);
		if(ret < 0)
		{
			perror("read error:");
			printf("read errno:%d\n",errno);
		}
		else
		{
			printf("buf:%s len:%d\n",buf,ret);
		}
		
		
	}
}



void *vty_main_loop(void *arg)
{	
	struct timeval timer_now;
	struct timeval *timer_wait;
	int ret;
	int readlen;
	int time1,time2;
	usp_fd_set rset;
	int i,fd;
	int maxfd;
	
	unsigned char buf[2560];

	sleep(3);
	fd = aslave;
	ff_th_init("vty_main_loop");


	while(1)
	{		
		timer_wait = &timer_now;
		timer_now.tv_sec = 20;
		timer_now.tv_usec = 0;
		USP_FD_ZERO(&rset); 
		USP_FD_SET(aslave, &rset);
		maxfd = aslave; 
		
	
		printf("%s:%d,read_set:%d,write_set:%d\r\n",__func__, __LINE__,
				USP_FD_ISSET(fd,&rset),USP_FD_ISSET(fd,&rset));

		ret = usp_select(maxfd + 1,&rset,NULL,NULL,timer_wait);
	
		printf("%s:%d,ret=%d,read_set:%d,write_set:%d\r\n",__func__, __LINE__,
				ret,USP_FD_ISSET(fd,&rset),USP_FD_ISSET(fd,&rset));


		
		if(ret > 0)
		{
			if(USP_FD_ISSET(aslave,&rset))
			{
				//printf("%s %d\n",__func__,__LINE__);
				readlen =  usp_read(aslave,buf,sizeof(buf));
				if(readlen <= 0)
					continue;
				printf("%s %d readlen=%d\n",__func__,__LINE__,readlen);
/*
				time2 = time(NULL);
				if((time2 - time1) > 1)
				{
					printf("pty read error\n\n\n");
					exit(-1);
				}
*/
				printf("select buf:%s len:%d\n",buf,readlen);

				for(i=0;i<readlen;i++)
					printf("%02x ",buf[i]);

				printf("\n\n\n\n\n\n\n");

				

				//printf("sockfd0 recv packet: readlen=%d\n",readlen);

				usp_write(aslave, buf, readlen);
				
			}
		
		}
	}
	return NULL;
}


void vty_sock_serv()
{
	int ptyfd,ttyfd,maxfd;
	char ttyname[128];
	char buf[1500];
	int bytes,ret,clientfd;
	usp_fd_set rfdset;
	pthread_t pid;
	int fd;

	ff_th_init("vty_sock_serv");
	
	int sockfd = usp_socket(USP_AF_INET, USP_SOCK_STREAM, 0);
    printf("tcp_echo_test sockfd:%d\n", sockfd);
    if (sockfd < 0) 
	{
        printf("usp_socket failed\n");
        return;
    }

    struct usp_sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_len = sizeof(my_addr);
    my_addr.sin_family = USP_AF_INET;
    my_addr.sin_port = htons(23);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = usp_bind(sockfd, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) 
	{
        printf("usp_bind failed\n");
        return;
    }

    ret = usp_listen(sockfd, MAX_EVENTS);
    if (ret < 0) 
	{
        printf("usp_listen failed\n");
        return;
    }


	fd = usp_accept(sockfd, NULL, NULL);
	if (fd < 0) 
	{
	  printf("usp_accept failed:%d, %s\n", errno,strerror(errno));
	  return;
	}

	//tcp_echo_select_loop(sockfd);

	ret = usp_openpty(&amaster, &aslave,NULL);
	if (ret < 0) 
	{
		printf("open fd failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return ;
	}
	ptyfd = amaster;

	pthread_create(&pid, NULL,vty_main_loop, NULL);
	
	maxfd = fd;
	if(maxfd < ptyfd)
		maxfd = ptyfd;
	USP_FD_ZERO(&rfdset);

	while(1)
	{
		USP_FD_SET(fd,&rfdset);
		USP_FD_SET(ptyfd, &rfdset);
		printf("%s %d\n",__func__,__LINE__);
		ret = usp_select(maxfd + 1, &rfdset, NULL, NULL, NULL);
		printf("%s:%d,ret=%d,tty:%d,pty:%d\r\n",__func__, __LINE__,
				ret,USP_FD_ISSET(fd,&rfdset),USP_FD_ISSET(ptyfd, &rfdset));
		
		if (ret <= 0)
		{
			break;
		}
		memset(buf,0,sizeof(buf));
		if(USP_FD_ISSET(ptyfd, &rfdset))
		{
			bytes = usp_read(ptyfd, buf, sizeof(buf));
			if(bytes <= 0)
			{
				printf("pty fd read fail\n");
				break;
			}
			printf("%s:%d,pty bytes=%d, buf:%s\r\n",__func__, __LINE__,bytes,buf);

			if(usp_write(fd, buf, bytes) < bytes)
			{
				printf("tcp fd write fail\n");
				//break;
			}
		}
		
		if(USP_FD_ISSET(fd, &rfdset))
		{
			bytes = usp_read(fd, buf, sizeof(buf));
			if(bytes <= 0)
			{
				printf("tcp fd read fail\n");
				break;
			}
			printf("%s:%d,tcp bytes=%d, buf:%s\r\n",__func__, __LINE__,bytes,buf);
			if(usp_write(ptyfd, buf, bytes) < bytes)
			{
				printf("pty fd write fail\n");
				break;
			}
		}
	}
	
	usp_close(fd);
	usp_close(ptyfd);
	return;
}





void *pty_select_read_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	unsigned char buf[2560];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
	int time1,time2;

	ff_th_init("pty_read_test");

	ret = usp_openpty(&amaster, &aslave,NULL);
	if (ret < 0) 
	{
		printf("open fd failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}


	printf("amaster:%d  aslave:%d\n", amaster,aslave);
	while (1)		 
	{	  
		waittime.tv_sec = 10;		   
		waittime.tv_usec = 0;
		USP_FD_ZERO(&rset); 
		USP_FD_SET(amaster, &rset);
		maxfd = amaster; 

		//printf("%s %d\n",__func__,__LINE__);
		ret=usp_select(maxfd+1,&rset,NULL,NULL,&waittime); 
		//printf("%s %d\n",__func__,__LINE__);
		if(ret > 0)
		{
			if(USP_FD_ISSET(amaster,&rset))
			{
				readlen =  usp_read(amaster,buf,sizeof(buf));
				if(readlen <= 0)
					continue;

				printf("select buf:%s len:%d\n",buf,readlen);

				

				//printf("sockfd0 recv packet: readlen=%d\n",readlen);

				//usp_sendto(sockfd0, buf, readlen,0, &from, fromlen);
				
			}

			
		}
	}

}


void *pty_write_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	char buf[2560] = "11111111111";
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;

	ff_th_init("pty_write_test");


	printf("write thread amaster:%d  aslave:%d\n", amaster,aslave);

	while(1)
	{
		ret = usp_write(aslave,buf,strlen(buf));
		printf("write ret =%d\n",ret);
		if(ret < 0)
		{
			perror("error:");
			printf("errno:%d\n",errno);
		}
		sleep(3);
		
	}
}


void *unix_client_test(void *arg)
{
	struct usp_sockaddr_un cmdAddr;
	socklen_t addrlen=sizeof(cmdAddr);
	char msg[128]="123456666666666";
	char buf[2560];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
#define UNIX_TEST_SOCKET_PATH		"/tmp/albCmd.socket"

	ff_th_init("unix_client_test");


	int unix_client_sockfd = usp_socket(USP_AF_UNIX, USP_SOCK_DGRAM, 0);
	if (unix_client_sockfd < 0) 
	{
		printf("unix_socket failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}


	printf("unix_client_sockfd:%d\n", unix_client_sockfd);


	bzero((char *)(&cmdAddr), sizeof(cmdAddr));
	cmdAddr.sun_family = USP_AF_UNIX;
	strcpy(cmdAddr.sun_path, UNIX_TEST_SOCKET_PATH);
	cmdAddr.sun_len = sizeof(cmdAddr);
	

	while(1)
	{
		ret = usp_sendto(unix_client_sockfd,msg,128,0,(struct usp_sockaddr *)(&cmdAddr), sizeof(cmdAddr));
		printf("send ret = %d\n",ret);
		sleep(3);
	}
}




void *unix_server_test(void *arg)
{
	struct usp_sockaddr_un cmdAddr;
	socklen_t addrlen=sizeof(cmdAddr);
	char buf[1024];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
#define UNIX_TEST_SOCKET_PATH		"/tmp/albCmd.socket"

	ff_th_init("unix_server_test");
    
	int unixsockfd = usp_socket(USP_AF_UNIX, USP_SOCK_DGRAM, 0);
	if (unixsockfd < 0) 
	{
		printf("unix_socket failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}


	printf("unixsockfd:%d\n", unixsockfd);


	bzero((char *)(&cmdAddr), sizeof(cmdAddr));
	cmdAddr.sun_family = USP_AF_UNIX;
	strcpy(cmdAddr.sun_path, UNIX_TEST_SOCKET_PATH);
	cmdAddr.sun_len = sizeof(cmdAddr);
	if(usp_bind(unixsockfd, (struct usp_sockaddr *)(&cmdAddr), sizeof(cmdAddr)) != 0) 
	{
		perror("unix socket bind failed!\n");
		return NULL;
	}
	

	while(1)
	{
		ret = usp_recv(unixsockfd,buf,sizeof(buf),0);
		printf("recv ret = %d\n",ret);
		printf("recv:%s\n",buf);
		
	}
}



void *unix_tcp_client_test(void *arg)
{
	struct usp_sockaddr_un cmdAddr;
	socklen_t addrlen=sizeof(cmdAddr);
	char msg[128]="123456666666666";
	char buf[2560];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
#define UNIX_TEST_SOCKET_PATH		"/tmp/albCmd.socket"

	ff_th_init("unix_client_test");


	int unix_client_sockfd = usp_socket(USP_AF_UNIX, USP_SOCK_STREAM, 0);
	if (unix_client_sockfd < 0) 
	{
		printf("unix_socket failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}


	printf("unix_client_sockfd:%d\n", unix_client_sockfd);


	bzero((char *)(&cmdAddr), sizeof(cmdAddr));
	cmdAddr.sun_family = USP_AF_UNIX;
	strcpy(cmdAddr.sun_path, UNIX_TEST_SOCKET_PATH);
	cmdAddr.sun_len = sizeof(cmdAddr);


	ret = usp_connect(unix_client_sockfd,(struct usp_sockaddr *)(&cmdAddr), sizeof(cmdAddr));
	if(ret != 0)
	{
		perror("unix connect failed!\r\n");
		return NULL;
	}

	while(1)
	{
		ret = usp_send(unix_client_sockfd,msg,128,0);
		printf("send ret = %d\n",ret);

		ret = usp_recv(unix_client_sockfd,buf,sizeof(buf),0);
		printf("recv ret = %d\n",ret);

		printf("recv buf:%s\n",buf);
		sleep(3);
	}
}




void *unix_tcp_server_test(void *arg)
{
	struct usp_sockaddr_un cmdAddr;
	socklen_t addrlen=sizeof(cmdAddr);
	char buf[1024];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
#define UNIX_TEST_SOCKET_PATH		"/tmp/albCmd.socket"

	ff_th_init("unix_server_test");
    
	int unixsockfd = usp_socket(USP_AF_UNIX, USP_SOCK_STREAM, 0);
	if (unixsockfd < 0) 
	{
		printf("unix_socket failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}


	printf("unixsockfd:%d\n", unixsockfd);


	bzero((char *)(&cmdAddr), sizeof(cmdAddr));
	cmdAddr.sun_family = USP_AF_UNIX;
	strcpy(cmdAddr.sun_path, UNIX_TEST_SOCKET_PATH);
	cmdAddr.sun_len = sizeof(cmdAddr);
	if(usp_bind(unixsockfd, (struct usp_sockaddr *)(&cmdAddr), sizeof(cmdAddr)) != 0) 
	{
		perror("unix socket bind failed!\n");
		return NULL;
	}

	ret = usp_listen(unixsockfd, 10);
    if (ret < 0) 
	{
        printf("usp_listen failed\n");
        return NULL;
    }
	
	tcp_echo_select_loop(unixsockfd);
	return NULL;
	
	while(1)
	{
		ret = usp_recv(unixsockfd,buf,sizeof(buf),0);
		printf("recv ret = %d\n",ret);
		printf("recv:%s\n",buf);
		
	}
}


void *ipv6_udp_server_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	char buf[2560] = {0};
	char addr_rcv[256] = {0};
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
	socklen_t addr_len;
	
	//ff_th_init("ipv6_udp_server");
    
    int ipv6sockfd = usp_socket(USP_AF_INET6, USP_SOCK_DGRAM, 0);
    if (ipv6sockfd < 0) 
	{
        printf("ipv6_socket failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
        return NULL;
    }


	printf("ipv6 server sockfd:%d\n", ipv6sockfd);

	struct usp_sockaddr_in6 my_addr;
#if 1
	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin6_len = sizeof(my_addr);
	my_addr.sin6_family = USP_AF_INET6;
	my_addr.sin6_port = htons(8016);
	my_addr.sin6_addr = in6addr_any;

	ret = usp_bind(ipv6sockfd, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
	if (ret < 0) 
	{
		printf("ipv6sockfd usp_bind failed ret=%d\n",ret);
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}
#endif
#define REMOTEIP "fe80::66"	

	while(1)
	{
		bzero(buf,sizeof(buf));  
		readlen = usp_recvfrom(ipv6sockfd,buf,sizeof(buf),0,(struct usp_sockaddr *)&my_addr,(socklen_t*)&addr_len); 
  
		inet_ntop(AF_INET6,&my_addr.sin6_addr,addr_rcv,sizeof(addr_rcv));  
		printf("message from ip %s",addr_rcv);  
		printf("Received message : %s\n",buf);
		#if 0
		if(usp_sendto(ipv6sockfd,buf,readlen,0,(struct usp_sockaddr *)&my_addr,addr_len)<0)  
		{  
			printf("error");
		}  
		#endif
		//inet_pton(AF_INET6,REMOTEIP,&my_addr.sin6_addr);  
		//printf("my_addr.sin6_addr.s6_addr[15] = %x\n", my_addr.sin6_addr.s6_addr[15]);
		
	}
}



void *ipv6_udp_client_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	char buf[2560] = {0};
	char msg[128] = "ipv6 msg";
	char addr_rcv[256] = {0};
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
	socklen_t addr_len;
	
	//ff_th_init("ipv6_udp_client");
    
    int ipv6sockfd = usp_socket(USP_AF_INET6, USP_SOCK_DGRAM, 0);
    if (ipv6sockfd < 0) 
	{
        printf("ipv6_socket failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
        return NULL;
    }


	printf("ipv6 client sockfd:%d\n", ipv6sockfd);

	struct usp_sockaddr_in6 my_addr;


#define LINKLOCALADDR "fe80::211:22ff:fe33:4455"	

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin6_len = sizeof(my_addr);
	my_addr.sin6_family = USP_AF_INET6;
	my_addr.sin6_port = htons(8017);
	//my_addr.sin6_addr = in6addr_any;
	inet_pton(AF_INET6,LINKLOCALADDR,&my_addr.sin6_addr);
	
#if 1

	ret = usp_bind(ipv6sockfd, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
	if (ret < 0) 
	{
		printf("ipv6sockfd usp_bind failed ret=%d\n",ret);
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}
#endif
#define REMOTEIP "fe80::66"	


	my_addr.sin6_port = htons(8016);
	inet_pton(AF_INET6,REMOTEIP,&my_addr.sin6_addr);

	while(1)
	{
		readlen = usp_sendto(ipv6sockfd,msg,sizeof(msg),0,(struct usp_sockaddr *)&my_addr,sizeof(my_addr)); 
		printf("ipv6 send len=%d\n",readlen);
  #if 0
		bzero(buf,sizeof(buf));  
		readlen = usp_recvfrom(ipv6sockfd,buf,sizeof(buf),0,(struct usp_sockaddr *)&my_addr,(socklen_t*)&addr_len); 
  
		inet_ntop(AF_INET6,&my_addr.sin6_addr,addr_rcv,sizeof(addr_rcv));  
		printf("message from ip %s",addr_rcv);  
		printf("Received message : %s\n",buf);  
		if(usp_sendto(ipv6sockfd,buf,readlen,0,(struct usp_sockaddr *)&my_addr,addr_len)<0)  
		{  
			printf("error");
		}  
	#endif
		//inet_pton(AF_INET6,REMOTEIP,&my_addr.sin6_addr);  
		//printf("my_addr.sin6_addr.s6_addr[15] = %x\n", my_addr.sin6_addr.s6_addr[15]);

		sleep(3);
		
	}
}


void *tcp_web_test(void *arg)
{
	//ff_th_init("tcp socket_test");
	
	int sockfd = usp_socket(USP_AF_INET, USP_SOCK_STREAM, 0);
    printf("tcp_web_test sockfd:%d\n", sockfd);
    if (sockfd < 0) 
	{
        printf("usp_socket failed\n");
        return NULL;
    }

    struct usp_sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_len = sizeof(my_addr);
    my_addr.sin_family = USP_AF_INET;
    my_addr.sin_port = htons(80);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = usp_bind(sockfd, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) 
	{
        printf("usp_bind failed\n");
        return NULL;
    }

    ret = usp_listen(sockfd, MAX_EVENTS);
    if (ret < 0) 
	{
        printf("usp_listen failed\n");
        return NULL;
    }

#if 1
	tcp_html_select_loop(sockfd);
#else
	kevent_test();
#endif
    return 0;
}




void *tcp_echo_test(void *arg)
{
	ff_th_init("tcp echo socket_test");
	
	int sockfd = usp_socket(USP_AF_INET, USP_SOCK_STREAM, 0);
    printf("tcp_echo_test sockfd:%d\n", sockfd);
    if (sockfd < 0) 
	{
        printf("usp_socket failed\n");
        return NULL;
    }

    struct usp_sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_len = sizeof(my_addr);
    my_addr.sin_family = USP_AF_INET;
    my_addr.sin_port = htons(800);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = usp_bind(sockfd, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) 
	{
        printf("usp_bind failed\n");
        return NULL;
    }

    ret = usp_listen(sockfd, MAX_EVENTS);
    if (ret < 0) 
	{
        printf("usp_listen failed\n");
        return NULL;
    }

	tcp_echo_select_loop(sockfd);
    return 0;
}


void *af_packet_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	unsigned char buf[2560];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;
	int packetsockfd;

	ff_th_init("af_packet_test");
    
    packetsockfd = usp_socket(USP_AF_PACKET, USP_SOCK_RAW, 0);
	if (packetsockfd < 0) 
	{
		printf("packetsockfd failed\n");
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}

	printf("packetsockfd:%d\n", packetsockfd);

	struct usp_sockaddr_ll  my_addr;
	memset(&my_addr, 0, sizeof(struct sockaddr_ll));
	my_addr.sll_len = sizeof(my_addr);
	my_addr.sll_family = USP_AF_PACKET ;
	my_addr.sll_pkttype = 0 ;
	my_addr.sll_protocol = htons(0x0800);
	my_addr.sll_ifindex = 2;  //test ifindex
	my_addr.sll_halen = ETH_ALEN ;


	ret = usp_bind(packetsockfd, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
	if (ret < 0) 
	{
		printf("packetsockfd usp_bind failed ret=%d\n",ret);
		perror("error:");
		printf("errno:%d\n",errno);
		return NULL;
	}

	while(1)
	{
		readlen = usp_recvfrom(packetsockfd, buf, sizeof(buf),0, &from, &fromlen);
		printf("af_packet receive readlen=%d\n",readlen);
		if(readlen <= 0)
			continue;

#if 1
        for(i=0;i<readlen;i++)
            printf("%02x ",buf[i]);
        printf("\n");
#endif	
        //usp_sendto(fd, buf, readlen,0, &from, fromlen);
        //readlen = usp_send(packetsockfd, buf, readlen,0);
		readlen = usp_sendto(packetsockfd, buf, readlen,0, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));

		printf("af_packet send readlen=%d\n",readlen);

        
	}
}



void *select_test(void *arg)
{
	struct usp_sockaddr from;
	socklen_t fromlen=sizeof(from);
	char buf[2560];
	unsigned i;
    struct timeval waittime;
    usp_fd_set rset;
	int ret;
	int clientfd = 0;
	int maxfd;
	int readlen;

	ff_th_init("select_test");
    
    int sockfd0 = usp_socket(USP_AF_INET, USP_SOCK_DGRAM, 0);
	int sockfd1 = usp_socket(USP_AF_INET, USP_SOCK_DGRAM, 0);
    
    if (sockfd0 < 0 || sockfd1 < 0) {
        printf("usp_socket failed\n");
        exit(1);
    }


	printf("sockfd0:%d\n", sockfd0);
	printf("sockfd1:%d\n", sockfd1);

    struct usp_sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_len = sizeof(my_addr);
    my_addr.sin_family = USP_AF_INET;
    my_addr.sin_port = htons(8011);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = usp_bind(sockfd0, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
	if (ret < 0) 
	{
		printf("select_test1 usp_bind failed ret=%d\n",ret);
		exit(1);
	}

	sleep(5);

	
    bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_len = sizeof(my_addr);
    my_addr.sin_family = USP_AF_INET;
    my_addr.sin_port = htons(8012);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = usp_bind(sockfd1, (struct usp_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("select_test2 usp_bind failed ret=%d\n",ret);
        exit(1);
    }

	

	while (1)		 
    {	  
		waittime.tv_sec	= 10;		   
		waittime.tv_usec = 0;
		USP_FD_ZERO(&rset);	
		USP_FD_SET(sockfd0, &rset);
		USP_FD_SET(sockfd1, &rset);	
    	maxfd = sockfd0 > sockfd1?sockfd0:sockfd1; 

		//printf("%s %d\n",__func__,__LINE__);
		ret=usp_select(maxfd+1,&rset,NULL,NULL,&waittime); 
		//printf("%s %d\n",__func__,__LINE__);
		if(ret > 0)
		{
			if(USP_FD_ISSET(sockfd0,&rset))
			{
				readlen = usp_recvfrom(sockfd0, buf, sizeof(buf),0, &from, &fromlen);

				if(readlen <= 0)
					continue;

				//printf("sockfd0 recv packet: readlen=%d\n",readlen);

				usp_sendto(sockfd0, buf, readlen,0, &from, fromlen);
				
			}

			if(USP_FD_ISSET(sockfd1,&rset))
			{
				readlen = usp_recvfrom(sockfd1, buf, sizeof(buf),0, &from, &fromlen);

				if(readlen <= 0)
					continue;

				//printf("sockfd1 recv packet: readlen=%d\n",readlen);

				usp_sendto(sockfd1, buf, readlen,0, &from, fromlen);
        	} 
    	}
	}
    return 0;
}



int main(int argc, char * argv[])
{
	pthread_t pid;
    ff_init(argc, argv);


#if 0  /*af_unix udp*/
	sleep(2);
	pthread_create(&pid, NULL,unix_server_test, NULL);

	sleep(2);
	pthread_create(&pid, NULL,unix_client_test, NULL);

#endif

#if 0  /*af_unix tcp*/
	sleep(2);
	pthread_create(&pid, NULL,unix_tcp_server_test, NULL);

	sleep(2);
	pthread_create(&pid, NULL,unix_tcp_client_test, NULL);
#endif


#if 0

	sleep(2);
	pthread_create(&pid, NULL,udp_socket_test, NULL);

#endif

#if 0

	sleep(2);
	pthread_create(&pid, NULL,select_test, NULL);
#endif

#if 0

	sleep(2);
	pthread_create(&pid, NULL,rtsocket_test, NULL);
#endif

#if 0  //ipv6 udp
	sleep(2);
	usp_pthread_create("ipv6_udp_server",&pid, NULL,ipv6_udp_server_test, NULL);

	sleep(2);
	usp_pthread_create("ipv6_udp_client",&pid, NULL,ipv6_udp_client_test, NULL);
#endif

#if 1
	sleep(2);
	usp_pthread_create("tcp_web",&pid, NULL,tcp_web_test, NULL);
#endif

#if 0
	sleep(2);
	pthread_create(&pid, NULL,tcp_echo_test, NULL);
#endif
	

#if 0  //pty
	sleep(2);
	//pthread_create(&pid, NULL,pty_read_test, NULL);
	pthread_create(&pid, NULL,pty_select_read_test, NULL);
	
	sleep(2);
	pthread_create(&pid, NULL,pty_write_test, NULL);

#endif

#if 0  //af_packet
	sleep(2);
	pthread_create(&pid, NULL,af_packet_test, NULL);
#endif


#if 0 //file operate
		sleep(2);
		pthread_create(&pid, NULL,open_test, NULL);
#endif


#if 0 //telnet test
		sleep(3);
		pthread_create(&pid, NULL,vty_sock_serv, NULL);
#endif


	while(1)
	{
		sleep(5);
		//uma_print_stats();
	}

    
}
