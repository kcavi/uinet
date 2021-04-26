/* 检测两个文件描述符，分别为一般数据和高优先数据。如果事件发生
       则用相关描述符和优先度调用函数handler()，无时间限制等待，直到
       错误发生或描述符挂起。*/
   
    #include <stdlib.h>
    #include <stdio.h>
  
    #include <sys/types.h>
    #include <stropts.h>
    #include <poll.h>
  
    #include <unistd.h>
    #include <errno.h>
    #include <string.h>
  
    #define NORMAL_DATA 1
    #define HIPRI_DATA 2
  
    int poll_two_normal(int fd1,int fd2)
    {
        struct pollfd poll_list[2];
        int retval;
  
        poll_list[0].fd = fd1;
        poll_list[1].fd = fd2;
        poll_list[0].events = POLLIN|POLLPRI;
        poll_list[1].events = POLLIN|POLLPRI;
  
        while(1)
        {
            retval = poll(poll_list,(unsigned long)2,-1);
            /* retval 总是大于0或为-1，因为我们在阻塞中工作 */
  
            if(retval < 0)
            {
                fprintf(stderr,"poll错误: %s\n",strerror(errno));
                return -1;
            }
    
            if(((poll_list[0].revents&POLLHUP) == POLLHUP) ||
               ((poll_list[0].revents&POLLERR) == POLLERR) ||
               ((poll_list[0].revents&POLLNVAL) == POLLNVAL) ||
               ((poll_list[1].revents&POLLHUP) == POLLHUP) ||
               ((poll_list[1].revents&POLLERR) == POLLERR) ||
               ((poll_list[1].revents&POLLNVAL) == POLLNVAL))
              return 0;
  
            if((poll_list[0].revents&POLLIN) == POLLIN)
              handle(poll_list[0].fd,NORMAL_DATA);
            if((poll_list[0].revents&POLLPRI) == POLLPRI)
              handle(poll_list[0].fd,HIPRI_DATA);
            if((poll_list[1].revents&POLLIN) == POLLIN)
              handle(poll_list[1].fd,NORMAL_DATA);
            if((poll_list[1].revents&POLLPRI) == POLLPRI)
              handle(poll_list[1].fd,HIPRI_DATA);
        }
    }
    
packet_tst()
{
	int maxfd,fd;
	struct sockaddr_ll dstAddr;
	fd_set rfdset;
	struct timeval timer_now;
	struct timeval *timer_wait;
	int ret,nbytes;
	unsigned char buf[1500];
	uint32_t ifIndex = 4097;
	uint16_t proto = 0x88cc;
	
	/*for ts telnet client*/
	fd = socket (AF_PACKET, SOCK_DGRAM, 0);
	if(fd==ERROR)
	{
		vty_out(vty,"socket error.%s",VTY_NEWLINE);
		return -1;
	}

	memset(&dstAddr,0,sizeof(dstAddr));
	dstAddr.sll_family      = AF_PACKET;
	dstAddr.sll_pkttype      = PACKET_HOST;
	proto = strtoul(argv[2],0,0);
   	dstAddr.sll_protocol    = htons(proto);
   	dstAddr.sll_ifindex 	= ifIndex;
   	dstAddr.sll_halen	= 6;
   	mac_str2hex(argv[3], dstAddr.sll_addr, 6);

	bind(fd, (struct sockaddr *)&dstAddr, sizeof(dstAddr));
	/*bind(fd, (struct sockaddr *)&dstAddr, sizeof(dstAddr));*/
   	
	timer_now.tv_sec=10;
	timer_now.tv_usec = 0;
	maxfd=fd;


	FD_ZERO(&rfdset);

	while(1)
	{
		FD_SET(fd,&rfdset);	
		
		vty_event (VTY_TIME, vty);		

		timer_now.tv_sec=0;
		timer_now.tv_usec = 0;
		if(timer_now.tv_sec>0)
			timer_wait= &timer_now;
		else
			timer_wait= NULL;
		ret=select(maxfd+1,&rfdset,NULL,NULL,timer_wait);
		if(ret == 0)
			break;

		/*process socket data*/
		if(FD_ISSET(fd,&rfdset))
		{
			if((nbytes = vty_recv(fd,buf,sizeof(buf))) <= 0)
			{
				vty_out(vty,"%s  %%Server has closed connection.%s",VTY_NEWLINE,VTY_NEWLINE);
				break;
			}
			vty_fast_out(vty,0,"Rcv packet:%d bytes\r\n",nbytes);
		}
	}
	close(fd);
	
	
	/*for ts telnet client*/
	fd = socket (AF_PACKET, SOCK_DGRAM, htons(proto));
	if(fd==ERROR)
	{
		vty_out(vty,"socket error.%s",VTY_NEWLINE);
		return -1;
	}

	memset(&dstAddr,0,sizeof(dstAddr));
	dstAddr.sll_family      = AF_PACKET;
	dstAddr.sll_pkttype      = PACKET_HOST;
	proto = strtoul(argv[2],0,0);
   	dstAddr.sll_protocol    = htons(proto);
   	dstAddr.sll_ifindex 	= ifIndex;
   	dstAddr.sll_halen	= 6;
   	mac_str2hex(argv[3], dstAddr.sll_addr, 6);

	bind(fd, (struct sockaddr *)&dstAddr, sizeof(dstAddr));
	/*bind(fd, (struct sockaddr *)&dstAddr, sizeof(dstAddr));*/
   	
	timer_now.tv_sec=10;
	timer_now.tv_usec = 0;
	maxfd=fd;


	FD_ZERO(&rfdset);

	while(1)
	{
		FD_SET(fd,&rfdset);	
		
		vty_event (VTY_TIME, vty);		

		timer_now.tv_sec=0;
		timer_now.tv_usec = 0;
		if(timer_now.tv_sec>0)
			timer_wait= &timer_now;
		else
			timer_wait= NULL;
		ret=select(maxfd+1,&rfdset,NULL,NULL,timer_wait);
		if(ret == 0)
			break;

		/*process socket data*/
		if(FD_ISSET(fd,&rfdset))
		{
			if((nbytes = vty_recv(fd,buf,sizeof(buf))) <= 0)
			{
				vty_out(vty,"%s  %%Server has closed connection.%s",VTY_NEWLINE,VTY_NEWLINE);
				break;
			}
			vty_fast_out(vty,0,"Rcv packet:%d bytes\r\n",nbytes);
		}
	}
	close(fd);


	/*for ts telnet client*/
	fd = socket (AF_PACKET, SOCK_RAW, 0);
	if(fd==ERROR)
	{
		vty_out(vty,"socket error.%s",VTY_NEWLINE);
		return -1;
	}

	memset(&dstAddr,0,sizeof(dstAddr));
	dstAddr.sll_family      = AF_PACKET;
	dstAddr.sll_pkttype      = PACKET_HOST;
	proto = strtoul(argv[2],0,0);
   	dstAddr.sll_protocol    = htons(proto);
   	dstAddr.sll_ifindex 	= ifIndex;
   	dstAddr.sll_halen	= 6;
   	mac_str2hex(argv[3], dstAddr.sll_addr, 6);

	bind(fd, (struct sockaddr *)&dstAddr, sizeof(dstAddr));
	/*bind(fd, (struct sockaddr *)&dstAddr, sizeof(dstAddr));*/
   	
	timer_now.tv_sec=10;
	timer_now.tv_usec = 0;
	maxfd=fd;


	FD_ZERO(&rfdset);

	while(1)
	{
		FD_SET(fd,&rfdset);	
		
		vty_event (VTY_TIME, vty);		

		timer_now.tv_sec=0;
		timer_now.tv_usec = 0;
		if(timer_now.tv_sec>0)
			timer_wait= &timer_now;
		else
			timer_wait= NULL;
		ret=select(maxfd+1,&rfdset,NULL,NULL,timer_wait);
		if(ret == 0)
			break;

		/*process socket data*/
		if(FD_ISSET(fd,&rfdset))
		{
			if((nbytes = vty_recv(fd,buf,sizeof(buf))) <= 0)
			{
				vty_out(vty,"%s  %%Server has closed connection.%s",VTY_NEWLINE,VTY_NEWLINE);
				break;
			}
			vty_fast_out(vty,0,"Rcv packet:%d bytes\r\n",nbytes);
		}
	}
	close(fd);
	
	/*for ts telnet client*/
	fd = socket (AF_PACKET, SOCK_RAW, htons(proto));
	if(fd==ERROR)
	{
		vty_out(vty,"socket error.%s",VTY_NEWLINE);
		return -1;
	}

	memset(&dstAddr,0,sizeof(dstAddr));
	dstAddr.sll_family      = AF_PACKET;
	dstAddr.sll_pkttype      = PACKET_HOST;
	proto = strtoul(argv[2],0,0);
   	dstAddr.sll_protocol    = htons(proto);
   	dstAddr.sll_ifindex 	= ifIndex;
   	dstAddr.sll_halen	= 6;
   	mac_str2hex(argv[3], dstAddr.sll_addr, 6);

	bind(fd, (struct sockaddr *)&dstAddr, sizeof(dstAddr));
	/*bind(fd, (struct sockaddr *)&dstAddr, sizeof(dstAddr));*/
   	
	timer_now.tv_sec=10;
	timer_now.tv_usec = 0;
	maxfd=fd;


	FD_ZERO(&rfdset);

	while(1)
	{
		FD_SET(fd,&rfdset);	
		
		vty_event (VTY_TIME, vty);		

		timer_now.tv_sec=0;
		timer_now.tv_usec = 0;
		if(timer_now.tv_sec>0)
			timer_wait= &timer_now;
		else
			timer_wait= NULL;
		ret=select(maxfd+1,&rfdset,NULL,NULL,timer_wait);
		if(ret == 0)
			break;

		/*process socket data*/
		if(FD_ISSET(fd,&rfdset))
		{
			if((nbytes = vty_recv(fd,buf,sizeof(buf))) <= 0)
			{
				vty_out(vty,"%s  %%Server has closed connection.%s",VTY_NEWLINE,VTY_NEWLINE);
				break;
			}
			vty_fast_out(vty,0,"Rcv packet:%d bytes\r\n",nbytes);
		}
	}
	close(fd);
	
	
	
	
	/*for ts telnet client*/
	fd = socket (AF_PACKET, SOCK_DGRAM, htons(proto));
	if(fd==ERROR)
	{
		vty_out(vty,"socket error.%s",VTY_NEWLINE);
		return -1;
	}

	memset(&dstAddr,0,sizeof(dstAddr));
	
	timer_now.tv_sec=10;
	timer_now.tv_usec = 0;
	maxfd=fd;


	FD_ZERO(&rfdset);

	while(1)
	{
		FD_SET(fd,&rfdset);	
		
		vty_event (VTY_TIME, vty);		

		timer_now.tv_sec=0;
		timer_now.tv_usec = 0;
		if(timer_now.tv_sec>0)
			timer_wait= &timer_now;
		else
			timer_wait= NULL;
		ret=select(maxfd+1,&rfdset,NULL,NULL,timer_wait);
		if(ret == 0)
			break;

		/*process socket data*/
		if(FD_ISSET(fd,&rfdset))
		{
			if((nbytes = vty_recv(fd,buf,sizeof(buf))) <= 0)
			{
				vty_out(vty,"%s  %%Server has closed connection.%s",VTY_NEWLINE,VTY_NEWLINE);
				break;
			}
			vty_fast_out(vty,0,"Rcv packet:%d bytes\r\n",nbytes);
		}
	}
	close(fd);
	
	
	/*for ts telnet client*/
	fd = socket (AF_PACKET, SOCK_RAW, htons(proto));
	if(fd==ERROR)
	{
		vty_out(vty,"socket error.%s",VTY_NEWLINE);
		return -1;
	}

	memset(&dstAddr,0,sizeof(dstAddr));
	
	timer_now.tv_sec=10;
	timer_now.tv_usec = 0;
	maxfd=fd;


	FD_ZERO(&rfdset);

	while(1)
	{
		FD_SET(fd,&rfdset);	
		
		vty_event (VTY_TIME, vty);		

		timer_now.tv_sec=0;
		timer_now.tv_usec = 0;
		if(timer_now.tv_sec>0)
			timer_wait= &timer_now;
		else
			timer_wait= NULL;
		ret=select(maxfd+1,&rfdset,NULL,NULL,timer_wait);
		if(ret == 0)
			break;

		/*process socket data*/
		if(FD_ISSET(fd,&rfdset))
		{
			if((nbytes = vty_recv(fd,buf,sizeof(buf))) <= 0)
			{
				vty_out(vty,"%s  %%Server has closed connection.%s",VTY_NEWLINE,VTY_NEWLINE);
				break;
			}
			vty_fast_out(vty,0,"Rcv packet:%d bytes\r\n",nbytes);
		}
	}
	close(fd);
}





