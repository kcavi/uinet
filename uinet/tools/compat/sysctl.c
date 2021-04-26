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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
//#include <rte_malloc.h>
#include <errno.h>
#include <linux/un.h>
#include <sys/ipc.h>
#include <sys/shm.h>


#include "ff_ipc.h"


struct ff_msg *msg = NULL;
int cmdSocket;

int sysctl(int *name, unsigned namelen, void *old,
    size_t *oldlenp, const void *new, size_t newlen)
{
    struct ff_msg  *retmsg = NULL;
    char *extra_buf = NULL;
    size_t total_len;
	char buffer[10240];

	int shm_id;
	struct sockaddr_un cmdAddr;

    if (old != NULL && oldlenp == NULL) {
        errno = EINVAL;
        return -1;
    }

	shm_id = shmget(FSTACK_SHM_KEY,20480,IPC_CREAT|0600); 
	if(shm_id==-1)
    {
        perror("shmget error");
        return -1;
    }
	//printf("shm_id = %d \n",shm_id);

	//printf("name =%s namelen=%d old =%p new=%p \n",name ,namelen, old,new);
	//printf("oldlenp =%p newlen=%d \n",oldlenp ,newlen);

#if 0
    //msg = ff_ipc_msg_alloc();
	msg = malloc(10240);
    if (msg == NULL) {
        errno = ENOMEM;
        return -1;
    }
#endif

	char *share_addr = (char *)0x7ffff1000000;
	if(msg == NULL)
	{
		msg = (struct ff_msg *)shmat(shm_id,share_addr,0);
		if( (void *) -1== msg)
		{
			perror("shmat error");
			return -1;
		}
	}


	//printf("msg = %p \n",msg);

	memset(msg,0,10240);

	msg->buf_len = 10112;
	msg->buf_addr = (char *)(msg + 1);

	cmdSocket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(0 >= cmdSocket)
	{
		perror("create cmdSock failed!");
		return -1; 	
	}


	unlink("/tmp/fstack_client");
	bzero((char *)(&cmdAddr), sizeof(cmdAddr));
	cmdAddr.sun_family = AF_UNIX;
	strcpy(cmdAddr.sun_path, "/tmp/fstack_client");
	if(0 != bind(cmdSocket, (struct sockaddr *)(&cmdAddr), sizeof(cmdAddr))) 
	{
		perror("bind failed!");
		return -1;
	}
	
	bzero((char *)(&cmdAddr), sizeof(cmdAddr));
	cmdAddr.sun_family = AF_UNIX;
	strcpy(cmdAddr.sun_path, FSTACK_SOCKET_PATH);

    size_t oldlen = 0;
    if (old && oldlenp) {
        oldlen = *oldlenp;
    }

    total_len = namelen + oldlen + newlen;
	//printf("total_len=%d\n",total_len);
	
    if (total_len > msg->buf_len) {
        extra_buf = malloc(total_len);
        if (extra_buf == NULL) {
            errno = ENOMEM;
            //free(msg);
            return -1;
        }
        msg->buf_addr = extra_buf;
        msg->buf_len = total_len; 
    }

    char *buf_addr = msg->buf_addr;

    msg->msg_type = FF_SYSCTL;
    msg->sysctl.name = (int *)buf_addr;
    msg->sysctl.namelen = namelen;
    memcpy(msg->sysctl.name, name, namelen*sizeof(int));

    buf_addr += namelen*sizeof(int);

    if (new != NULL && newlen != 0) {
        msg->sysctl.new = buf_addr;
        msg->sysctl.newlen = newlen;
        memcpy(msg->sysctl.new, new, newlen);

        buf_addr += newlen;
    } else {
        msg->sysctl.new = NULL;
        msg->sysctl.newlen = 0;
    }

    if (oldlenp != NULL) {
        msg->sysctl.oldlenp = (size_t *)buf_addr;
        memcpy(msg->sysctl.oldlenp, oldlenp, sizeof(size_t));
        buf_addr += sizeof(size_t);

        if (old != NULL) {
            msg->sysctl.old = (void *)buf_addr;
            memcpy(msg->sysctl.old, old, *oldlenp);
            buf_addr += *oldlenp;
        } else {
            msg->sysctl.old = NULL;
        }
    } else {
        msg->sysctl.oldlenp = NULL;
        msg->sysctl.old = NULL;
    }

	//printf("msg->sysctl.oldlenp=%p\n", msg->sysctl.oldlenp);
	//printf("msg->sysctl.newlen=%d\n",  msg->sysctl.newlen);

    int ret = sendto(cmdSocket,msg, 10112, 0,
				(struct sockaddr *)&cmdAddr,sizeof(cmdAddr));
    if (ret < 0) {
        errno = EPIPE;
        //free(msg);
        if (extra_buf) {
            free(extra_buf);
        }
        return -1;
    }
   
	ret = recv(cmdSocket,buffer, 10112, 0);
    if (ret < 0) {
        errno = EPIPE;
        //free(msg);
        if (extra_buf) {
            free(extra_buf);
        }
        return -1;
    }

 	retmsg = msg;
    if (retmsg->result == 0) {
        ret = 0;
        if (oldlenp && retmsg->sysctl.oldlenp) {
            *oldlenp = *retmsg->sysctl.oldlenp;
        }

        if (old && retmsg->sysctl.old && oldlenp) {
            memcpy(old, retmsg->sysctl.old, *oldlenp);
        }
    } else {
        ret = -1;
        errno = retmsg->result;
    }

    //free(msg);
    if (extra_buf) {
        free(extra_buf);
    }

    return ret;
}
