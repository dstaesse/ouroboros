/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * The sockets layer to communicate between daemons
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#include <ouroboros/errno.h>
#include <ouroboros/sockets.h>
#include <ouroboros/utils.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

int client_socket_open(char * file_name)
{
        int sockfd;
        struct sockaddr_un serv_addr;

        sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (sockfd < 0)
                return -1;

        serv_addr.sun_family = AF_UNIX;
        sprintf(serv_addr.sun_path, "%s", file_name);

        if (connect(sockfd,
                    (struct sockaddr *) &serv_addr,
                    sizeof(serv_addr))) {
                close(sockfd);
                return -1;
        }

        return sockfd;
}

int server_socket_open(char * file_name)
{
        int sockfd;
        struct sockaddr_un serv_addr;

        if (access(file_name, F_OK) != -1) {
                /* File exists */
                if (unlink(file_name))
                        return -1;
        }

        sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (sockfd < 0)
                return -1;

        serv_addr.sun_family = AF_UNIX;
        sprintf(serv_addr.sun_path, "%s", file_name);

        if (bind(sockfd,
                 (struct sockaddr *) &serv_addr,
                 sizeof(serv_addr))) {
                close(sockfd);
                return -1;
        }

        if (listen(sockfd, 0)) {
                close(sockfd);
                return -1;
        }

        return sockfd;
}

static void close_ptr(void * o)
{
        close(*(int *) o);
}

irm_msg_t * send_recv_irm_msg(irm_msg_t * msg)
{
        int         sockfd;
        uint8_t     buf[IRM_MSG_BUF_SIZE];
        ssize_t     len;
        irm_msg_t * recv_msg = NULL;

        sockfd = client_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return NULL;

        len = irm_msg__get_packed_size(msg);
        if (len == 0) {
                close(sockfd);
                return NULL;
        }

        pthread_cleanup_push(close_ptr, &sockfd);

        irm_msg__pack(msg, buf);

        if (write(sockfd, buf, len) != -1)
                len = read(sockfd, buf, IRM_MSG_BUF_SIZE);

        if (len > 0)
                recv_msg = irm_msg__unpack(NULL, len, buf);

        pthread_cleanup_pop(true);

        return recv_msg;
}

char * ipcp_sock_path(pid_t pid)
{
        char * full_name = NULL;
        char * pid_string = NULL;
        size_t len = 0;
        char * delim = "_";

        len = n_digits(pid);
        pid_string = malloc(len + 1);
        if (pid_string == NULL)
                return NULL;

        sprintf(pid_string, "%d", pid);

        len += strlen(IPCP_SOCK_PATH_PREFIX);
        len += strlen(delim);
        len += strlen(SOCK_PATH_SUFFIX);

        full_name = malloc(len + 1);
        if (full_name == NULL) {
                free(pid_string);
                return NULL;
        }

        strcpy(full_name, IPCP_SOCK_PATH_PREFIX);
        strcat(full_name, delim);
        strcat(full_name, pid_string);
        strcat(full_name, SOCK_PATH_SUFFIX);

        free(pid_string);

        return full_name;
}
