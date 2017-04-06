/*
 * Ouroboros - Copyright (C) 2016 - 2017
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
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

        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
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

        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
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
        int sockfd;
        buffer_t buf;
        ssize_t count = 0;
        irm_msg_t * recv_msg = NULL;

        sockfd = client_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return NULL;

        buf.len = irm_msg__get_packed_size(msg);
        if (buf.len == 0) {
                close(sockfd);
                return NULL;
        }

        buf.data = malloc(IRM_MSG_BUF_SIZE);
        if (buf.data == NULL) {
                close(sockfd);
                return NULL;
        }

        pthread_cleanup_push(close_ptr, &sockfd);
        pthread_cleanup_push((void (*)(void *)) free, (void *) buf.data);

        irm_msg__pack(msg, buf.data);

        if (write(sockfd, buf.data, buf.len) != -1)
                count = read(sockfd, buf.data, IRM_MSG_BUF_SIZE);

        if (count > 0)
                recv_msg = irm_msg__unpack(NULL, count, buf.data);

        pthread_cleanup_pop(true);
        pthread_cleanup_pop(true);

        return recv_msg;
}

char * ipcp_sock_path(pid_t api)
{
        char * full_name = NULL;
        char * api_string = NULL;
        size_t len = 0;
        char * delim = "_";

        len = n_digits(api);
        api_string = malloc(len + 1);
        if (api_string == NULL)
                return NULL;

        sprintf(api_string, "%d", api);

        len += strlen(IPCP_SOCK_PATH_PREFIX);
        len += strlen(delim);
        len += strlen(SOCK_PATH_SUFFIX);

        full_name = malloc(len + 1);
        if (full_name == NULL) {
                free(api_string);
                return NULL;
        }

        strcpy(full_name, IPCP_SOCK_PATH_PREFIX);
        strcat(full_name, delim);
        strcat(full_name, api_string);
        strcat(full_name, SOCK_PATH_SUFFIX);

        free(api_string);

        return full_name;
}
