/*
 * Ouroboros - Copyright (C) 2016
 *
 * The sockets layer to communicate between daemons
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "libouroboros-sockets"

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/sockets.h>
#include <ouroboros/utils.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

int client_socket_open(char * file_name)
{
        int sockfd;
        struct sockaddr_un serv_addr;

        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd < 0) {
                LOG_ERR("Failed to open socket");
                return -1;
        }

        serv_addr.sun_family = AF_UNIX;
        sprintf(serv_addr.sun_path, "%s", file_name);

        if (connect(sockfd,
                    (struct sockaddr *) &serv_addr,
                    sizeof(serv_addr))) {
                LOG_ERR("Failed to connect to daemon");
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
                if (unlink(file_name)) {
                        LOG_ERR("Failed to unlink filename: %s",
                                strerror(errno));
                        return -1;
                }
        }

        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd < 0) {
                LOG_ERR("Failed to open socket");
                return -1;
        }

        serv_addr.sun_family = AF_UNIX;
        sprintf(serv_addr.sun_path, "%s", file_name);

        if (bind(sockfd,
                 (struct sockaddr *) &serv_addr,
                 sizeof(serv_addr))) {
                LOG_ERR("Failed to bind socket");
                close(sockfd);
                return -1;
        }

        if (listen(sockfd, 0)) {
                LOG_ERR("Failed to listen to socket");
                close(sockfd);
                return -1;
        }

        return sockfd;
}

static void close_ptr(void * o)
{
        close(*(int *) o);
}

static irm_msg_t * send_recv_irm_msg_timed(irm_msg_t * msg, bool timed)
{
        int sockfd;
        buffer_t buf;
        ssize_t count = 0;
        irm_msg_t * recv_msg = NULL;
        struct timeval tv = {(SOCKET_TIMEOUT / 1000),
                             (SOCKET_TIMEOUT % 1000) * 1000};

        sockfd = client_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return NULL;

        if (timed)
                if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                               (void *) &tv, sizeof(tv)))
                        LOG_WARN("Failed to set timeout on socket.");

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

void send_irm_msg(irm_msg_t * msg)
{
        int sockfd;
        buffer_t buf;

        sockfd = client_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return;

        buf.len = irm_msg__get_packed_size(msg);
        if (buf.len == 0) {
                close(sockfd);
                return;
        }

        buf.data = malloc(buf.len);
        if (buf.data == NULL) {
                close(sockfd);
                return;
        }

        pthread_cleanup_push(close_ptr, &sockfd);
        pthread_cleanup_push((void (*)(void *)) free, (void *) buf.data);

        irm_msg__pack(msg, buf.data);

        if (write(sockfd, buf.data, buf.len) < 0)
                return;

        pthread_cleanup_pop(true);
        pthread_cleanup_pop(true);
}

irm_msg_t * send_recv_irm_msg(irm_msg_t * msg)
{ return send_recv_irm_msg_timed(msg, true); }

irm_msg_t * send_recv_irm_msg_b(irm_msg_t * msg)
{ return send_recv_irm_msg_timed(msg, false); }

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
