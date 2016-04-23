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

#include <ouroboros/logs.h>
#include <ouroboros/common.h>
#include <ouroboros/sockets.h>
#include <ouroboros/utils.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>

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
                return -1;
        }

        if (listen(sockfd, 0)) {
                LOG_ERR("Failed to listen to socket");
                return -1;
        }

        return sockfd;
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

        buf.size = irm_msg__get_packed_size(msg);
        if (buf.size == 0) {
                close(sockfd);
                return NULL;
        }

        buf.data = malloc(IRM_MSG_BUF_SIZE);
        if (buf.data == NULL) {
                close(sockfd);
                return NULL;
        }

        irm_msg__pack(msg, buf.data);

        if (write(sockfd, buf.data, buf.size) == -1) {
                free(buf.data);
                close(sockfd);
                return NULL;
        }

        count = read(sockfd, buf.data, IRM_MSG_BUF_SIZE);
        if (count <= 0) {
                free(buf.data);
                close(sockfd);
                return NULL;
        }

        recv_msg = irm_msg__unpack(NULL, count, buf.data);
        if (recv_msg == NULL) {
                free(buf.data);
                close(sockfd);
                return NULL;
        }

        free(buf.data);
        close(sockfd);
        return recv_msg;
}


char * ipcp_sock_path(pid_t pid)
{
        char * full_name = NULL;
        char * pid_string = NULL;
        size_t len = 0;
        char * delim = "-";

        len = n_digits(pid);
        pid_string = malloc(len + 1);
        if (pid_string == NULL)
                return NULL;

        sprintf(pid_string, "%d", pid);

        len += strlen(IPCP_SOCK_PATH_PREFIX);
        len += strlen(delim);
        full_name = malloc(len + 1);
        if (full_name == NULL) {
                free(pid_string);
                return NULL;
        }

        strcpy(full_name, IPCP_SOCK_PATH_PREFIX);
        strcat(full_name, delim);
        strcat(full_name, pid_string);

        free(pid_string);

        return full_name;
}
