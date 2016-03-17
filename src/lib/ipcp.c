/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API to instruct IPCPs
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

#define OUROBOROS_PREFIX "lib-ipcp"

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199506L
#endif

#include <ouroboros/ipcp.h>
#include <ouroboros/common.h>
#include <ouroboros/logs.h>
#include <ouroboros/config.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

static int send_ipcp_msg(pid_t pid,
                         struct ipcp_msg * msg)
{
       int sockfd = 0;
       buffer_t * buf = NULL;
       char * sock_path;

       sock_path = ipcp_sock_path(pid);
       if (sock_path == NULL)
               return -1;

       sockfd = client_socket_open(sock_path);
       if (sockfd < 0) {
               free(sock_path);
               return -1;
       }

       buf = serialize_ipcp_msg(msg);
       if (buf == NULL) {
               free(sock_path);
               close(sockfd);
               return -1;
       }

       if (write(sockfd, buf->data, buf->size) == -1) {
               free(sock_path);
               free(buf->data);
               free(buf);
               close(sockfd);
               return -1;
       }

       free(buf->data);
       free(buf);

       close(sockfd);
       return 0;
}

pid_t ipcp_create(rina_name_t name,
                  char * ipcp_type)
{
        pid_t pid = 0;
        char * api_id = NULL;
        char * aei_id = NULL;
        size_t len = 0;
        char * ipcp_dir = "bin/ipcpd";
        char * full_name = NULL;

        if (ipcp_type == NULL)
                return -1;

        pid = fork();
        if (pid == -1) {
                LOG_ERR("Failed to fork");
                return pid;
        }

        if (pid != 0) {
                return pid;
        }

        api_id = malloc(n_digits(name.api_id) + 1);
        if (!api_id) {
                LOG_ERR("Failed to malloc");
                exit(-1);
        }
        sprintf(api_id, "%d", name.api_id);

        aei_id = malloc(n_digits(name.aei_id) + 1);
        if (!aei_id) {
                LOG_ERR("Failed to malloc");
                exit(-1);
        }
        sprintf(aei_id, "%d", name.aei_id);

        len += strlen(INSTALL_DIR);
        len += strlen(ipcp_dir);
        len += 2;
        full_name = malloc(len);
        if (!full_name) {
                LOG_ERR("Failed to malloc");
                exit(-1);
        }

        strcpy(full_name, INSTALL_DIR);
        strcat(full_name, "/");
        strcat(full_name, ipcp_dir);

        char * argv[] = {full_name,
                         name.ap_name, api_id,
                         name.ae_name, aei_id,
                         ipcp_type, 0};

        char * envp[] = {0};

        execve(argv[0], &argv[0], envp);

        LOG_DBG("%s", strerror(errno));
        LOG_ERR("Failed to load IPCP daemon");
        LOG_ERR("Make sure to run the installed version");
        exit(-1);
}

int ipcp_destroy(pid_t pid)
{
        int status;

        if (kill(pid, SIGTERM)) {
                LOG_ERR("Failed to destroy IPCP");
                return -1;
        }

        if (waitpid(pid, &status, 0) < 0) {
                LOG_ERR("Failed to destroy IPCP");
                return -1;
        }

        return 0;
}

int ipcp_reg(pid_t pid,
             char ** difs,
             size_t difs_size)
{
        struct ipcp_msg msg;

        if (difs == NULL)
                return -1;

        msg.code = IPCP_REG;
        msg.difs = difs;
        msg.difs_size = difs_size;

        if (send_ipcp_msg(pid, &msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int ipcp_unreg(pid_t pid,
               char ** difs,
               size_t difs_size)
{
        struct ipcp_msg msg;

        if (difs == NULL)
                return -1;

        msg.code = IPCP_UNREG;
        msg.difs = difs;
        msg.difs_size = difs_size;

        if (send_ipcp_msg(pid, &msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int ipcp_bootstrap(pid_t pid,
                   struct dif_config conf)
{
        struct ipcp_msg msg;

        msg.code = IPCP_BOOTSTRAP;
        msg.conf = &conf;

        if (send_ipcp_msg(pid, &msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int ipcp_enroll(pid_t pid,
                char * dif_name,
                rina_name_t member,
                char ** n_1_difs,
                ssize_t n_1_difs_size)
{
        struct ipcp_msg msg;

        if (n_1_difs == NULL)
                return -1;

        if (dif_name == NULL)
                return -1;

        msg.code = IPCP_ENROLL;
        msg.dif_name = dif_name;
        msg.member = &member;
        msg.difs = n_1_difs;
        msg.difs_size = n_1_difs_size;

        if (send_ipcp_msg(pid, &msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}
