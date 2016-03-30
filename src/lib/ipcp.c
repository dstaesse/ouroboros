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

#include <ouroboros/config.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/common.h>
#include <ouroboros/logs.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

static int send_ipcp_msg(pid_t pid,
                         ipcp_msg_t * msg)
{
       int sockfd = 0;
       buffer_t buf;
       char * sock_path;

       sock_path = ipcp_sock_path(pid);
       if (sock_path == NULL)
               return -1;

       sockfd = client_socket_open(sock_path);
       if (sockfd < 0) {
               free(sock_path);
               return -1;
       }

       buf.size = ipcp_msg__get_packed_size(msg);
       if (buf.size == 0) {
               close(sockfd);
               free(sock_path);
               return -1;
       }

       buf.data = malloc(buf.size);
       if (buf.data == NULL) {
               close(sockfd);
               free(sock_path);
               return -ENOMEM;
       }

       ipcp_msg__pack(msg, buf.data);

       if (write(sockfd, buf.data, buf.size) == -1) {
               free(sock_path);
               free(buf.data);
               close(sockfd);
               return -1;
       }

       free(buf.data);
       free(sock_path);
       close(sockfd);
       return 0;
}

pid_t ipcp_create(instance_name_t * api,
                  char *            ipcp_type)
{
        pid_t pid = 0;
        char * api_id = NULL;
        size_t len = 0;
        char * ipcp_dir = "bin/ipcpd";
        char * full_name = NULL;

        if (ipcp_type == NULL)
                return -1;

        LOG_DBG("%lu", _POSIX_C_SOURCE);

        pid = fork();
        if (pid == -1) {
                LOG_ERR("Failed to fork");
                return pid;
        }

        if (pid != 0) {
                return pid;
        }

        api_id = malloc(n_digits(api->id) + 1);
        if (!api_id) {
                LOG_ERR("Failed to malloc");
                exit(EXIT_FAILURE);
        }
        sprintf(api_id, "%d", api->id);

        len += strlen(INSTALL_DIR);
        len += strlen(ipcp_dir);
        len += 2;
        full_name = malloc(len);
        if (full_name == NULL) {
                LOG_ERR("Failed to malloc");
                free(api_id);
                exit(EXIT_FAILURE);
        }

        strcpy(full_name, INSTALL_DIR);
        strcat(full_name, "/");
        strcat(full_name, ipcp_dir);

        char * argv[] = {full_name,
                         api->name, api_id,
                         ipcp_type, 0};

        char * envp[] = {0};

        execve(argv[0], &argv[0], envp);

        LOG_DBG("%s", strerror(errno));
        LOG_ERR("Failed to load IPCP daemon");
        LOG_ERR("Make sure to run the installed version");
        free(api_id);
        free(full_name);
        exit(EXIT_FAILURE);
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
        ipcp_msg_t msg = IPCP_MSG__INIT;

        if (difs == NULL ||
            difs_size == 0 ||
            difs[0] == NULL)
                return -EINVAL;

        msg.code = IPCP_MSG_CODE__IPCP_REG;
        msg.dif_name = difs;
        msg.n_dif_name = difs_size;

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
        ipcp_msg_t msg = IPCP_MSG__INIT;

        if (difs == NULL ||
            difs_size == 0 ||
            difs[0] == NULL)
                return -EINVAL;

        msg.code = IPCP_MSG_CODE__IPCP_UNREG;
        msg.dif_name = difs;
        msg.n_dif_name = difs_size;

        if (send_ipcp_msg(pid, &msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int ipcp_bootstrap(pid_t pid,
                   struct dif_config * conf)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;

        msg.code = IPCP_MSG_CODE__IPCP_BOOTSTRAP;

        if (send_ipcp_msg(pid, &msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int ipcp_enroll(pid_t pid,
                char * dif_name,
                char * member_name,
                char ** n_1_difs,
                ssize_t n_1_difs_size)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;

        if (n_1_difs == NULL ||
            n_1_difs_size == 0 ||
            n_1_difs[0] == NULL ||
            dif_name == NULL ||
            member_name == NULL)
                return -EINVAL;

        msg.code = IPCP_MSG_CODE__IPCP_ENROLL;
        msg.dif_name = malloc(sizeof(*(msg.dif_name)));
        if (msg.dif_name == NULL) {
                LOG_ERR("Failed to malloc");
                return -1;
        }
        msg.dif_name[0] = dif_name;
        msg.ap_name = member_name;
        msg.n_1_dif_name = n_1_difs;
        msg.n_n_1_dif_name = n_1_difs_size;

        if (send_ipcp_msg(pid, &msg)) {
                LOG_ERR("Failed to send message to daemon");
                free(msg.dif_name);
                return -1;
        }

        free(msg.dif_name);
        return 0;
}
