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

static ipcp_msg_t * send_recv_ipcp_msg(pid_t pid,
                                       ipcp_msg_t * msg)
{
       int sockfd = 0;
       buffer_t buf;
       char * sock_path = NULL;
       ssize_t count = 0;
       ipcp_msg_t * recv_msg = NULL;

       sock_path = ipcp_sock_path(pid);
       if (sock_path == NULL)
               return NULL;

       sockfd = client_socket_open(sock_path);
       if (sockfd < 0) {
               free(sock_path);
               return NULL;
       }

       buf.size = ipcp_msg__get_packed_size(msg);
       if (buf.size == 0) {
               close(sockfd);
               free(sock_path);
               return NULL;
       }

       buf.data = malloc(IPCP_MSG_BUF_SIZE);
       if (buf.data == NULL) {
               close(sockfd);
               free(sock_path);
               return NULL;
       }

       ipcp_msg__pack(msg, buf.data);

       if (write(sockfd, buf.data, buf.size) == -1) {
               free(sock_path);
               free(buf.data);
               close(sockfd);
               return NULL;
       }

       count = read(sockfd, buf.data, IPCP_MSG_BUF_SIZE);
       if (count <= 0) {
               free(sock_path);
               free(buf.data);
               close(sockfd);
               return NULL;
       }

       recv_msg = ipcp_msg__unpack(NULL, count, buf.data);
       if (recv_msg == NULL) {
               free(sock_path);
               free(buf.data);
               close(sockfd);
               return NULL;
       }

       free(buf.data);
       free(sock_path);
       close(sockfd);
       return recv_msg;
}

pid_t ipcp_create(char *         ipcp_name,
                  enum ipcp_type ipcp_type)
{
        pid_t pid = 0;
        char irmd_pid[10];
        size_t len = 0;
        char * ipcp_dir = "bin";
        char * full_name = NULL;
        char * exec_name = NULL;

        sprintf (irmd_pid, "%u", getpid());

        pid = fork();
        if (pid == -1) {
                LOG_ERR("Failed to fork");
                return pid;
        }

        if (pid != 0) {
                return pid;
        }

        if (ipcp_type == IPCP_NORMAL)
                exec_name = IPCP_NORMAL_EXEC;
        else if (ipcp_type == IPCP_SHIM_UDP)
                exec_name = IPCP_SHIM_UDP_EXEC;
        else
                exit(EXIT_FAILURE);

        len += strlen(INSTALL_DIR);
        len += strlen(ipcp_dir);
        len += strlen(exec_name);
        len += 3;

        full_name = malloc(len + 1);
        if (full_name == NULL) {
                LOG_ERR("Failed to malloc");
                exit(EXIT_FAILURE);
        }

        strcpy(full_name, INSTALL_DIR);
        strcat(full_name, "/");
        strcat(full_name, ipcp_dir);
        strcat(full_name, "/");
        strcat(full_name, exec_name);
        full_name[len] = '\0';

        LOG_DBG("Full name is %s", full_name);

        char * argv[] = {full_name,
                         irmd_pid,
                         ipcp_name,
                         0};

        char * envp[] = {0};

        execve(argv[0], &argv[0], envp);

        LOG_DBG("%s", strerror(errno));
        LOG_ERR("Failed to load IPCP daemon");
        LOG_ERR("Make sure to run the installed version");
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

int ipcp_reg(pid_t   pid,
             char ** dif_names,
             size_t  len)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (dif_names == NULL ||
            len == 0 ||
            dif_names[0] == NULL)
                return -EINVAL;

        msg.code       = IPCP_MSG_CODE__IPCP_REG;
        msg.dif_names  = dif_names;
        msg.len        = len;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_unreg(pid_t pid,
               char ** dif_names,
               size_t len)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (dif_names == NULL ||
            len == 0 ||
            dif_names[0] == NULL)
                return -EINVAL;

        msg.code       = IPCP_MSG_CODE__IPCP_UNREG;
        msg.dif_names  = dif_names;
        msg.len        = len;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}


int ipcp_bootstrap(pid_t pid,
                   dif_config_msg_t * conf)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (conf == NULL)
                return -EINVAL;

        msg.code = IPCP_MSG_CODE__IPCP_BOOTSTRAP;
        msg.conf = conf;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_enroll(pid_t pid,
                char * member_name,
                char * n_1_dif)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (n_1_dif == NULL || member_name == NULL)
                return -EINVAL;

        msg.code        = IPCP_MSG_CODE__IPCP_ENROLL;
        msg.member_name = malloc(sizeof(*(msg.member_name)));
        if (msg.member_name == NULL) {
                LOG_ERR("Failed to malloc.");
                return -1;
        }
        msg.n_1_dif     = n_1_dif;
        msg.member_name = member_name;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL) {
                free(msg.member_name);
                return -1;
        }

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                free(msg.member_name);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);
        free(msg.member_name);

        return ret;
}

int ipcp_name_reg(pid_t    pid,
                  char *   name)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL)
                return -1;

        msg.code          = IPCP_MSG_CODE__IPCP_NAME_REG;
        msg.name          = name;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_name_unreg(pid_t  pid,
                    char * name)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code = IPCP_MSG_CODE__IPCP_NAME_UNREG;
        msg.name = name;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_alloc(pid_t             pid,
                    uint32_t          port_id,
                    char *            dst_name,
                    char *            src_ap_name,
                    char *            src_ae_name,
                    struct qos_spec * qos)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (dst_name == NULL || src_ap_name == NULL || src_ae_name == NULL)
                return -EINVAL;

        msg.code        = IPCP_MSG_CODE__IPCP_FLOW_ALLOC;
        msg.src_ap_name = src_ap_name;
        msg.src_ae_name = src_ae_name;
        msg.dst_name    = dst_name;
        msg.port_id     = port_id;
        msg.has_port_id = true;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_alloc_resp(pid_t    pid,
                         uint32_t port_id,
                         int      result)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code        = IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP;
        msg.has_port_id = true;
        msg.port_id     = port_id;
        msg.has_result  = true;
        msg.result      = result;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_req_arr(pid_t    pid,
                      char *   dst_name,
                      char *   src_ap_name,
                      char *   src_ae_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int fd = -1;

        if (src_ap_name == NULL || src_ae_name == NULL)
                return -EINVAL;

        msg.code          = IRM_MSG_CODE__IPCP_FLOW_REQ_ARR;
        msg.dst_name      = dst_name;
        msg.ap_name       = src_ap_name;
        msg.ae_name       = src_ae_name;
        msg.pid           = pid;
        msg.has_pid       = true;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_fd == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        fd = recv_msg->fd;
        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int ipcp_flow_alloc_reply(pid_t    pid,
                          uint32_t port_id,
                          int      response)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code         = IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY;
        msg.port_id      = port_id;
        msg.has_port_id  = true;
        msg.response     = response;
        msg.has_response = true;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}


int ipcp_flow_dealloc(pid_t    pid,
                      uint32_t port_id)
{
        if (pid != 0) {
                ipcp_msg_t msg = IPCP_MSG__INIT;
                ipcp_msg_t * recv_msg = NULL;
                int ret = -1;

                msg.code        = IPCP_MSG_CODE__IPCP_FLOW_DEALLOC;
                msg.has_port_id = true;
                msg.port_id     = port_id;

                recv_msg = send_recv_ipcp_msg(pid, &msg);
                if (recv_msg == NULL)
                        return -1;

                if (recv_msg->has_result == false) {
                        ipcp_msg__free_unpacked(recv_msg, NULL);
                        return -1;
                }

                ret = recv_msg->result;
                ipcp_msg__free_unpacked(recv_msg, NULL);

                return ret;
        } else {
                irm_msg_t msg = IRM_MSG__INIT;
                irm_msg_t * recv_msg = NULL;
                int ret = -1;

                msg.code        = IRM_MSG_CODE__IPCP_FLOW_DEALLOC;
                msg.has_port_id = true;
                msg.port_id     = port_id;

                recv_msg = send_recv_irm_msg(&msg);
                if (recv_msg == NULL)
                        return -1;

                if (recv_msg->has_result == false) {
                        irm_msg__free_unpacked(recv_msg, NULL);
                        return -1;
                }

                ret = recv_msg->result;
                irm_msg__free_unpacked(recv_msg, NULL);

                return ret;
        }
}
