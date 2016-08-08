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
#include <ouroboros/errno.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/common.h>
#include <ouroboros/logs.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

static void close_ptr(void * o)
{
        close(*((int *) o));
}

static ipcp_msg_t * send_recv_ipcp_msg(pid_t api,
                                       ipcp_msg_t * msg)
{
       int sockfd = 0;
       buffer_t buf;
       char * sock_path = NULL;
       ssize_t count = 0;
       ipcp_msg_t * recv_msg = NULL;

       sock_path = ipcp_sock_path(api);
       if (sock_path == NULL)
               return NULL;

       sockfd = client_socket_open(sock_path);
       if (sockfd < 0) {
               free(sock_path);
               return NULL;
       }

       free(sock_path);

       buf.len = ipcp_msg__get_packed_size(msg);
       if (buf.len == 0) {
               close(sockfd);
               return NULL;
       }

       buf.data = malloc(IPCP_MSG_BUF_SIZE);
       if (buf.data == NULL) {
               close(sockfd);
               return NULL;
       }

       pthread_cleanup_push(close_ptr, (void *) &sockfd);
       pthread_cleanup_push((void (*)(void *)) free, (void *) buf.data);

       ipcp_msg__pack(msg, buf.data);

       if (write(sockfd, buf.data, buf.len) == -1) {
               free(buf.data);
               close(sockfd);
               return NULL;
       }

       count = read(sockfd, buf.data, IPCP_MSG_BUF_SIZE);
       if (count <= 0) {
               free(buf.data);
               close(sockfd);
               return NULL;
       }

       recv_msg = ipcp_msg__unpack(NULL, count, buf.data);
       if (recv_msg == NULL) {
               free(buf.data);
               close(sockfd);
               return NULL;
       }

       pthread_cleanup_pop(true);
       pthread_cleanup_pop(true);

       return recv_msg;
}

pid_t ipcp_create(enum ipcp_type ipcp_type)
{
        pid_t api = -1;
        char irmd_api[10];
        size_t len = 0;
        char * ipcp_dir = "/sbin/";
        char * full_name = NULL;
        char * exec_name = NULL;
        char * log_file = NULL;

        sprintf(irmd_api, "%u", getpid());

        api = fork();
        if (api == -1) {
                LOG_ERR("Failed to fork");
                return api;
        }

        if (api != 0) {
                return api;
        }

        if (ipcp_type == IPCP_NORMAL)
                exec_name = IPCP_NORMAL_EXEC;
        else if (ipcp_type == IPCP_SHIM_UDP)
                exec_name = IPCP_SHIM_UDP_EXEC;
        else if (ipcp_type == IPCP_SHIM_ETH_LLC)
                exec_name = IPCP_SHIM_ETH_LLC_EXEC;
        else if (ipcp_type == IPCP_LOCAL)
                exec_name = IPCP_LOCAL_EXEC;
        else
                exit(EXIT_FAILURE);

        len += strlen(INSTALL_PREFIX);
        len += strlen(ipcp_dir);
        len += strlen(exec_name);
        len += 1;

        full_name = malloc(len + 1);
        if (full_name == NULL) {
                LOG_ERR("Failed to malloc");
                exit(EXIT_FAILURE);
        }

        strcpy(full_name, INSTALL_PREFIX);
        strcat(full_name, ipcp_dir);
        strcat(full_name, exec_name);
        full_name[len] = '\0';

        if (logfile != NULL) {
                log_file = malloc(20);
                if (log_file == NULL) {
                        LOG_ERR("Failed to malloc.");
                        exit(EXIT_FAILURE);
                }
                sprintf(log_file, "ipcpd-%u.log", getpid());
        }

        /* log_file to be placed at the end */
        char * argv[] = {full_name,
                         irmd_api,
                         log_file,
                         0};

        char * envp[] = {0};

        execve(argv[0], &argv[0], envp);

        LOG_DBG("%s", strerror(errno));
        LOG_ERR("Failed to load IPCP daemon");
        LOG_ERR("Make sure to run the installed version");
        free(full_name);
        exit(EXIT_FAILURE);
}

int ipcp_destroy(pid_t api)
{
        int status;

        if (kill(api, SIGTERM)) {
                LOG_ERR("Failed to destroy IPCP");
                return -1;
        }

        if (waitpid(api, &status, 0) < 0) {
                LOG_ERR("Failed to destroy IPCP");
                return -1;
        }

        return 0;
}

int ipcp_bootstrap(pid_t api,
                   dif_config_msg_t * conf)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (conf == NULL)
                return -EINVAL;

        msg.code = IPCP_MSG_CODE__IPCP_BOOTSTRAP;
        msg.conf = conf;

        recv_msg = send_recv_ipcp_msg(api, &msg);
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

int ipcp_enroll(pid_t  api,
                char * dif_name)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (dif_name == NULL)
                return -EINVAL;

        msg.code     = IPCP_MSG_CODE__IPCP_ENROLL;
        msg.dif_name = dif_name;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_name_reg(pid_t  api,
                  char * name)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL)
                return -1;

        msg.code = IPCP_MSG_CODE__IPCP_NAME_REG;
        msg.name = name;

        recv_msg = send_recv_ipcp_msg(api, &msg);
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

int ipcp_name_unreg(pid_t  api,
                    char * name)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code = IPCP_MSG_CODE__IPCP_NAME_UNREG;
        msg.name = name;

        recv_msg = send_recv_ipcp_msg(api, &msg);
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

int ipcp_flow_alloc(pid_t         api,
                    int           port_id,
                    pid_t         n_api,
                    char *        dst_name,
                    char *        src_ae_name,
                    enum qos_cube qos)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        if (dst_name == NULL || src_ae_name == NULL)
                return -EINVAL;

        msg.code         = IPCP_MSG_CODE__IPCP_FLOW_ALLOC;
        msg.has_port_id  = true;
        msg.port_id      = port_id;
        msg.has_api      = true;
        msg.api          = n_api;
        msg.src_ae_name  = src_ae_name;
        msg.dst_name     = dst_name;
        msg.has_qos_cube = true;
        msg.qos_cube     = qos;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_result) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_alloc_resp(pid_t api,
                         int   port_id,
                         pid_t n_api,
                         int   response)
{
        ipcp_msg_t msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code         = IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP;
        msg.has_port_id  = true;
        msg.port_id      = port_id;
        msg.has_api      = true;
        msg.api          = n_api;
        msg.has_response = true;
        msg.response     = response;

        recv_msg = send_recv_ipcp_msg(api, &msg);
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

int ipcp_flow_req_arr(pid_t  api,
                      char * dst_name,
                      char * src_ae_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int port_id = -1;

        if (dst_name == NULL || src_ae_name == NULL)
                return -EINVAL;

        msg.code          = IRM_MSG_CODE__IPCP_FLOW_REQ_ARR;
        msg.has_api       = true;
        msg.api           = api;
        msg.dst_name      = dst_name;
        msg.ae_name       = src_ae_name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        port_id = recv_msg->port_id;
        irm_msg__free_unpacked(recv_msg, NULL);

        return port_id;
}

int ipcp_flow_alloc_reply(pid_t api,
                          int   port_id,
                          int   response)
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


int ipcp_flow_dealloc(pid_t api,
                      int   port_id)
{
        if (api != 0) {
                ipcp_msg_t msg = IPCP_MSG__INIT;
                ipcp_msg_t * recv_msg = NULL;
                int ret = -1;

                msg.code        = IPCP_MSG_CODE__IPCP_FLOW_DEALLOC;
                msg.has_port_id = true;
                msg.port_id     = port_id;

                recv_msg = send_recv_ipcp_msg(api, &msg);
                if (recv_msg == NULL)
                        return 0;

                if (recv_msg->has_result == false) {
                        ipcp_msg__free_unpacked(recv_msg, NULL);
                        return 0;
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
                        return 0;

                if (recv_msg->has_result == false) {
                        irm_msg__free_unpacked(recv_msg, NULL);
                        return 0;
                }

                ret = recv_msg->result;
                irm_msg__free_unpacked(recv_msg, NULL);

                return ret;
        }
}
