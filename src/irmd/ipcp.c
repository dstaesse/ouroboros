/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The API to instruct IPCPs
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 199309L

#include "config.h"

#define OUROBOROS_PREFIX "irmd/ipcp"

#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>

#include "ipcp.h"

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>

static void close_ptr(void * o)
{
        close(*(int *) o);
}

ipcp_msg_t * send_recv_ipcp_msg(pid_t        api,
                                ipcp_msg_t * msg)
{
       int            sockfd    = 0;
       buffer_t       buf;
       char *         sock_path = NULL;
       ssize_t        count     = 0;
       ipcp_msg_t *   recv_msg  = NULL;
       struct timeval tv;

       if (kill(api, 0) < 0)
               return NULL;

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

       switch (msg->code) {
       case IPCP_MSG_CODE__IPCP_BOOTSTRAP:
               tv.tv_sec  = BOOTSTRAP_TIMEOUT / 1000;
               tv.tv_usec = (BOOTSTRAP_TIMEOUT % 1000) * 1000;
               break;
       case IPCP_MSG_CODE__IPCP_ENROLL:
               tv.tv_sec  = ENROLL_TIMEOUT / 1000;
               tv.tv_usec = (ENROLL_TIMEOUT % 1000) * 1000;
               break;
       case IPCP_MSG_CODE__IPCP_REG:
               tv.tv_sec  = REG_TIMEOUT / 1000;
               tv.tv_usec = (REG_TIMEOUT % 1000) * 1000;
               break;
       case IPCP_MSG_CODE__IPCP_QUERY:
               tv.tv_sec  = QUERY_TIMEOUT / 1000;
               tv.tv_usec = (QUERY_TIMEOUT % 1000) * 1000;
               break;
       default:
               tv.tv_sec  = SOCKET_TIMEOUT / 1000;
               tv.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;
               break;
       }

       if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                      (void *) &tv, sizeof(tv)))
               log_warn("Failed to set timeout on socket.");

       pthread_cleanup_push(close_ptr, (void *) &sockfd);
       pthread_cleanup_push((void (*)(void *)) free, (void *) buf.data);

       ipcp_msg__pack(msg, buf.data);

       if (write(sockfd, buf.data, buf.len) != -1)
               count = read(sockfd, buf.data, IPCP_MSG_BUF_SIZE);

       if (count > 0)
               recv_msg = ipcp_msg__unpack(NULL, count, buf.data);

       pthread_cleanup_pop(true);
       pthread_cleanup_pop(true);

       return recv_msg;
}

pid_t ipcp_create(const char *   name,
                  enum ipcp_type ipcp_type)
{
        pid_t  api       = -1;
        char * ipcp_dir  = "/sbin/";
        char * exec_name = NULL;
        char   irmd_api[10];
        char   full_name[256];
        char * argv[5];

        switch(ipcp_type) {
        case IPCP_NORMAL:
                exec_name = IPCP_NORMAL_EXEC;
                break;
        case IPCP_SHIM_UDP:
                exec_name = IPCP_SHIM_UDP_EXEC;
                break;
        case IPCP_SHIM_ETH_LLC:
                exec_name = IPCP_SHIM_ETH_LLC_EXEC;
                break;
        case IPCP_LOCAL:
                exec_name = IPCP_LOCAL_EXEC;
                break;
        default:
                return -1;
        }

        if (strlen(exec_name) == 0) {
                log_err("IPCP type not installed.");
                return -1;
        }

        sprintf(irmd_api, "%u", getpid());

        api = fork();
        if (api == -1) {
                log_err("Failed to fork");
                return api;
        }

        if (api != 0)
                return api;

        strcpy(full_name, INSTALL_PREFIX);
        strcat(full_name, ipcp_dir);
        strcat(full_name, exec_name);

        /* log_file to be placed at the end */
        argv[0] = full_name;
        argv[1] = irmd_api;
        argv[2] = (char *) name;
        if (log_syslog)
                argv[3] = "1";
        else
                argv[3] = NULL;

        argv[4] = NULL;

        execv(argv[0], &argv[0]);

        log_dbg("%s", strerror(errno));
        log_err("Failed to load IPCP daemon.");
        exit(EXIT_FAILURE);
}

int ipcp_destroy(pid_t api)
{
        if (kill(api, SIGTERM)) {
                log_err("Failed to destroy IPCP");
                return -1;
        }

        return 0;
}

int ipcp_bootstrap(pid_t               api,
                   ipcp_config_msg_t * conf,
                   struct dif_info   * info)
{
        ipcp_msg_t   msg      = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int          ret      = -1;

        if (conf == NULL)
                return -EINVAL;

        msg.code = IPCP_MSG_CODE__IPCP_BOOTSTRAP;
        msg.conf = conf;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL)
                return -EIPCP;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        if (ret != 0) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return ret;
        }

        if (recv_msg->dif_info == NULL) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        info->dir_hash_algo = recv_msg->dif_info->dir_hash_algo;
        strcpy(info->dif_name, recv_msg->dif_info->dif_name);

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_enroll(pid_t             api,
                const char *      dst,
                struct dif_info * info)
{
        ipcp_msg_t   msg      = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int          ret      = -1;

        if (dst == NULL)
                return -EINVAL;

        msg.code     = IPCP_MSG_CODE__IPCP_ENROLL;
        msg.dst_name = (char *) dst;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL)
                return -EIPCP;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        if (ret != 0) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return ret;
        }

        if (recv_msg->dif_info == NULL) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        info->dir_hash_algo = recv_msg->dif_info->dir_hash_algo;
        strcpy(info->dif_name, recv_msg->dif_info->dif_name);

        ipcp_msg__free_unpacked(recv_msg, NULL);

        return 0;
}

int ipcp_reg(pid_t           api,
             const uint8_t * hash,
             size_t          len)
{
        ipcp_msg_t   msg      = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int          ret      = -1;

        assert(hash);

        msg.code      = IPCP_MSG_CODE__IPCP_REG;
        msg.has_hash  = true;
        msg.hash.len  = len;
        msg.hash.data = (uint8_t *)hash;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL)
                return -EIPCP;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_unreg(pid_t           api,
               const uint8_t * hash,
               size_t          len)
{
        ipcp_msg_t   msg      = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int          ret      = -1;

        msg.code      = IPCP_MSG_CODE__IPCP_UNREG;
        msg.has_hash  = true;
        msg.hash.len  = len;
        msg.hash.data = (uint8_t *) hash;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL)
                return -EIPCP;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_query(pid_t           api,
               const uint8_t * hash,
               size_t          len)
{
        ipcp_msg_t   msg      = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int          ret      = -1;

        msg.code      = IPCP_MSG_CODE__IPCP_QUERY;
        msg.has_hash  = true;
        msg.hash.len  = len;
        msg.hash.data = (uint8_t *) hash;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL)
                return -EIPCP;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_alloc(pid_t           api,
                    int             port_id,
                    pid_t           n_api,
                    const uint8_t * dst,
                    size_t          len,
                    qoscube_t       cube)
{
        ipcp_msg_t   msg      = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int          ret      = -1;

        assert(dst);

        msg.code         = IPCP_MSG_CODE__IPCP_FLOW_ALLOC;
        msg.has_port_id  = true;
        msg.port_id      = port_id;
        msg.has_api      = true;
        msg.api          = n_api;
        msg.has_hash     = true;
        msg.hash.len     = len;
        msg.hash.data    = (uint8_t *) dst;
        msg.has_qoscube  = true;
        msg.qoscube      = cube;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL)
                return -EIPCP;

        if (!recv_msg->has_result) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
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
        ipcp_msg_t   msg      = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int          ret      = -1;

        msg.code         = IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP;
        msg.has_port_id  = true;
        msg.port_id      = port_id;
        msg.has_api      = true;
        msg.api          = n_api;
        msg.has_response = true;
        msg.response     = response;

        recv_msg = send_recv_ipcp_msg(api, &msg);
        if (recv_msg == NULL)
                return -EIPCP;

        if (recv_msg->has_result == false) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_dealloc(pid_t api,
                      int   port_id)
{
        ipcp_msg_t   msg      = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg = NULL;
        int          ret      = -1;

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
}
