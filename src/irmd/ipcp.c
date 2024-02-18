/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The API to instruct IPCPs
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#define _POSIX_C_SOURCE 200112L

#include "config.h"

#define OUROBOROS_PREFIX "irmd/ipcp"

#include <ouroboros/errno.h>
#include <ouroboros/flow.h>
#include <ouroboros/logs.h>
#include <ouroboros/sockets.h>
#include <ouroboros/time.h>
#include <ouroboros/utils.h>

#include "ipcp.h"

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>

ipcp_msg_t * send_recv_ipcp_msg(pid_t        pid,
                                ipcp_msg_t * msg)
{
        int             sockfd;
        uint8_t         buf[SOCK_BUF_SIZE];
        char *          sock_path;
        ssize_t         len;
        ipcp_msg_t *    recv_msg;
        struct timeval  tv;
        struct timespec tic;
        struct timespec toc;
        bool            dealloc = false;

        if (kill(pid, 0) < 0)
                return NULL;

        sock_path = ipcp_sock_path(pid);
        if (sock_path == NULL)
                return NULL;

        sockfd = client_socket_open(sock_path);
        if (sockfd < 0) {
                free(sock_path);
                return NULL;
        }

        free(sock_path);

        len = ipcp_msg__get_packed_size(msg);
        if (len == 0) {
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
        case IPCP_MSG_CODE__IPCP_CONNECT:
                tv.tv_sec  = CONNECT_TIMEOUT / 1000;
                tv.tv_usec = (CONNECT_TIMEOUT % 1000) * 1000;
                break;
        case IPCP_MSG_CODE__IPCP_FLOW_ALLOC:
                tv.tv_sec  = FLOW_ALLOC_TIMEOUT / 1000;
                tv.tv_usec = (FLOW_ALLOC_TIMEOUT % 1000) * 1000;
                break;
        case IPCP_MSG_CODE__IPCP_FLOW_DEALLOC:
                dealloc = true;
                tv.tv_sec  = 0; /* FIX DEALLOC: don't wait for dealloc */
                tv.tv_usec = 500;
                break;
        default:
                tv.tv_sec  = SOCKET_TIMEOUT / 1000;
                tv.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;
                break;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                        (void *) &tv, sizeof(tv)))
                log_warn("Failed to set timeout on socket.");

        pthread_cleanup_push(__cleanup_close_ptr, (void *) &sockfd);

        ipcp_msg__pack(msg, buf);

        clock_gettime(CLOCK_REALTIME, &tic);

        if (write(sockfd, buf, len) != -1)
                len = read(sockfd, buf, SOCK_BUF_SIZE);

        clock_gettime(CLOCK_REALTIME, &toc);

        pthread_cleanup_pop(true); /* close socket */

        if (len > 0)
                recv_msg = ipcp_msg__unpack(NULL, len, buf);
        else {
                if (errno == EAGAIN && !dealloc) {
                        int diff = ts_diff_ms(&tic, &toc);
                        log_warn("IPCP command timed out after %d ms.", diff);
                }
                return NULL;
        }

        return recv_msg;
}

int ipcp_bootstrap(pid_t                pid,
                   struct ipcp_config * conf,
                   struct layer_info *  info)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        if (conf == NULL)
                return -EINVAL;

        msg.code = IPCP_MSG_CODE__IPCP_BOOTSTRAP;
        msg.conf = ipcp_config_s_to_msg(conf);

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        ipcp_config_msg__free_unpacked(msg.conf, NULL);
        if (recv_msg == NULL)
                return -EIPCP;

        if (!recv_msg->has_result) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        if (ret != 0) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return ret;
        }

        if (recv_msg->layer_info == NULL) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        info->dir_hash_algo = recv_msg->layer_info->dir_hash_algo;
        strcpy(info->name, recv_msg->layer_info->name);

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_enroll(pid_t               pid,
                const char *        dst,
                struct layer_info * info)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        if (dst == NULL)
                return -EINVAL;

        msg.code = IPCP_MSG_CODE__IPCP_ENROLL;
        msg.dst  = (char *) dst;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return -EIPCP;

        if (!recv_msg->has_result) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        if (ret != 0) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return ret;
        }

        if (recv_msg->layer_info == NULL) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        info->dir_hash_algo = recv_msg->layer_info->dir_hash_algo;
        strcpy(info->name, recv_msg->layer_info->name);

        ipcp_msg__free_unpacked(recv_msg, NULL);

        return 0;
}

int ipcp_connect(pid_t        pid,
                 const char * dst,
                 const char * component,
                 qosspec_t    qs)
{
        ipcp_msg_t    msg = IPCP_MSG__INIT;
        ipcp_msg_t *  recv_msg;
        int           ret;

        msg.code    = IPCP_MSG_CODE__IPCP_CONNECT;
        msg.dst     = (char *) dst;
        msg.comp    = (char *) component;
        msg.has_pid = true;
        msg.pid     = pid;
        msg.qosspec = qos_spec_s_to_msg(&qs);

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        free(msg.qosspec);
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

int ipcp_disconnect(pid_t        pid,
                    const char * dst,
                    const char * component)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        msg.code    = IPCP_MSG_CODE__IPCP_DISCONNECT;
        msg.dst     = (char *) dst;
        msg.comp    = (char *) component;
        msg.has_pid = true;
        msg.pid     = pid;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
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

int ipcp_reg(pid_t          pid,
             const buffer_t hash)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        msg.code      = IPCP_MSG_CODE__IPCP_REG;
        msg.has_hash  = true;
        msg.hash.data = (uint8_t *) hash.data;
        msg.hash.len  = hash.len;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
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

int ipcp_unreg(pid_t          pid,
               const buffer_t hash)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        msg.code      = IPCP_MSG_CODE__IPCP_UNREG;
        msg.has_hash  = true;
        msg.hash.data = (uint8_t *) hash.data;
        msg.hash.len  = hash.len;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
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

int ipcp_query(pid_t          pid,
               const buffer_t dst)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        msg.code      = IPCP_MSG_CODE__IPCP_QUERY;
        msg.has_hash  = true;
        msg.hash.data = (uint8_t *) dst.data;
        msg.hash.len  = dst.len;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
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

int ipcp_flow_join(const struct flow_info * flow,
                   const buffer_t           dst)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        msg.code         = IPCP_MSG_CODE__IPCP_FLOW_JOIN;
        msg.has_flow_id  = true;
        msg.flow_id      = flow->id;
        msg.has_pid      = true;
        msg.pid          = flow->n_pid;
        msg.has_hash     = true;
        msg.hash.data    = (uint8_t *) dst.data;
        msg.hash.len     = dst.len;
        msg.has_pk       = false;

        recv_msg = send_recv_ipcp_msg(flow->n_1_pid, &msg);
        free(msg.qosspec);
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

int ipcp_flow_alloc(const struct flow_info * flow,
                    const buffer_t           dst,
                    const buffer_t           data)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        msg.code         = IPCP_MSG_CODE__IPCP_FLOW_ALLOC;
        msg.has_flow_id  = true;
        msg.flow_id      = flow->id;
        msg.has_pid      = true;
        msg.pid          = flow->n_pid;
        msg.qosspec      = qos_spec_s_to_msg(&flow->qs);
        msg.has_hash     = true;
        msg.hash.data    = (uint8_t *) dst.data;
        msg.hash.len     = dst.len;
        msg.has_pk       = true;
        msg.pk.data      = data.data;
        msg.pk.len       = data.len;

        recv_msg = send_recv_ipcp_msg(flow->n_1_pid, &msg);
        free(msg.qosspec);
        if (recv_msg == NULL) {
                log_err("Did not receive message.");
                return -EIPCP;
        }

        if (!recv_msg->has_result) {
                log_err("Message has no result");
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return -EIPCP;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_alloc_resp(const struct flow_info * flow,
                         int                      response,
                         const buffer_t           data)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        msg.code         = IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP;
        msg.has_flow_id  = true;
        msg.flow_id      = flow->id;
        msg.has_pid      = true;
        msg.pid          = flow->n_pid;
        msg.has_response = true;
        msg.response     = response;
        msg.has_pk       = true;
        msg.pk.data      = data.data;
        msg.pk.len       = data.len;

        recv_msg = send_recv_ipcp_msg(flow->n_1_pid, &msg);
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

int ipcp_flow_dealloc(pid_t  pid,
                      int    flow_id,
                      time_t timeo)
{
        ipcp_msg_t   msg = IPCP_MSG__INIT;
        ipcp_msg_t * recv_msg;
        int          ret;

        msg.code          = IPCP_MSG_CODE__IPCP_FLOW_DEALLOC;
        msg.has_flow_id   = true;
        msg.flow_id       = flow_id;
        msg.has_timeo_sec = true;
        msg.timeo_sec     = timeo;

        recv_msg = send_recv_ipcp_msg(pid, &msg);
        if (recv_msg == NULL)
                return 0;

        if (!recv_msg->has_result) {
                ipcp_msg__free_unpacked(recv_msg, NULL);
                return 0;
        }

        ret = recv_msg->result;
        ipcp_msg__free_unpacked(recv_msg, NULL);

        return ret;
}
