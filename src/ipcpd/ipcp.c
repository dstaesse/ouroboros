/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * IPC process main loop
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "ipcpd/ipcp"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/np1_flow.h>

#include "ipcp.h"

#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>

static void * ipcp_main_loop(void * o)
{
        int     lsockfd;
        uint8_t buf[IPCP_MSG_BUF_SIZE];

        ipcp_msg_t * msg;
        ssize_t      count;
        buffer_t     buffer;
        ipcp_msg_t   ret_msg = IPCP_MSG__INIT;

        dif_config_msg_t * conf_msg;
        struct dif_config  conf;

        struct timeval ltv = {(SOCKET_TIMEOUT / 1000),
                             (SOCKET_TIMEOUT % 1000) * 1000};

        (void) o;

        while (true) {
#ifdef __FreeBSD__
                fd_set fds;
                struct timeval timeout = {(IPCP_ACCEPT_TIMEOUT / 1000),
                                          (IPCP_ACCEPT_TIMEOUT % 1000) * 1000};
#endif
                int fd = -1;

                pthread_rwlock_rdlock(&ipcpi.state_lock);

                if (ipcp_get_state() == IPCP_SHUTDOWN
                    || ipcp_get_state() == IPCP_NULL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        break;
                }

                pthread_rwlock_unlock(&ipcpi.state_lock);

                ret_msg.code = IPCP_MSG_CODE__IPCP_REPLY;
#ifdef __FreeBSD__
                FD_ZERO(&fds);
                FD_SET(ipcpi.sockfd, &fds);
                if (select(ipcpi.sockfd, &fds, NULL, NULL, &timeout) <= 0)
                        continue;
#endif
                lsockfd = accept(ipcpi.sockfd, 0, 0);
                if (lsockfd < 0)
                        continue;

                if (setsockopt(lsockfd, SOL_SOCKET, SO_RCVTIMEO,
                               (void *) &ltv, sizeof(ltv)))
                        LOG_WARN("Failed to set timeout on socket.");

                count = read(lsockfd, buf, IPCP_MSG_BUF_SIZE);
                if (count <= 0) {
                        LOG_ERR("Failed to read from socket");
                        close(lsockfd);
                        continue;
                }

                msg = ipcp_msg__unpack(NULL, count, buf);
                if (msg == NULL) {
                        close(lsockfd);
                        continue;
                }

                switch (msg->code) {
                case IPCP_MSG_CODE__IPCP_BOOTSTRAP:
                        if (ipcpi.ops->ipcp_bootstrap == NULL) {
                                LOG_ERR("Bootstrap unsupported.");
                                break;
                        }
                        conf_msg = msg->conf;
                        conf.type = conf_msg->ipcp_type;
                        conf.dif_name = conf_msg->dif_name;
                        if (conf.dif_name == NULL) {
                                ret_msg.has_result = true;
                                ret_msg.result = -1;
                                break;
                        }
                        if (conf_msg->ipcp_type == IPCP_NORMAL) {
                                conf.addr_size = conf_msg->addr_size;
                                conf.cep_id_size = conf_msg->cep_id_size;
                                conf.pdu_length_size =
                                        conf_msg->pdu_length_size;
                                conf.seqno_size = conf_msg->seqno_size;
                                conf.has_ttl = conf_msg->has_ttl;
                                conf.has_chk = conf_msg->has_chk;
                                conf.min_pdu_size = conf_msg->min_pdu_size;
                                conf.max_pdu_size = conf_msg->max_pdu_size;
                                conf.addr_auth_type = conf_msg->addr_auth_type;
                                conf.dt_gam_type = conf_msg->dt_gam_type;
                                conf.rm_gam_type = conf_msg->rm_gam_type;
                        }
                        if (conf_msg->ipcp_type == IPCP_SHIM_UDP) {
                                conf.ip_addr  = conf_msg->ip_addr;
                                conf.dns_addr = conf_msg->dns_addr;
                        }
                        if (conf_msg->ipcp_type == IPCP_SHIM_ETH_LLC)
                                conf.if_name = conf_msg->if_name;

                        ret_msg.has_result = true;
                        ret_msg.result = ipcpi.ops->ipcp_bootstrap(&conf);
                        break;
                case IPCP_MSG_CODE__IPCP_ENROLL:
                        if (ipcpi.ops->ipcp_enroll == NULL) {
                                LOG_ERR("Enroll unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result = ipcpi.ops->ipcp_enroll(msg->dif_name);

                        break;
                case IPCP_MSG_CODE__IPCP_NAME_REG:
                        if (ipcpi.ops->ipcp_name_reg == NULL) {
                                LOG_ERR("Ap_reg unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_name_reg(msg->name);
                        break;
                case IPCP_MSG_CODE__IPCP_NAME_UNREG:
                        if (ipcpi.ops->ipcp_name_unreg == NULL) {
                                LOG_ERR("Ap_unreg unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_name_unreg(msg->name);
                        break;
                case IPCP_MSG_CODE__IPCP_NAME_QUERY:
                        if (ipcpi.ops->ipcp_name_query == NULL) {
                                LOG_ERR("Ap_query unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_name_query(msg->name);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC:
                        if (ipcpi.ops->ipcp_flow_alloc == NULL) {
                                LOG_ERR("Flow_alloc unsupported.");
                                break;
                        }
                        fd = np1_flow_alloc(msg->api, msg->port_id);
                        if (fd < 0) {
                                LOG_ERR("Failed allocating fd on port_id %d.",
                                        msg->port_id);
                                ret_msg.has_result = true;
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_alloc(fd,
                                                           msg->dst_name,
                                                           msg->src_ae_name,
                                                           msg->qoscube);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP:
                        if (ipcpi.ops->ipcp_flow_alloc_resp == NULL) {
                                LOG_ERR("Flow_alloc_resp unsupported.");
                                break;
                        }

                        if (!msg->response) {
                                fd = np1_flow_resp(msg->port_id);
                                if (fd < 0) {
                                        LOG_WARN("Port_id %d is not known.",
                                                 msg->port_id);
                                        ret_msg.has_result = true;
                                        ret_msg.result = -1;
                                        break;
                                }
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_alloc_resp(fd,
                                                                msg->response);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_DEALLOC:
                        if (ipcpi.ops->ipcp_flow_dealloc == NULL) {
                                LOG_ERR("Flow_dealloc unsupported.");
                                break;
                        }

                        fd = np1_flow_dealloc(msg->port_id);
                        if (fd < 0) {
                                LOG_WARN("Could not deallocate port_id %d.",
                                        msg->port_id);
                                ret_msg.has_result = true;
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_dealloc(fd);
                        break;
                default:
                        LOG_ERR("Don't know that message code");
                        break;
                }

                ipcp_msg__free_unpacked(msg, NULL);

                buffer.len = ipcp_msg__get_packed_size(&ret_msg);
                if (buffer.len == 0) {
                        LOG_ERR("Failed to send reply message");
                        close(lsockfd);
                        continue;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        close(lsockfd);
                        continue;
                }

                ipcp_msg__pack(&ret_msg, buffer.data);

                if (write(lsockfd, buffer.data, buffer.len) == -1) {
                        free(buffer.data);
                        close(lsockfd);
                        continue;
                }

                free(buffer.data);
                close(lsockfd);
        }

        return (void *) 0;
}

int ipcp_init(enum ipcp_type    type,
              struct ipcp_ops * ops)
{
        pthread_condattr_t cattr;

        struct timeval tv = {(IPCP_ACCEPT_TIMEOUT / 1000),
                             (IPCP_ACCEPT_TIMEOUT % 1000) * 1000};

        ipcpi.irmd_fd   = -1;
        ipcpi.state     = IPCP_NULL;
        ipcpi.shim_data = NULL;

        ipcpi.threadpool = malloc(sizeof(pthread_t) * IPCPD_THREADPOOL_SIZE);
        if (ipcpi.threadpool == NULL) {
                return -ENOMEM;
        }

        ipcpi.sock_path = ipcp_sock_path(getpid());
        if (ipcpi.sock_path == NULL) {
                free(ipcpi.threadpool);
                return -1;
        }

        ipcpi.sockfd = server_socket_open(ipcpi.sock_path);
        if (ipcpi.sockfd < 0) {
                LOG_ERR("Could not open server socket.");
                free(ipcpi.threadpool);
                free(ipcpi.sock_path);
                return -1;
        }

        if (setsockopt(ipcpi.sockfd, SOL_SOCKET, SO_RCVTIMEO,
                       (void *) &tv, sizeof(tv)))
                LOG_WARN("Failed to set timeout on socket.");

        ipcpi.ops = ops;

        pthread_rwlock_init(&ipcpi.state_lock, NULL);
        pthread_mutex_init(&ipcpi.state_mtx, NULL);
        pthread_condattr_init(&cattr);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        pthread_cond_init(&ipcpi.state_cond, &cattr);

        if (type == IPCP_NORMAL)
                return 0;

        ipcpi.shim_data = shim_data_create();
        if (ipcpi.shim_data == NULL) {
                free(ipcpi.threadpool);
                free(ipcpi.sock_path);
                return -ENOMEM;
        }

        return 0;
}

int ipcp_boot()
{
        int t;

        ipcp_set_state(IPCP_INIT);

        for (t = 0; t < IPCPD_THREADPOOL_SIZE; ++t) {
                if (pthread_create(&ipcpi.threadpool[t], NULL,
                                   ipcp_main_loop, NULL)) {
                        int i;
                        LOG_ERR("Failed to create main thread.");
                        ipcp_set_state(IPCP_NULL);
                        for (i = 0; i < t; ++i)
                                pthread_join(ipcpi.threadpool[i], NULL);
                        return -1;
                }
        }

        return 0;
}

void ipcp_shutdown()
{
        int t;
        for (t = 0; t < IPCPD_THREADPOOL_SIZE; ++t)
                pthread_join(ipcpi.threadpool[t], NULL);

        LOG_DBG("IPCP %d shutting down. Bye.", getpid());
}

void ipcp_fini()
{
        close(ipcpi.sockfd);
        if (unlink(ipcpi.sock_path))
                LOG_DBG("Could not unlink %s.", ipcpi.sock_path);

        free(ipcpi.sock_path);
        free(ipcpi.threadpool);

        shim_data_destroy(ipcpi.shim_data);

        pthread_cond_destroy(&ipcpi.state_cond);
        pthread_mutex_destroy(&ipcpi.state_mtx);
        pthread_rwlock_destroy(&ipcpi.state_lock);
}

void ipcp_set_state(enum ipcp_state state)
{
        pthread_mutex_lock(&ipcpi.state_mtx);

        ipcpi.state = state;

        pthread_cond_broadcast(&ipcpi.state_cond);
        pthread_mutex_unlock(&ipcpi.state_mtx);
}

enum ipcp_state ipcp_get_state()
{
        enum ipcp_state state;

        pthread_mutex_lock(&ipcpi.state_mtx);

        state = ipcpi.state;

        pthread_mutex_unlock(&ipcpi.state_mtx);

        return state;
}

int ipcp_wait_state(enum ipcp_state         state,
                    const struct timespec * timeout)
{
        struct timespec abstime;
        int ret = 0;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, timeout, &abstime);

        pthread_mutex_lock(&ipcpi.state_mtx);

        while (ipcpi.state != state
               && ipcpi.state != IPCP_SHUTDOWN
               && ipcpi.state != IPCP_NULL) {
                if (timeout == NULL)
                        ret = -pthread_cond_wait(&ipcpi.state_cond,
                                                 &ipcpi.state_mtx);
                else
                        ret = -pthread_cond_timedwait(&ipcpi.state_cond,
                                                      &ipcpi.state_mtx,
                                                      &abstime);
        }

        pthread_mutex_unlock(&ipcpi.state_mtx);

        return ret;
}

int ipcp_parse_arg(int    argc,
                   char * argv[])
{
        char * log_file;
        size_t len = 0;

        if (!(argc == 3 || argc == 2))
                return -1;

        /* argument 1: api of irmd */
        if (atoi(argv[1]) == 0)
                return -1;

        ipcpi.irmd_api = atoi(argv[1]);

        /* argument 2: IPCP name */
        ipcpi.name = argv[2];

        /* argument 3: logfile name (if any) */
        if (argv[3] == NULL)
                return 0;

        len += strlen(INSTALL_PREFIX);
        len += strlen(LOG_DIR);
        len += strlen(argv[3]);

        log_file = malloc(len + 1);
        if (log_file == NULL)
                return -1;

        strcpy(log_file, INSTALL_PREFIX);
        strcat(log_file, LOG_DIR);
        strcat(log_file, argv[3]);
        log_file[len] = '\0';

        if (set_logfile(log_file))
                LOG_ERR("Cannot open %s, falling back to stdout for logs.",
                        log_file);

        free(log_file);

        return 0;
}
