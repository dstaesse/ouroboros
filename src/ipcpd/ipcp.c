/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * IPC process main loop
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
#include <ouroboros/bitmap.h>
#include <ouroboros/np1_flow.h>

#include "ipcp.h"

#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>


static void thread_inc(void)
{
        pthread_mutex_lock(&ipcpi.threads_lock);

        ++ipcpi.threads;
        pthread_cond_signal(&ipcpi.threads_cond);

        pthread_mutex_unlock(&ipcpi.threads_lock);
}

static void thread_dec(void)
{
        pthread_mutex_lock(&ipcpi.threads_lock);

        --ipcpi.threads;
        pthread_cond_signal(&ipcpi.threads_cond);

        pthread_mutex_unlock(&ipcpi.threads_lock);
}

static bool thread_check(void)
{
        int ret;

        pthread_mutex_lock(&ipcpi.threads_lock);

        ret = ipcpi.threads > ipcpi.max_threads;

        pthread_mutex_unlock(&ipcpi.threads_lock);

        return ret;
}

static void thread_exit(ssize_t id)
{
        pthread_mutex_lock(&ipcpi.threads_lock);
        bmp_release(ipcpi.thread_ids, id);

        --ipcpi.threads;
        pthread_cond_signal(&ipcpi.threads_cond);

        pthread_mutex_unlock(&ipcpi.threads_lock);
}

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

        ssize_t id = (ssize_t)  o;

        while (true) {
#ifdef __FreeBSD__
                fd_set fds;
                struct timeval timeout = {(IPCP_ACCEPT_TIMEOUT / 1000),
                                          (IPCP_ACCEPT_TIMEOUT % 1000) * 1000};
#endif
                int fd = -1;

                pthread_rwlock_rdlock(&ipcpi.state_lock);

                if (ipcp_get_state() == IPCP_SHUTDOWN ||
                    ipcp_get_state() == IPCP_NULL ||
                    thread_check()) {
                        thread_exit(id);
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
                        log_warn("Failed to set timeout on socket.");

                count = read(lsockfd, buf, IPCP_MSG_BUF_SIZE);
                if (count <= 0) {
                        log_err("Failed to read from socket");
                        close(lsockfd);
                        continue;
                }

                msg = ipcp_msg__unpack(NULL, count, buf);
                if (msg == NULL) {
                        close(lsockfd);
                        continue;
                }

                thread_dec();

                switch (msg->code) {
                case IPCP_MSG_CODE__IPCP_BOOTSTRAP:
                        if (ipcpi.ops->ipcp_bootstrap == NULL) {
                                log_err("Bootstrap unsupported.");
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
                                log_err("Enroll unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result = ipcpi.ops->ipcp_enroll(msg->dif_name);
                        break;
                case IPCP_MSG_CODE__IPCP_NAME_REG:
                        if (ipcpi.ops->ipcp_name_reg == NULL) {
                                log_err("Ap_reg unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_name_reg(msg->name);
                        break;
                case IPCP_MSG_CODE__IPCP_NAME_UNREG:
                        if (ipcpi.ops->ipcp_name_unreg == NULL) {
                                log_err("Ap_unreg unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_name_unreg(msg->name);
                        break;
                case IPCP_MSG_CODE__IPCP_NAME_QUERY:
                        if (ipcpi.ops->ipcp_name_query == NULL) {
                                log_err("Ap_query unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_name_query(msg->name);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC:
                        if (ipcpi.ops->ipcp_flow_alloc == NULL) {
                                log_err("Flow_alloc unsupported.");
                                break;
                        }
                        fd = np1_flow_alloc(msg->api, msg->port_id);
                        if (fd < 0) {
                                log_err("Failed allocating fd on port_id %d.",
                                        msg->port_id);
                                ret_msg.has_result = true;
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.has_result = true;
                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_alloc(fd,
                                                           msg->dst_name,
                                                           msg->qoscube);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP:
                        if (ipcpi.ops->ipcp_flow_alloc_resp == NULL) {
                                log_err("Flow_alloc_resp unsupported.");
                                break;
                        }

                        if (!msg->response) {
                                fd = np1_flow_resp(msg->port_id);
                                if (fd < 0) {
                                        log_warn("Port_id %d is not known.",
                                                 msg->port_id);
                                        ret_msg.has_result = true;
                                        ret_msg.result = -1;
                                        break;
                                }
                        }
                        ret_msg.has_result = true;

                        pthread_mutex_lock(&ipcpi.alloc_lock);
                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_alloc_resp(fd,
                                                                msg->response);
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_DEALLOC:
                        if (ipcpi.ops->ipcp_flow_dealloc == NULL) {
                                log_err("Flow_dealloc unsupported.");
                                break;
                        }

                        fd = np1_flow_dealloc(msg->port_id);
                        if (fd < 0) {
                                log_warn("Could not deallocate port_id %d.",
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
                        log_err("Don't know that message code");
                        break;
                }

                ipcp_msg__free_unpacked(msg, NULL);

                buffer.len = ipcp_msg__get_packed_size(&ret_msg);
                if (buffer.len == 0) {
                        log_err("Failed to pack reply message");
                        close(lsockfd);
                        thread_inc();
                        continue;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        log_err("Failed to create reply buffer.");
                        close(lsockfd);
                        thread_inc();
                        continue;
                }

                ipcp_msg__pack(&ret_msg, buffer.data);

                if (write(lsockfd, buffer.data, buffer.len) == -1) {
                        log_err("Failed to send reply message");
                        free(buffer.data);
                        close(lsockfd);
                        thread_inc();
                        continue;
                }

                free(buffer.data);
                close(lsockfd);

                thread_inc();
        }

        return (void *) 0;
}

static int parse_args(int    argc,
                      char * argv[],
                      bool * log)
{
        *log = false;

        if (!(argc == 4 || argc == 3))
                return -1;

        /* argument 1: api of irmd */
        if (atoi(argv[1]) == 0)
                return -1;

        ipcpi.irmd_api = atoi(argv[1]);

        /* argument 2: IPCP name */
        ipcpi.name = argv[2];

        /* argument 3: syslog */
        if (argv[3] != NULL)
                *log = true;

        return 0;
}

int ipcp_init(int               argc,
              char **           argv,
              enum ipcp_type    type,
              struct ipcp_ops * ops)
{
        bool               log;
        pthread_condattr_t cattr;
        struct timeval     tv  = {(IPCP_ACCEPT_TIMEOUT / 1000),
                                  (IPCP_ACCEPT_TIMEOUT % 1000) * 1000};
        int                ret = -1;

        if (parse_args(argc, argv, &log))
                return -1;

        log_init(log);

        if (type == IPCP_NORMAL) {
                if (ap_init(argv[0])) {
                        log_err("Failed to init normal IPCPI.");
                        return -1;
                }
        } else {
                if (ap_init(NULL)) {
                        log_err("Failed to init shim IPCPI.");
                        return -1;
                }
        }

        ipcpi.irmd_fd   = -1;
        ipcpi.state     = IPCP_NULL;
        ipcpi.shim_data = NULL;

        ipcpi.threadpool = malloc(sizeof(pthread_t) * IPCP_MAX_THREADS);
        if (ipcpi.threadpool == NULL) {
                ret = -ENOMEM;
                goto fail_thr;
        }

        ipcpi.threads = 0;
        ipcpi.max_threads = IPCP_MIN_AV_THREADS;

        ipcpi.sock_path = ipcp_sock_path(getpid());
        if (ipcpi.sock_path == NULL)
                goto fail_sock_path;

        ipcpi.sockfd = server_socket_open(ipcpi.sock_path);
        if (ipcpi.sockfd < 0) {
                log_err("Could not open server socket.");
                goto fail_serv_sock;
        }

        if (setsockopt(ipcpi.sockfd, SOL_SOCKET, SO_RCVTIMEO,
                       (void *) &tv, sizeof(tv)))
                log_warn("Failed to set timeout on socket.");

        ipcpi.ops = ops;

        if (pthread_rwlock_init(&ipcpi.state_lock, NULL)) {
                log_err("Could not create rwlock.");
                goto fail_state_rwlock;
        }

        if (pthread_mutex_init(&ipcpi.state_mtx, NULL)) {
                log_err("Could not create mutex.");
                goto fail_state_mtx;
        }

        if (pthread_mutex_init(&ipcpi.threads_lock, NULL)) {
                log_err("Could not create mutex.");
                goto fail_thread_lock;
        }

        if (pthread_condattr_init(&cattr)) {
                log_err("Could not create condattr.");
                goto fail_cond_attr;
        }

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&ipcpi.state_cond, &cattr)) {
                log_err("Could not init condvar.");
                goto fail_state_cond;
        }

        if (pthread_cond_init(&ipcpi.threads_cond, &cattr)) {
                log_err("Could not init condvar.");
                goto fail_thread_cond;
        }

        ipcpi.thread_ids = bmp_create(IPCP_MAX_THREADS, 0);
        if (ipcpi.thread_ids == NULL) {
                log_err("Could not init condvar.");
                goto fail_bmp;
        }

        if (pthread_mutex_init(&ipcpi.alloc_lock, NULL)) {
                log_err("Failed to init mutex.");
                goto fail_alloc_lock;
        }

        if (type == IPCP_NORMAL) {
                pthread_condattr_destroy(&cattr);
                return 0;
        }

        ipcpi.shim_data = shim_data_create();
        if (ipcpi.shim_data == NULL) {
                ret = -ENOMEM;
                goto fail_shim_data;
        }

        pthread_condattr_destroy(&cattr);

        return 0;

 fail_shim_data:
        pthread_mutex_destroy(&ipcpi.alloc_lock);
 fail_alloc_lock:
        bmp_destroy(ipcpi.thread_ids);
 fail_bmp:
        pthread_cond_destroy(&ipcpi.threads_cond);
 fail_thread_cond:
        pthread_cond_destroy(&ipcpi.state_cond);
 fail_state_cond:
        pthread_condattr_destroy(&cattr);
 fail_cond_attr:
        pthread_mutex_destroy(&ipcpi.threads_lock);
 fail_thread_lock:
        pthread_mutex_destroy(&ipcpi.state_mtx);
 fail_state_mtx:
        pthread_rwlock_destroy(&ipcpi.state_lock);
 fail_state_rwlock:
        close(ipcpi.sockfd);
 fail_serv_sock:
        free(ipcpi.sock_path);
 fail_sock_path:
        free(ipcpi.threadpool);
 fail_thr:
        ap_fini();

        return ret;
}

void * threadpoolmgr(void * o)
{
        pthread_attr_t  pattr;
        struct timespec dl;
        struct timespec to = {(IRMD_TPM_TIMEOUT / 1000),
                              (IRMD_TPM_TIMEOUT % 1000) * MILLION};
        (void) o;

        if (pthread_attr_init(&pattr))
                return (void *) -1;

        pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);

        while (true) {
                clock_gettime(PTHREAD_COND_CLOCK, &dl);
                ts_add(&dl, &to, &dl);

                pthread_rwlock_rdlock(&ipcpi.state_lock);
                if (ipcp_get_state() == IPCP_SHUTDOWN ||
                    ipcp_get_state() == IPCP_NULL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        pthread_attr_destroy(&pattr);
                        log_dbg("Waiting for threads to exit.");
                        pthread_mutex_lock(&ipcpi.threads_lock);
                        while (ipcpi.threads > 0)
                                pthread_cond_wait(&ipcpi.threads_cond,
                                                  &ipcpi.threads_lock);
                        pthread_mutex_unlock(&ipcpi.threads_lock);

                        log_dbg("Threadpool manager done.");
                        break;
                }

                pthread_rwlock_unlock(&ipcpi.state_lock);

                pthread_mutex_lock(&ipcpi.threads_lock);

                if (ipcpi.threads < IPCP_MIN_AV_THREADS) {
                        log_dbg("Increasing threadpool.");
                        ipcpi.max_threads = IPCP_MAX_AV_THREADS;

                        while (ipcpi.threads < ipcpi.max_threads) {
                                ssize_t id = bmp_allocate(ipcpi.thread_ids);
                                if (!bmp_is_id_valid(ipcpi.thread_ids, id)) {
                                        log_warn("IPCP threadpool exhausted.");
                                        break;
                                }

                                if (pthread_create(&ipcpi.threadpool[id],
                                                   &pattr, ipcp_main_loop,
                                                   (void *) id))
                                        log_warn("Failed to start new thread.");
                                else
                                        ++ipcpi.threads;
                        }
                }

                if (pthread_cond_timedwait(&ipcpi.threads_cond,
                                           &ipcpi.threads_lock,
                                           &dl) == ETIMEDOUT)
                        if (ipcpi.threads > IPCP_MIN_AV_THREADS)
                                --ipcpi.max_threads;

                pthread_mutex_unlock(&ipcpi.threads_lock);
        }

        return (void *) 0;
}

int ipcp_boot()
{
        ipcp_set_state(IPCP_INIT);

        pthread_create(&ipcpi.tpm, NULL, threadpoolmgr, NULL);

        return 0;
}

void ipcp_shutdown()
{
        pthread_join(ipcpi.tpm, NULL);

        log_info("IPCP %d shutting down.", getpid());
}

void ipcp_fini()
{
        close(ipcpi.sockfd);
        if (unlink(ipcpi.sock_path))
                log_warn("Could not unlink %s.", ipcpi.sock_path);

        bmp_destroy(ipcpi.thread_ids);

        free(ipcpi.sock_path);
        free(ipcpi.threadpool);

        shim_data_destroy(ipcpi.shim_data);

        pthread_cond_destroy(&ipcpi.state_cond);
        pthread_cond_destroy(&ipcpi.threads_cond);
        pthread_mutex_destroy(&ipcpi.threads_lock);
        pthread_mutex_destroy(&ipcpi.state_mtx);
        pthread_rwlock_destroy(&ipcpi.state_lock);

        log_fini();

        ap_fini();

        log_info("IPCP %d out.", getpid());
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
               && ipcpi.state != IPCP_NULL
               && ret != -ETIMEDOUT) {
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
