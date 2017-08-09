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
#include <ouroboros/hash.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/np1_flow.h>
#include <ouroboros/tpm.h>

#include "ipcp.h"

#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>

void ipcp_sig_handler(int         sig,
                      siginfo_t * info,
                      void *      c)
{
        (void) c;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
        case SIGQUIT:
                if (info->si_pid == ipcpi.irmd_api) {
                        if (ipcp_get_state() == IPCP_INIT)
                                ipcp_set_state(IPCP_NULL);

                        if (ipcp_get_state() == IPCP_OPERATIONAL)
                                ipcp_set_state(IPCP_SHUTDOWN);
                }

                tpm_stop();
        default:
                return;
        }
}

uint8_t * ipcp_hash_dup(const uint8_t * hash)
{
        uint8_t * dup = malloc(hash_len(ipcpi.dir_hash_algo));
        if (dup == NULL)
                return NULL;

        memcpy(dup, hash, ipcp_dir_hash_len());

        return dup;
}

void ipcp_hash_str(char *          buf,
                   const uint8_t * hash)
{
        size_t i;

        char * HEX = "0123456789abcdef";

        for (i = 0; i < ipcp_dir_hash_len(); ++i) {
                buf[i * 2]     = HEX[(hash[i] & 0xF0) >> 4];
                buf[i * 2 + 1] = HEX[hash[i] & 0x0F];
        }

        buf[2 * i] = '\0';
}

static void * mainloop(void * o)
{
        int                 lsockfd;
        uint8_t             buf[IPCP_MSG_BUF_SIZE];
        ssize_t             count;
        buffer_t            buffer;
        struct ipcp_config  conf;
        struct dif_info     info;

        ipcp_config_msg_t * conf_msg;
        ipcp_msg_t *        msg;
        ipcp_msg_t          ret_msg  = IPCP_MSG__INIT;
        dif_info_msg_t      dif_info = DIF_INFO_MSG__INIT;
        struct timeval      ltv      = {(SOCKET_TIMEOUT / 1000),
                                        (SOCKET_TIMEOUT % 1000) * 1000};

        (void)  o;

        while (true) {
#ifdef __FreeBSD__
                fd_set fds;
                struct timeval timeout = {(IPCP_ACCEPT_TIMEOUT / 1000),
                                          (IPCP_ACCEPT_TIMEOUT % 1000) * 1000};
#endif
                int fd = -1;

                if (ipcp_get_state() == IPCP_SHUTDOWN ||
                    ipcp_get_state() == IPCP_NULL ||
                    tpm_check()) {
                        tpm_exit();
                        break;
                }

                ret_msg.code = IPCP_MSG_CODE__IPCP_REPLY;
#ifdef __FreeBSD__
                FD_ZERO(&fds);
                FD_SET(ipcpi.sockfd, &fds);
                if (select(ipcpi.sockfd + 1, &fds, NULL, NULL, &timeout) <= 0)
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

                tpm_dec();

                switch (msg->code) {
                case IPCP_MSG_CODE__IPCP_BOOTSTRAP:
                        ret_msg.has_result = true;

                        if (ipcpi.ops->ipcp_bootstrap == NULL) {
                                log_err("Bootstrap unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        if (ipcp_get_state() != IPCP_INIT) {
                                log_err("IPCP in wrong state.");
                                ret_msg.result = -EIPCPSTATE;
                                break;
                        }

                        conf_msg = msg->conf;
                        conf.type = conf_msg->ipcp_type;
                        strcpy(conf.dif_info.dif_name,
                               conf_msg->dif_info->dif_name);
                        if (conf.dif_info.dif_name == NULL) {
                                log_err("No DIF name provided.");
                                ret_msg.result = -1;
                                break;
                        }
                        if (conf_msg->ipcp_type == IPCP_NORMAL) {
                                conf.addr_size      = conf_msg->addr_size;
                                conf.fd_size        = conf_msg->fd_size;
                                conf.has_ttl        = conf_msg->has_ttl;
                                conf.addr_auth_type = conf_msg->addr_auth_type;
                                conf.dt_gam_type    = conf_msg->dt_gam_type;
                                conf.rm_gam_type    = conf_msg->rm_gam_type;
                                conf.routing_type   = conf_msg->routing_type;

                                switch(conf_msg->dif_info->dir_hash_algo) {
                                case DIR_HASH_SHA3_224:
                                        conf.dif_info.dir_hash_algo
                                                = HASH_SHA3_224;
                                        break;
                                case DIR_HASH_SHA3_256:
                                        conf.dif_info.dir_hash_algo
                                                = HASH_SHA3_256;
                                        break;
                                case DIR_HASH_SHA3_384:
                                        conf.dif_info.dir_hash_algo
                                                = HASH_SHA3_384;
                                        break;
                                case DIR_HASH_SHA3_512:
                                        conf.dif_info.dir_hash_algo
                                                = HASH_SHA3_512;
                                        break;
                                default:
                                        assert(false);
                                }

                                dif_info.dir_hash_algo =
                                        conf.dif_info.dir_hash_algo;
                        }

                        if (conf_msg->ipcp_type == IPCP_SHIM_UDP) {
                                conf.ip_addr           = conf_msg->ip_addr;
                                conf.dns_addr          = conf_msg->dns_addr;
                                dif_info.dir_hash_algo = HASH_MD5;
                                ipcpi.dir_hash_algo    = HASH_MD5;
                        }

                        if (conf_msg->ipcp_type == IPCP_SHIM_ETH_LLC) {
                                conf.if_name           = conf_msg->if_name;
                                dif_info.dir_hash_algo = HASH_SHA3_256;
                                ipcpi.dir_hash_algo    = HASH_SHA3_256;
                        }

                        if (conf_msg->ipcp_type == IPCP_LOCAL) {
                                dif_info.dir_hash_algo = HASH_SHA3_256;
                                ipcpi.dir_hash_algo    = HASH_SHA3_256;
                        }

                        ret_msg.result = ipcpi.ops->ipcp_bootstrap(&conf);
                        if (ret_msg.result == 0) {
                                ret_msg.dif_info       = &dif_info;
                                dif_info.dif_name      = conf.dif_info.dif_name;
                        }
                        break;
                case IPCP_MSG_CODE__IPCP_ENROLL:
                        ret_msg.has_result = true;

                        if (ipcpi.ops->ipcp_enroll == NULL) {
                                log_err("Enroll unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        if (ipcp_get_state() != IPCP_INIT) {
                                log_err("IPCP in wrong state.");
                                ret_msg.result = -EIPCPSTATE;
                                break;
                        }

                        ret_msg.result = ipcpi.ops->ipcp_enroll(msg->dst_name,
                                                                &info);
                        if (ret_msg.result == 0) {
                                ret_msg.dif_info       = &dif_info;
                                dif_info.dir_hash_algo = info.dir_hash_algo;
                                dif_info.dif_name      = info.dif_name;
                        }
                        break;
                case IPCP_MSG_CODE__IPCP_REG:
                        ret_msg.has_result = true;

                        if (ipcpi.ops->ipcp_reg == NULL) {
                                log_err("Registration unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        assert(msg->hash.len == ipcp_dir_hash_len());

                        ret_msg.result =
                                ipcpi.ops->ipcp_reg(msg->hash.data);
                        break;
                case IPCP_MSG_CODE__IPCP_UNREG:
                        ret_msg.has_result = true;

                        if (ipcpi.ops->ipcp_unreg == NULL) {
                                log_err("Unregistration unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        assert(msg->hash.len == ipcp_dir_hash_len());

                        ret_msg.result =
                                ipcpi.ops->ipcp_unreg(msg->hash.data);
                        break;
                case IPCP_MSG_CODE__IPCP_QUERY:
                        ret_msg.has_result = true;

                        if (ipcpi.ops->ipcp_query == NULL) {
                                log_err("Directory query unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        assert(msg->hash.len == ipcp_dir_hash_len());

                        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                                log_err("IPCP in wrong state.");
                                ret_msg.result = -EIPCPSTATE;
                                break;
                        }

                        ret_msg.result =
                                ipcpi.ops->ipcp_query(msg->hash.data);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC:
                        ret_msg.has_result = true;

                        if (ipcpi.ops->ipcp_flow_alloc == NULL) {
                                log_err("Flow allocation unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        assert(msg->hash.len == ipcp_dir_hash_len());

                        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                                log_err("IPCP in wrong state.");
                                ret_msg.result = -EIPCPSTATE;
                                break;
                        }

                        fd = np1_flow_alloc(msg->api,
                                            msg->port_id,
                                            msg->qoscube);
                        if (fd < 0) {
                                log_err("Failed allocating fd on port_id %d.",
                                        msg->port_id);
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_alloc(fd,
                                                           msg->hash.data,
                                                           msg->qoscube);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP:
                        ret_msg.has_result = true;
                        if (ipcpi.ops->ipcp_flow_alloc_resp == NULL) {
                                log_err("Flow_alloc_resp unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                                log_err("IPCP in wrong state.");
                                ret_msg.result = -EIPCPSTATE;
                                break;
                        }

                        if (!msg->response) {
                                fd = np1_flow_resp(msg->port_id);
                                if (fd < 0) {
                                        log_warn("Port_id %d is not known.",
                                                 msg->port_id);
                                        ret_msg.result = -1;
                                        break;
                                }
                        }

                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_alloc_resp(fd,
                                                                msg->response);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_DEALLOC:
                        ret_msg.has_result = true;
                        if (ipcpi.ops->ipcp_flow_dealloc == NULL) {
                                log_err("Flow deallocation unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                                log_err("IPCP in wrong state.");
                                ret_msg.result = -EIPCPSTATE;
                                break;
                        }

                        fd = np1_flow_dealloc(msg->port_id);
                        if (fd < 0) {
                                log_warn("Could not deallocate port_id %d.",
                                        msg->port_id);
                                ret_msg.result = -1;
                                break;
                        }

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
                        tpm_inc();
                        continue;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        log_err("Failed to create reply buffer.");
                        close(lsockfd);
                        tpm_inc();
                        continue;
                }

                ipcp_msg__pack(&ret_msg, buffer.data);

                if (write(lsockfd, buffer.data, buffer.len) == -1) {
                        log_err("Failed to send reply message");
                        free(buffer.data);
                        close(lsockfd);
                        tpm_inc();
                        continue;
                }

                free(buffer.data);
                close(lsockfd);

                tpm_inc();
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
                if (ouroboros_init(argv[0])) {
                        log_err("Failed to init normal IPCPI.");
                        return -1;
                }
        } else {
                if (ouroboros_init(NULL)) {
                        log_err("Failed to init shim IPCPI.");
                        return -1;
                }
        }

        ipcpi.irmd_fd   = -1;
        ipcpi.state     = IPCP_NULL;
        ipcpi.shim_data = NULL;

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

        if (pthread_mutex_init(&ipcpi.state_mtx, NULL)) {
                log_err("Could not create mutex.");
                goto fail_state_mtx;
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

        if (pthread_mutex_init(&ipcpi.alloc_lock, NULL)) {
                log_err("Failed to init mutex.");
                goto fail_alloc_lock;
        }

        if (pthread_cond_init(&ipcpi.alloc_cond, NULL)) {
                log_err("Failed to init convar.");
                goto fail_alloc_cond;
        }

        ipcpi.alloc_id = -1;

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
        pthread_cond_destroy(&ipcpi.alloc_cond);
 fail_alloc_cond:
        pthread_mutex_destroy(&ipcpi.alloc_lock);
 fail_alloc_lock:
        pthread_cond_destroy(&ipcpi.state_cond);
 fail_state_cond:
        pthread_condattr_destroy(&cattr);
 fail_cond_attr:
        pthread_mutex_destroy(&ipcpi.state_mtx);
 fail_state_mtx:
        close(ipcpi.sockfd);
 fail_serv_sock:
        free(ipcpi.sock_path);
 fail_sock_path:
        ouroboros_fini();

        return ret;
}

int ipcp_boot()
{
        struct sigaction sig_act;
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        /* init sig_act */
        memset(&sig_act, 0, sizeof(sig_act));

        /* install signal traps */
        sig_act.sa_sigaction = &ipcp_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        sigaction(SIGINT,  &sig_act, NULL);
        sigaction(SIGTERM, &sig_act, NULL);
        sigaction(SIGHUP,  &sig_act, NULL);
        sigaction(SIGPIPE, &sig_act, NULL);

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (tpm_init(IPCP_MIN_THREADS, IPCP_ADD_THREADS, mainloop))
                return -1;

        if (tpm_start()) {
                tpm_fini();
                return -1;
        }

        ipcp_set_state(IPCP_INIT);

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        return 0;
}

void ipcp_shutdown()
{
        tpm_fini();
        log_info("IPCP %d shutting down.", getpid());
}

void ipcp_fini()
{
        close(ipcpi.sockfd);
        if (unlink(ipcpi.sock_path))
                log_warn("Could not unlink %s.", ipcpi.sock_path);

        free(ipcpi.sock_path);

        shim_data_destroy(ipcpi.shim_data);

        pthread_cond_destroy(&ipcpi.state_cond);
        pthread_mutex_destroy(&ipcpi.state_mtx);
        pthread_cond_destroy(&ipcpi.alloc_cond);
        pthread_mutex_destroy(&ipcpi.alloc_lock);

        log_info("IPCP %d out.", getpid());

        log_fini();

        ouroboros_fini();
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
