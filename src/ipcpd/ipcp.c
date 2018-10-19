/*
 * Ouroboros - Copyright (C) 2016 - 2018
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#define __XSI_VISIBLE   500
#endif

#if defined(__linux__) && !defined(DISABLE_CORE_LOCK)
#define _GNU_SOURCE
#define NPROC (sysconf(_SC_NPROCESSORS_ONLN))
#endif

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#define __XSI_VISIBLE   500
#endif

#include "config.h"

#define OUROBOROS_PREFIX "ipcpd/ipcp"

#include <ouroboros/hash.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/np1_flow.h>

#include "ipcp.h"

#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#if defined(__linux__) && !defined(DISABLE_CORE_LOCK)
#include <unistd.h>
#endif

struct cmd {
        struct list_head next;

        uint8_t          cbuf[SOCK_BUF_SIZE];
        size_t           len;
        int              fd;
};

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

static void close_ptr(void * o)
{
        close(*((int *) o));
}

static void * acceptloop(void * o)
{
        int            csockfd;
        struct timeval tv = {(SOCKET_TIMEOUT / 1000),
                             (SOCKET_TIMEOUT % 1000) * 1000};

        (void) o;

        while (ipcp_get_state() != IPCP_SHUTDOWN &&
               ipcp_get_state() != IPCP_NULL) {
                struct cmd * cmd;

                csockfd = accept(ipcpi.sockfd, 0, 0);
                if (csockfd < 0)
                        continue;

                if (setsockopt(csockfd, SOL_SOCKET, SO_RCVTIMEO,
                               (void *) &tv, sizeof(tv)))
                        log_warn("Failed to set timeout on socket.");

                cmd = malloc(sizeof(*cmd));
                if (cmd == NULL) {
                        log_err("Out of memory");
                        close(csockfd);
                        break;
                }

                pthread_cleanup_push(close_ptr, &csockfd);
                pthread_cleanup_push(free, cmd);

                cmd->len = read(csockfd, cmd->cbuf, SOCK_BUF_SIZE);

                pthread_cleanup_pop(false);
                pthread_cleanup_pop(false);

                if (cmd->len <= 0) {
                        log_err("Failed to read from socket.");
                        close(csockfd);
                        free(cmd);
                        continue;
                }

                cmd->fd = csockfd;

                pthread_mutex_lock(&ipcpi.cmd_lock);

                list_add(&cmd->next, &ipcpi.cmds);

                pthread_cond_signal(&ipcpi.cmd_cond);

                pthread_mutex_unlock(&ipcpi.cmd_lock);
        }

        return (void *) 0;
}

static void free_msg(void * o)
{
        ipcp_msg__free_unpacked((ipcp_msg_t *) o, NULL);
}

static void * mainloop(void * o)
{
        int                 sfd;
        buffer_t            buffer;
        struct ipcp_config  conf;
        struct layer_info   info;
        ipcp_config_msg_t * conf_msg;
        ipcp_msg_t *        msg;

        (void) o;

        while (true) {
                ipcp_msg_t          ret_msg    = IPCP_MSG__INIT;
                layer_info_msg_t    layer_info = LAYER_INFO_MSG__INIT;
                int                 fd         = -1;
                struct cmd *        cmd;
                qosspec_t           qs;

                ret_msg.code = IPCP_MSG_CODE__IPCP_REPLY;

                pthread_mutex_lock(&ipcpi.cmd_lock);

                pthread_cleanup_push((void *)(void *) pthread_mutex_unlock,
                                     &ipcpi.cmd_lock);

                while (list_is_empty(&ipcpi.cmds))
                        pthread_cond_wait(&ipcpi.cmd_cond, &ipcpi.cmd_lock);

                cmd = list_last_entry(&ipcpi.cmds, struct cmd, next);
                list_del(&cmd->next);

                pthread_cleanup_pop(true);

                msg = ipcp_msg__unpack(NULL, cmd->len, cmd->cbuf);
                sfd = cmd->fd;

                free(cmd);

                if (msg == NULL) {
                        close(sfd);
                        continue;
                }

                tpm_dec(ipcpi.tpm);

                pthread_cleanup_push(close_ptr, &sfd);
                pthread_cleanup_push(free_msg, msg);

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
                        strcpy(conf.layer_info.layer_name,
                               conf_msg->layer_info->layer_name);
                        if (conf_msg->ipcp_type == IPCP_NORMAL) {
                                conf.addr_size      = conf_msg->addr_size;
                                conf.eid_size       = conf_msg->eid_size;
                                conf.max_ttl        = conf_msg->max_ttl;
                                conf.addr_auth_type = conf_msg->addr_auth_type;
                                conf.routing_type   = conf_msg->routing_type;
                                conf.pff_type       = conf_msg->pff_type;
                        }

                        if (conf_msg->ipcp_type == IPCP_ETH_LLC)
                                conf.dev = conf_msg->dev;

                        if (conf_msg->ipcp_type == IPCP_ETH_DIX) {
                                conf.dev = conf_msg->dev;
                                conf.ethertype = conf_msg->ethertype;
                        }

                        if (conf_msg->ipcp_type == IPCP_UDP) {
                                conf.ip_addr  = conf_msg->ip_addr;
                                conf.dns_addr = conf_msg->dns_addr;

                                conf.layer_info.dir_hash_algo = HASH_MD5;
                                layer_info.dir_hash_algo      = HASH_MD5;
                        }

                        /* Only udp needs a fixed hash algorithm */
                        if (conf_msg->ipcp_type != IPCP_UDP) {
                                switch(conf_msg->layer_info->dir_hash_algo) {
                                case DIR_HASH_SHA3_224:
                                        conf.layer_info.dir_hash_algo =
                                                HASH_SHA3_224;
                                        break;
                                case DIR_HASH_SHA3_256:
                                        conf.layer_info.dir_hash_algo =
                                                HASH_SHA3_256;
                                        break;
                                case DIR_HASH_SHA3_384:
                                        conf.layer_info.dir_hash_algo =
                                                HASH_SHA3_384;
                                        break;
                                case DIR_HASH_SHA3_512:
                                        conf.layer_info.dir_hash_algo =
                                                HASH_SHA3_512;
                                        break;
                                default:
                                        assert(false);
                                }

                                layer_info.dir_hash_algo =
                                        conf.layer_info.dir_hash_algo;
                        }

                        ipcpi.dir_hash_algo = conf.layer_info.dir_hash_algo;

                        ret_msg.result = ipcpi.ops->ipcp_bootstrap(&conf);
                        if (ret_msg.result == 0) {
                                ret_msg.layer_info = &layer_info;
                                layer_info.layer_name =
                                        conf.layer_info.layer_name;
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

                        ret_msg.result = ipcpi.ops->ipcp_enroll(msg->dst,
                                                                &info);
                        if (ret_msg.result == 0) {
                                ret_msg.layer_info       = &layer_info;
                                layer_info.dir_hash_algo = info.dir_hash_algo;
                                layer_info.layer_name    = info.layer_name;
                        }
                        break;
                case IPCP_MSG_CODE__IPCP_CONNECT:
                        ret_msg.has_result = true;

                        if (ipcpi.ops->ipcp_connect == NULL) {
                                log_err("Connect unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        qs = msg_to_spec(msg->qosspec);
                        ret_msg.result = ipcpi.ops->ipcp_connect(msg->dst,
                                                                 msg->comp,
                                                                 qs);
                        break;
                case IPCP_MSG_CODE__IPCP_DISCONNECT:
                        ret_msg.has_result = true;

                        if (ipcpi.ops->ipcp_disconnect == NULL) {
                                log_err("Disconnect unsupported.");
                                ret_msg.result = -ENOTSUP;
                                break;
                        }

                        ret_msg.result = ipcpi.ops->ipcp_disconnect(msg->dst,
                                                                    msg->comp);
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

                        qs = msg_to_spec(msg->qosspec);
                        fd = np1_flow_alloc(msg->pid,
                                            msg->flow_id,
                                            qs);
                        if (fd < 0) {
                                log_err("Failed allocating fd on flow_id %d.",
                                        msg->flow_id);
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_alloc(fd,
                                                           msg->hash.data,
                                                           qs);
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
                                fd = np1_flow_resp(msg->flow_id);
                                if (fd < 0) {
                                        log_warn("Port_id %d is not known.",
                                                 msg->flow_id);
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

                        fd = np1_flow_dealloc(msg->flow_id);
                        if (fd < 0) {
                                log_warn("Could not deallocate flow_id %d.",
                                        msg->flow_id);
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.result =
                                ipcpi.ops->ipcp_flow_dealloc(fd);
                        break;
                default:
                        ret_msg.has_result = true;
                        ret_msg.result     = -1;
                        log_err("Don't know that message code");
                        break;
                }

                pthread_cleanup_pop(true);
                pthread_cleanup_pop(false);

                buffer.len = ipcp_msg__get_packed_size(&ret_msg);
                if (buffer.len == 0) {
                        log_err("Failed to pack reply message");
                        close(sfd);
                        tpm_inc(ipcpi.tpm);
                        continue;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        log_err("Failed to create reply buffer.");
                        close(sfd);
                        tpm_inc(ipcpi.tpm);
                        continue;
                }

                ipcp_msg__pack(&ret_msg, buffer.data);

                pthread_cleanup_push(close_ptr, &sfd);

                if (write(sfd, buffer.data, buffer.len) == -1)
                        log_warn("Failed to send reply message");

                free(buffer.data);
                pthread_cleanup_pop(true);

                tpm_inc(ipcpi.tpm);
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

        /* argument 1: pid of irmd */
        if (atoi(argv[1]) == 0)
                return -1;

        ipcpi.irmd_pid = atoi(argv[1]);

        /* argument 2: IPCP name */
        ipcpi.name = argv[2];

        /* argument 3: syslog */
        if (argv[3] != NULL)
                *log = true;

        return 0;
}

int ipcp_init(int               argc,
              char **           argv,
              struct ipcp_ops * ops)
{
        bool               log;
        pthread_condattr_t cattr;
        int                ret = -1;

        if (parse_args(argc, argv, &log))
                return -1;

        log_init(log);

        ipcpi.irmd_fd   = -1;
        ipcpi.state     = IPCP_NULL;

        ipcpi.sock_path = ipcp_sock_path(getpid());
        if (ipcpi.sock_path == NULL)
                goto fail_sock_path;

        ipcpi.sockfd = server_socket_open(ipcpi.sock_path);
        if (ipcpi.sockfd < 0) {
                log_err("Could not open server socket.");
                goto fail_serv_sock;
        }

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

        if (pthread_cond_init(&ipcpi.alloc_cond, &cattr)) {
                log_err("Failed to init convar.");
                goto fail_alloc_cond;
        }

        if (pthread_mutex_init(&ipcpi.cmd_lock, NULL)) {
                log_err("Failed to init mutex.");
                goto fail_cmd_lock;
        }

        if (pthread_cond_init(&ipcpi.cmd_cond, &cattr)) {
                log_err("Failed to init convar.");
                goto fail_cmd_cond;
        }

        list_head_init(&ipcpi.cmds);

        ipcpi.alloc_id = -1;

        pthread_condattr_destroy(&cattr);

        return 0;

 fail_cmd_cond:
        pthread_mutex_destroy(&ipcpi.cmd_lock);
 fail_cmd_lock:
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
        return ret;
}

int ipcp_boot()
{
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        ipcpi.tpm = tpm_create(IPCP_MIN_THREADS, IPCP_ADD_THREADS,
                               mainloop, NULL);
        if (ipcpi.tpm == NULL)
                goto fail_tpm_create;

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (tpm_start(ipcpi.tpm))
                goto fail_tpm_start;

        ipcp_set_state(IPCP_INIT);

        if (pthread_create(&ipcpi.acceptor, NULL, acceptloop, NULL)) {
                log_err("Failed to create acceptor thread.");
                ipcp_set_state(IPCP_NULL);
                goto fail_acceptor;
        }

        return 0;

 fail_acceptor:
        tpm_stop(ipcpi.tpm);
 fail_tpm_start:
        tpm_destroy(ipcpi.tpm);
 fail_tpm_create:
        return -1;
}

void ipcp_shutdown()
{
        siginfo_t info;
        sigset_t  sigset;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGPIPE);

        while(ipcp_get_state() != IPCP_NULL &&
              ipcp_get_state() != IPCP_SHUTDOWN) {
                if (sigwaitinfo(&sigset, &info) < 0) {
                        log_warn("Bad signal.");
                        continue;
                }

                switch(info.si_signo) {
                case SIGINT:
                case SIGTERM:
                case SIGHUP:
                case SIGQUIT:
                        if (info.si_pid == ipcpi.irmd_pid) {
                                if (ipcp_get_state() == IPCP_INIT)
                                        ipcp_set_state(IPCP_NULL);

                                if (ipcp_get_state() == IPCP_OPERATIONAL)
                                        ipcp_set_state(IPCP_SHUTDOWN);
                        }
                        break;
                case SIGPIPE:
                        log_dbg("Ignored SIGPIPE.");
                default:
                        continue;
                }
        }

        pthread_cancel(ipcpi.acceptor);

        pthread_join(ipcpi.acceptor, NULL);
        tpm_stop(ipcpi.tpm);
        tpm_destroy(ipcpi.tpm);

        log_info("IPCP %d shutting down.", getpid());
}

void ipcp_fini()
{
        close(ipcpi.sockfd);
        if (unlink(ipcpi.sock_path))
                log_warn("Could not unlink %s.", ipcpi.sock_path);

        free(ipcpi.sock_path);

        pthread_cond_destroy(&ipcpi.state_cond);
        pthread_mutex_destroy(&ipcpi.state_mtx);
        pthread_cond_destroy(&ipcpi.alloc_cond);
        pthread_mutex_destroy(&ipcpi.alloc_lock);
        pthread_cond_destroy(&ipcpi.cmd_cond);
        pthread_mutex_destroy(&ipcpi.cmd_lock);

        log_info("IPCP %d out.", getpid());

        log_fini();
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

        pthread_cleanup_push((void *)(void *) pthread_mutex_unlock,
                             &ipcpi.state_mtx);

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

        pthread_cleanup_pop(true);

        return ret;
}

void ipcp_lock_to_core(void)
{
#if defined(__linux__) && !defined(DISABLE_CORE_LOCK)
        cpu_set_t           cpus;
        size_t              cpu;

        /* Choose a random core. */
        cpu = rand() % NPROC;

        CPU_ZERO(&cpus);
        CPU_SET(cpu, &cpus);

        if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus))
                log_warn("Failed to lock thread %lu to CPU %zu/%lu.",
                         pthread_self(), cpu, NPROC);
        else
                log_dbg("Locked thread %lu to CPU %zu/%lu.",
                        pthread_self(), cpu, NPROC);
#endif
}
