/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * IPC process main loop
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

#if defined(__linux__) && !defined(DISABLE_CORE_LOCK)
#define _GNU_SOURCE
#define NPROC (sysconf(_SC_NPROCESSORS_ONLN))
#endif

#include "config.h"

#define OUROBOROS_PREFIX  "ipcpd/ipcp"
#define IPCP_INFO         "info"

#include <ouroboros/hash.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/np1_flow.h>
#include <ouroboros/rib.h>
#include <ouroboros/protobuf.h>
#include <ouroboros/pthread.h>

#include "ipcp.h"

#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#if defined(__linux__)
#include <sys/prctl.h>
#ifndef DISABLE_CORE_LOCK
#include <unistd.h>
#endif
#endif

char * info[LAYER_NAME_SIZE + 1] = {
        "_state",
        "_type",
        "_layer",
        NULL
};

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

static int ipcp_rib_read(const char * path,
                         char *       buf,
                         size_t       len)
{
        char * entry;

        if (len < LAYER_NAME_SIZE + 2) /* trailing \n */
                return 0;

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        if (strcmp(entry, info[0]) == 0) { /* _state */
                enum ipcp_state state = ipcp_get_state();
                if (state == IPCP_NULL)
                        strcpy(buf, "null\n");
                else if (state == IPCP_INIT)
                        strcpy(buf, "init\n");
                else if (state == IPCP_OPERATIONAL)
                        strcpy(buf, "operational\n");
                else if (state == IPCP_SHUTDOWN)
                        strcpy(buf, "shutdown\n");
                else
                        strcpy(buf, "bug\n");
        }

        if (strcmp(entry, info[1]) == 0) { /* _type */
                if (ipcpi.type == IPCP_LOCAL)
                        strcpy(buf, "local\n");
                else if (ipcpi.type == IPCP_UNICAST)
                        strcpy(buf, "unicast\n");
                else if (ipcpi.type == IPCP_BROADCAST)
                        strcpy(buf, "broadcast\n");
                else if (ipcpi.type == IPCP_ETH_LLC)
                        strcpy(buf, "eth-llc\n");
                else if (ipcpi.type == IPCP_ETH_DIX)
                        strcpy(buf, "eth-dix\n");
                else if (ipcpi.type == IPCP_UDP)
                        strcpy(buf, "udp\n");
                else
                        strcpy(buf, "bug\n");
        }

        if (strcmp(entry, info[2]) == 0) { /* _layer */
                memset(buf, 0, LAYER_NAME_SIZE + 1);
                if (ipcp_get_state() < IPCP_OPERATIONAL)
                        strcpy(buf, "(null)");
                else
                        strcpy(buf, ipcpi.layer_name);

                buf[strlen(buf)] = '\n';
        }

        return strlen(buf);
}

static int ipcp_rib_readdir(char *** buf)
{
        int  i = 0;

        while (info[i] != NULL)
                i++;

        *buf = malloc(sizeof(**buf) * i);
        if (*buf == NULL)
                goto fail;

        i = 0;

        while (info[i] != NULL) {
                (*buf)[i] = strdup(info[i]);
                if (*buf == NULL)
                        goto fail_dup;
                i++;
        }

        return i;
 fail_dup:
        while (--i > 0)
                free((*buf)[i]);
 fail:
        free(*buf);

        return -1;
}

static int ipcp_rib_getattr(const char *      path,
                            struct rib_attr * attr)
{
        (void) path;

        attr->size = LAYER_NAME_SIZE;

        return 0;
}

static struct rib_ops r_ops = {
        .read    = ipcp_rib_read,
        .readdir = ipcp_rib_readdir,
        .getattr = ipcp_rib_getattr
};

static void * acceptloop(void * o)
{
        int csockfd;

        (void) o;

        while (ipcp_get_state() != IPCP_SHUTDOWN &&
               ipcp_get_state() != IPCP_NULL) {
                struct cmd * cmd;

                csockfd = accept(ipcpi.sockfd, 0, 0);
                if (csockfd < 0)
                        continue;

                cmd = malloc(sizeof(*cmd));
                if (cmd == NULL) {
                        log_err("Out of memory");
                        close(csockfd);
                        break;
                }

                pthread_cleanup_push(__cleanup_close_ptr, &csockfd);
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


static void handle_bootstrap(ipcp_config_msg_t * conf_msg,
                             ipcp_msg_t *        ret_msg)
{
        struct ipcp_config conf;

        assert(ipcp_get_state() == IPCP_INIT);

        if (ipcpi.ops->ipcp_bootstrap == NULL) {
                log_err("Bootstrap unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_INIT) {
                log_err("IPCP in wrong state.");
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        conf = ipcp_config_msg_to_s(conf_msg);
        ret_msg->result = ipcpi.ops->ipcp_bootstrap(&conf);
        if (ret_msg->result == 0) {
                ret_msg->layer_info = layer_info_s_to_msg(&conf.layer_info);
                ipcp_set_state(IPCP_OPERATIONAL);
        }
}

static void handle_enroll(const char * dst,
                          ipcp_msg_t * ret_msg)
{
        struct layer_info info;

        assert(ipcp_get_state() == IPCP_INIT);

        if (ipcpi.ops->ipcp_enroll == NULL) {
                log_err("Enroll unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_INIT) {
                log_err("IPCP in wrong state.");
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_enroll(dst, &info);
        if (ret_msg->result == 0) {
                ret_msg->layer_info = layer_info_s_to_msg(&info);
                ipcp_set_state(IPCP_OPERATIONAL);
        }
}

static void handle_connect(const char * dst,
                           const char * comp,
                           qosspec_t    qs,
                           ipcp_msg_t * ret_msg)
{
        if (ipcpi.ops->ipcp_connect == NULL) {
                log_err("Connect unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_connect(dst, comp, qs);
}

static void handle_disconnect(const char * dst,
                              const char * comp,
                              ipcp_msg_t * ret_msg)
{
        if (ipcpi.ops->ipcp_disconnect == NULL) {
                log_err("Disconnect unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_disconnect(dst, comp);
}

static void handle_reg(const uint8_t * hash,
                       ipcp_msg_t *    ret_msg)
{

        if (ipcpi.ops->ipcp_reg == NULL) {
                log_err("Registration unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_reg(hash);
}

static void handle_unreg(const uint8_t * hash,
                         ipcp_msg_t *    ret_msg)
{
        if (ipcpi.ops->ipcp_unreg == NULL) {
                log_err("Unregistration unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_unreg(hash);
}

static void handle_query(const uint8_t * hash,
                         ipcp_msg_t * ret_msg)
{
        if (ipcpi.ops->ipcp_query == NULL) {
                log_err("Directory query unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("IPCP in wrong state.");
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_query(hash);
}

static void handle_flow_alloc(pid_t        pid,
                              int          flow_id,
                              uint8_t *    dst,
                              qosspec_t    qs,
                              void *       data,
                              size_t       len,
                              ipcp_msg_t * ret_msg)
{
        int fd;

        if (ipcpi.ops->ipcp_flow_alloc == NULL) {
                log_err("Flow allocation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("IPCP in wrong state.");
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        fd = np1_flow_alloc(pid, flow_id);
        if (fd < 0) {
                log_err("Failed allocating fd on flow_id %d.", flow_id);
                ret_msg->result = -EFLOWDOWN;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_flow_alloc(fd, dst, qs, data, len);
}


static void handle_flow_join(pid_t           pid,
                             int             flow_id,
                             const uint8_t * dst,
                             qosspec_t       qs,
                             ipcp_msg_t *    ret_msg)
{
        int fd;

        if (ipcpi.ops->ipcp_flow_join == NULL) {
                log_err("Broadcast unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("IPCP in wrong state.");
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        fd = np1_flow_alloc(pid, flow_id);
        if (fd < 0) {
                log_err("Failed allocating fd on flow_id %d.", flow_id);
                ret_msg->result = -1;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_flow_join(fd, dst, qs);
}

static void handle_flow_alloc_resp(int          resp,
                                   int          flow_id,
                                   const void * data,
                                   size_t       len,
                                   ipcp_msg_t * ret_msg)
{
        int fd = -1;

        if (ipcpi.ops->ipcp_flow_alloc_resp == NULL) {
                log_err("Flow_alloc_resp unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("IPCP in wrong state.");
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        if (resp == 0) {
                fd = np1_flow_resp(flow_id);
                if (fd < 0) {
                        log_warn("Flow_id %d is not known.", flow_id);
                        ret_msg->result = -1;
                        return;
                }
        }

        ret_msg->result = ipcpi.ops->ipcp_flow_alloc_resp(fd, resp, data, len);
}

static void handle_flow_dealloc(int          flow_id,
                                int          timeo_sec,
                                ipcp_msg_t * ret_msg)
{
        int fd;

        if (ipcpi.ops->ipcp_flow_dealloc == NULL) {
                log_err("Flow deallocation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("IPCP in wrong state.");
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        fd = np1_flow_dealloc(flow_id, timeo_sec);
        if (fd < 0) {
                log_warn("Could not deallocate flow_id %d.", flow_id);
                ret_msg->result = -1;
                return;
        }

        ret_msg->result = ipcpi.ops->ipcp_flow_dealloc(fd);
}


static void * mainloop(void * o)
{
        int                 sfd;
        buffer_t            buffer;
        ipcp_msg_t *        msg;

        (void) o;

        while (true) {
                ipcp_msg_t       ret_msg        = IPCP_MSG__INIT;
                qosspec_t        qs;
                struct cmd *     cmd;

                ret_msg.code = IPCP_MSG_CODE__IPCP_REPLY;

                pthread_mutex_lock(&ipcpi.cmd_lock);

                pthread_cleanup_push(__cleanup_mutex_unlock, &ipcpi.cmd_lock);

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

                pthread_cleanup_push(__cleanup_close_ptr, &sfd);
                pthread_cleanup_push(free_msg, msg);

                ret_msg.has_result = true;

                switch (msg->code) {
                case IPCP_MSG_CODE__IPCP_BOOTSTRAP:
                        handle_bootstrap(msg->conf, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_ENROLL:
                        handle_enroll(msg->dst, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_CONNECT:
                        qs = qos_spec_msg_to_s(msg->qosspec);
                        handle_connect(msg->dst, msg->comp, qs, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_DISCONNECT:
                        handle_disconnect(msg->dst, msg->comp, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_REG:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        handle_reg(msg->hash.data, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_UNREG:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        handle_unreg(msg->hash.data, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_QUERY:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        handle_query(msg->hash.data, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        assert(msg->pk.len > 0 ? msg->pk.data != NULL
                                               : msg->pk.data == NULL);
                        qs = qos_spec_msg_to_s(msg->qosspec);
                        handle_flow_alloc(msg->pid, msg->flow_id,
                                          msg->hash.data, qs,
                                          msg->pk.data, msg->pk.len,
                                          &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_JOIN:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        qs = qos_spec_msg_to_s(msg->qosspec);
                        handle_flow_join(msg->pid, msg->flow_id,
                                         msg->hash.data, qs, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP:
                        assert(msg->pk.len > 0 ? msg->pk.data != NULL
                                               : msg->pk.data == NULL);

                        handle_flow_alloc_resp(msg->response, msg->flow_id,
                                               msg->pk.data, msg->pk.len,
                                               &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_DEALLOC:
                        handle_flow_dealloc(msg->flow_id, msg->timeo_sec,
                                            &ret_msg);
                        break;
                default:
                        ret_msg.result     = -1;
                        log_err("Unknown message code: %d.", msg->code);
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

                if (ret_msg.layer_info != NULL)
                        layer_info_msg__free_unpacked(ret_msg.layer_info, NULL);

                pthread_cleanup_push(__cleanup_close_ptr, &sfd);
                pthread_cleanup_push(free, buffer.data)

                if (write(sfd, buffer.data, buffer.len) == -1)
                        log_warn("Failed to send reply message");

                pthread_cleanup_pop(true);
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

        /* argument 1: pid of irm */
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
              struct ipcp_ops * ops,
              enum ipcp_type    type)
{
        bool               log;
        pthread_condattr_t cattr;
        int                ret = -1;

        if (parse_args(argc, argv, &log))
                return -1;

        log_init(log);

        ipcpi.irmd_fd   = -1;
        ipcpi.state     = IPCP_NULL;
        ipcpi.type      = type;

#if defined (__linux__)
        prctl(PR_SET_TIMERSLACK, IPCP_LINUX_SLACK_NS, 0, 0, 0);
#endif
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

        if (rib_init(ipcpi.name)) {
                log_err("Failed to initialize RIB.");
                goto fail_rib_init;
        }

        if (rib_reg(IPCP_INFO, &r_ops))
                goto fail_rib_reg;

        ipcpi.tpm = tpm_create(IPCP_MIN_THREADS, IPCP_ADD_THREADS,
                               mainloop, NULL);
        if (ipcpi.tpm == NULL)
                goto fail_tpm_create;


        list_head_init(&ipcpi.cmds);

        ipcpi.alloc_id = -1;

        pthread_condattr_destroy(&cattr);

        ipcp_set_state(IPCP_INIT);

        return 0;

 fail_tpm_create:
        rib_unreg(IPCP_INFO);
 fail_rib_reg:
        rib_fini();
 fail_rib_init:
        pthread_cond_destroy(&ipcpi.cmd_cond);
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

int ipcp_start(void)
{
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (tpm_start(ipcpi.tpm))
                goto fail_tpm_start;

        if (pthread_create(&ipcpi.acceptor, NULL, acceptloop, NULL)) {
                log_err("Failed to create acceptor thread.");
                goto fail_acceptor;
        }

        if (ipcp_create_r(0)) {
                log_err("Failed to notify IRMd we are initialized.");
                goto fail_create_r;
        }

        return 0;

 fail_create_r:
        pthread_cancel(ipcpi.acceptor);
        pthread_join(ipcpi.acceptor, NULL);
 fail_acceptor:
        ipcp_set_state(IPCP_NULL);
        tpm_stop(ipcpi.tpm);
 fail_tpm_start:
        tpm_destroy(ipcpi.tpm);
        ipcp_create_r(-1);
        return -1;
}

void ipcp_sigwait(void)
{

        siginfo_t info;
        sigset_t  sigset;
#ifdef __APPLE__
        int       sig;
#endif
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGPIPE);

        while(ipcp_get_state() != IPCP_NULL &&
              ipcp_get_state() != IPCP_SHUTDOWN) {
#ifdef __APPLE__
                if (sigwait(&sigset, &sig) < 0) {
#else
                if (sigwaitinfo(&sigset, &info) < 0) {
#endif
                        log_warn("Bad signal.");
                        continue;
                }

#ifdef __APPLE__
                memset(&info, 0, sizeof(info));
                info.si_signo = sig;
                info.si_pid   = ipcpi.irmd_pid;
#endif
                switch(info.si_signo) {
                case SIGINT:
                        /* FALLTHRU */
                case SIGTERM:
                        /* FALLTHRU */
                case SIGHUP:
                        /* FALLTHRU */
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
                        continue;
                default:
                        continue;
                }
        }
}

void ipcp_stop(void)
{
        log_info("IPCP %d shutting down.", getpid());

        pthread_cancel(ipcpi.acceptor);
        pthread_join(ipcpi.acceptor, NULL);

        tpm_stop(ipcpi.tpm);
}

void ipcp_fini(void)
{

        tpm_destroy(ipcpi.tpm);

        rib_unreg(IPCP_INFO);

        rib_fini();

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

enum ipcp_state ipcp_get_state(void)
{
        enum ipcp_state state;

        pthread_mutex_lock(&ipcpi.state_mtx);

        state = ipcpi.state;

        pthread_mutex_unlock(&ipcpi.state_mtx);

        return state;
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
