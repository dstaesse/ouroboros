/*
 * Ouroboros - Copyright (C) 2016 - 2024
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
#define ALLOC_TIMEOUT     50 /* ms */

#include <ouroboros/bitmap.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/hash.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/np1_flow.h>
#include <ouroboros/protobuf.h>
#include <ouroboros/pthread.h>
#include <ouroboros/rib.h>
#include <ouroboros/sockets.h>
#include <ouroboros/time.h>
#include <ouroboros/utils.h>

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

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

static char * ipcp_type_str[] = {
        "local",
        "unicast",
        "broadcast",
        "eth-llc",
        "eth-dix",
        "udp4",
        "udp6"
};

static char * dir_hash_str[] = {
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "CRC32",
        "MD5"
};

static char * ipcp_state_str[] = {
        "null",
        "init",
        "boot",
        "bootstrapped",
        "enrolled",
        "operational",
        "shutdown"
};

struct {
        pid_t              irmd_pid;
        char *             name;

        enum ipcp_type     type;
        char               layer_name[LAYER_NAME_SIZE + 1];

        uint64_t           dt_addr;

        enum hash_algo     dir_hash_algo;

        struct ipcp_ops *  ops;
        int                irmd_fd;

        enum ipcp_state    state;
        pthread_cond_t     state_cond;
        pthread_mutex_t    state_mtx;

        int                sockfd;
        char *             sock_path;

        struct list_head   cmds;
        pthread_cond_t     cmd_cond;
        pthread_mutex_t    cmd_lock;

        int                alloc_id;
        pthread_cond_t     alloc_cond;
        pthread_mutex_t    alloc_lock;

        struct tpm *       tpm;

        pthread_t          acceptor;
} ipcpd;

struct cmd {
        struct list_head next;

        uint8_t          cbuf[SOCK_BUF_SIZE];
        size_t           len;
        int              fd;
};

enum ipcp_type ipcp_get_type(void)
{
        return ipcpd.type;
}

const char * ipcp_get_name(void)
{
        return ipcpd.name;
}

void ipcp_set_dir_hash_algo(enum hash_algo algo)
{
        ipcpd.dir_hash_algo = algo;
}

size_t ipcp_dir_hash_len(void)
{
        return hash_len(ipcpd.dir_hash_algo);
}

uint8_t * ipcp_hash_dup(const uint8_t * hash)
{
        uint8_t * dup = malloc(hash_len(ipcpd.dir_hash_algo));
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

static const char * info[] = {
        "_state",
        "_type",
        "_layer",
        NULL
};

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
                if (ipcpd.type == IPCP_LOCAL)
                        strcpy(buf, "local\n");
                else if (ipcpd.type == IPCP_UNICAST)
                        strcpy(buf, "unicast\n");
                else if (ipcpd.type == IPCP_BROADCAST)
                        strcpy(buf, "broadcast\n");
                else if (ipcpd.type == IPCP_ETH_LLC)
                        strcpy(buf, "eth-llc\n");
                else if (ipcpd.type == IPCP_ETH_DIX)
                        strcpy(buf, "eth-dix\n");
                else if (ipcpd.type == IPCP_UDP4)
                        strcpy(buf, "udp4\n");
                else if (ipcpd.type == IPCP_UDP6)
                        strcpy(buf, "udp6\n");
                else
                        strcpy(buf, "bug\n");
        }

        if (strcmp(entry, info[2]) == 0) { /* _layer */
                memset(buf, 0, LAYER_NAME_SIZE + 1);
                if (ipcp_get_state() < IPCP_OPERATIONAL)
                        strcpy(buf, "(null)");
                else
                        strcpy(buf, ipcpd.layer_name);

                buf[strlen(buf)] = '\n';
        }

        return strlen(buf);
}

static int ipcp_rib_readdir(char *** buf)
{
        int  i = 0;

        while (info[i++] != NULL);

        *buf = malloc(sizeof(**buf) * i);
        if (*buf == NULL)
                goto fail_entries;

        i = 0;

        while (info[i] != NULL) {
                (*buf)[i] = strdup(info[i]);
                if ((*buf)[i] == NULL)
                        goto fail_dup;
                i++;
        }

        return i;
 fail_dup:
        while (i-- > 0)
                free((*buf)[i]);
        free(*buf);
 fail_entries:
        return -ENOMEM;
}

static int ipcp_rib_getattr(const char *      path,
                            struct rib_attr * attr)
{
        char buf[LAYER_NAME_SIZE + 2];
        struct timespec now;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        attr->size = ipcp_rib_read(path, buf, LAYER_NAME_SIZE + 2);
        attr->mtime = now.tv_sec;

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
               ipcp_get_state() != IPCP_INIT) {
                struct cmd * cmd;

                csockfd = accept(ipcpd.sockfd, 0, 0);
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

                pthread_mutex_lock(&ipcpd.cmd_lock);

                list_add(&cmd->next, &ipcpd.cmds);

                pthread_cond_signal(&ipcpd.cmd_cond);

                pthread_mutex_unlock(&ipcpd.cmd_lock);
        }

        return (void *) 0;
}

int ipcp_wait_flow_req_arr(const uint8_t *  dst,
                           qosspec_t        qs,
                           time_t           mpl,
                           const buffer_t * data)
{
        struct timespec ts = TIMESPEC_INIT_MS(ALLOC_TIMEOUT);
        struct timespec abstime;
        int             fd;
        buffer_t        hash;

        hash.data = (uint8_t *) dst;
        hash.len  = ipcp_dir_hash_len();

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpd.alloc_lock);

        while (ipcpd.alloc_id != -1 && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpd.alloc_cond,
                                       &ipcpd.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_mutex_unlock(&ipcpd.alloc_lock);
                log_err("Won't allocate over non-operational IPCP.");
                return -EIPCPSTATE;
        }

        assert(ipcpd.alloc_id == -1);

        fd = ipcp_flow_req_arr(&hash, qs, mpl, data);
        if (fd < 0) {
                pthread_mutex_unlock(&ipcpd.alloc_lock);
                log_err("Failed to get fd for flow.");
                return fd;
        }

        ipcpd.alloc_id = fd;
        pthread_cond_broadcast(&ipcpd.alloc_cond);

        pthread_mutex_unlock(&ipcpd.alloc_lock);

        return fd;

}

int ipcp_wait_flow_resp(const int fd)
{
        struct timespec ts = TIMESPEC_INIT_MS(ALLOC_TIMEOUT);
        struct timespec abstime;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpd.alloc_lock);

        while (ipcpd.alloc_id != fd && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpd.alloc_cond,
                                       &ipcpd.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_mutex_unlock(&ipcpd.alloc_lock);
                return -1;
        }

        assert(ipcpd.alloc_id == fd);

        ipcpd.alloc_id = -1;
        pthread_cond_broadcast(&ipcpd.alloc_cond);

        pthread_mutex_unlock(&ipcpd.alloc_lock);

        return 0;
}

static void free_msg(void * o)
{
        ipcp_msg__free_unpacked((ipcp_msg_t *) o, NULL);
}


static void do_bootstrap(ipcp_config_msg_t * conf_msg,
                         ipcp_msg_t *        ret_msg)
{
        struct ipcp_config  conf;
        struct layer_info * info;

        log_info("Bootstrapping...");

        if (ipcpd.ops->ipcp_bootstrap == NULL) {
                log_err("Failed to Bootstrap: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_BOOT) {

                log_err("Failed to bootstrap: IPCP in state <%s>, need <%s>.",
                        ipcp_state_str[ipcp_get_state()],
                        ipcp_state_str[IPCP_BOOT]);
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        conf = ipcp_config_msg_to_s(conf_msg);
        switch(conf.type) { /* FIXED algorithms */
        case IPCP_UDP4:
                /* FALLTHRU */
        case IPCP_UDP6:
                conf.layer_info.dir_hash_algo = (enum pol_dir_hash) HASH_MD5;
                break;
        case IPCP_BROADCAST:
                conf.layer_info.dir_hash_algo = DIR_HASH_SHA3_256;
                break;
        default:
                break;
        }

        ret_msg->result = ipcpd.ops->ipcp_bootstrap(&conf);
        if (ret_msg->result < 0) {
                log_err("Failed to bootstrap IPCP.");
                return;
        }

        info = &conf.layer_info;

        strcpy(ipcpd.layer_name, info->name);
        ipcpd.dir_hash_algo = (enum hash_algo) info->dir_hash_algo;
        ret_msg->layer_info = layer_info_s_to_msg(info);
        ipcp_set_state(IPCP_OPERATIONAL);

        log_info("Finished bootstrapping in %s.", info->name);
        log_info("  type: %s", ipcp_type_str[ipcpd.type]);
        log_info("  hash: %s [%zd bytes]",
                dir_hash_str[ipcpd.dir_hash_algo],
                ipcp_dir_hash_len());
}

static void do_enroll(const char * dst,
                      ipcp_msg_t * ret_msg)
{
        struct layer_info info;

        log_info("Enrolling with %s...", dst);

        if (ipcpd.ops->ipcp_enroll == NULL) {
                log_err("Failed to enroll: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_BOOT) {
                log_err("Failed to enroll: IPCP in state <%s>, need <%s>.",
                        ipcp_state_str[ipcp_get_state()],
                        ipcp_state_str[IPCP_BOOT]);
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_enroll(dst, &info);
        if (ret_msg->result < 0) {
                log_err("Failed to bootstrap IPCP.");
                return;
        }

        strcpy(ipcpd.layer_name, info.name);
        ipcpd.dir_hash_algo = (enum hash_algo) info.dir_hash_algo;
        ret_msg->layer_info = layer_info_s_to_msg(&info);
        ipcp_set_state(IPCP_OPERATIONAL);

        log_info("Finished enrolling with %s in layer %s.", dst, info.name);
        log_info("  type: %s", ipcp_type_str[ipcpd.type]);
        log_info("  hash: %s [%zd bytes]",
                dir_hash_str[ipcpd.dir_hash_algo],
                ipcp_dir_hash_len());
}

static void do_connect(const char * dst,
                       const char * comp,
                       qosspec_t    qs,
                       ipcp_msg_t * ret_msg)
{
        log_info("Connecting %s to %s...", comp, dst);

        if (ipcpd.ops->ipcp_connect == NULL) {
                log_err("Failed to connect: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_connect(dst, comp, qs);

        log_info("Finished connecting.");
}

static void do_disconnect(const char * dst,
                          const char * comp,
                          ipcp_msg_t * ret_msg)
{
        log_info("Disconnecting %s from %s...", comp, dst);

        if (ipcpd.ops->ipcp_disconnect == NULL) {
                log_err("Failed to disconnect: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_disconnect(dst, comp);

        log_info("Finished disconnecting %s from %s.", comp, dst);
}

static void do_reg(const uint8_t * hash,
                   ipcp_msg_t *    ret_msg)
{

        log_info("Registering " HASH_FMT32 "...", HASH_VAL32(hash));

        if (ipcpd.ops->ipcp_reg == NULL) {
                log_err("Failed to register: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_reg(hash);

        log_info("Finished registering " HASH_FMT32 ".", HASH_VAL32(hash));
}

static void do_unreg(const uint8_t * hash,
                     ipcp_msg_t *    ret_msg)
{
        log_info("Unregistering " HASH_FMT32 "...", HASH_VAL32(hash));

        if (ipcpd.ops->ipcp_unreg == NULL) {
                log_err("Failed to unregister: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_unreg(hash);

        log_info("Finished unregistering " HASH_FMT32 ".", HASH_VAL32(hash));
}

static void do_query(const uint8_t * hash,
                     ipcp_msg_t *    ret_msg)
{
        /*  TODO: Log this operation when IRMd has internal caches. */

        if (ipcpd.ops->ipcp_query == NULL) {
                log_err("Failed to query: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_dbg("Failed to query: IPCP in state <%s>, need <%s>.",
                        ipcp_state_str[ipcp_get_state()],
                        ipcp_state_str[IPCP_OPERATIONAL]);
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_query(hash);
}

static void do_flow_alloc(pid_t            pid,
                          int              flow_id,
                          uint8_t *        dst,
                          qosspec_t        qs,
                          const buffer_t * data,
                          ipcp_msg_t *     ret_msg)
{
        int fd;

        log_info("Allocating flow %d for %d to " HASH_FMT32 ".",
                 flow_id, pid, HASH_VAL32(dst));

        if (ipcpd.ops->ipcp_flow_alloc == NULL) {
                log_err("Flow allocation failed: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("Failed to enroll: IPCP in state <%s>, need <%s>.",
                        ipcp_state_str[ipcp_get_state()],
                        ipcp_state_str[IPCP_OPERATIONAL]);
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        fd = np1_flow_alloc(pid, flow_id);
        if (fd < 0) {
                log_err("Failed allocating n + 1 fd on flow_id %d: %d",
                        flow_id, fd);
                ret_msg->result = -EFLOWDOWN;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_flow_alloc(fd, dst, qs, data);

        log_info("Finished allocating flow %d to " HASH_FMT32 ".",
                 flow_id, HASH_VAL32(dst));
}


static void do_flow_join(pid_t           pid,
                         int             flow_id,
                         const uint8_t * dst,
                         qosspec_t       qs,
                         ipcp_msg_t *    ret_msg)
{
        int fd;

        log_info("Joining layer " HASH_FMT32 ".", HASH_VAL32(dst));

        if (ipcpd.ops->ipcp_flow_join == NULL) {
                log_err("Failed to join: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("Failed to join: IPCP in state <%s>, need <%s>.",
                        ipcp_state_str[ipcp_get_state()],
                        ipcp_state_str[IPCP_OPERATIONAL]);
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        fd = np1_flow_alloc(pid, flow_id);
        if (fd < 0) {
                log_err("Failed allocating n + 1 fd on flow_id %d.", flow_id);
                ret_msg->result = -1;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_flow_join(fd, dst, qs);

        log_info("Finished joining layer " HASH_FMT32 ".", HASH_VAL32(dst));
}

static void do_flow_alloc_resp(int              resp,
                               int              flow_id,
                               const buffer_t * data,
                               ipcp_msg_t *     ret_msg)
{
        int fd = -1;

        log_info("Responding %d to alloc on flow_id %d.", resp, flow_id);

        if (ipcpd.ops->ipcp_flow_alloc_resp == NULL) {
                log_err("Failed to respond on flow %d: operation unsupported.",
                        flow_id);
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("Failed to respond to flow %d:"
                        "IPCP in state <%s>, need <%s>.",
                        flow_id,
                        ipcp_state_str[ipcp_get_state()],
                        ipcp_state_str[IPCP_OPERATIONAL]);
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        fd = np1_flow_resp(flow_id, resp);
        if (fd < 0) {
                log_warn("Flow_id %d is not known.", flow_id);
                ret_msg->result = -1;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_flow_alloc_resp(fd, resp, data);

        log_info("Finished responding %d to allocation request.",
                 ret_msg->result);
}

static void do_flow_dealloc(int          flow_id,
                            int          timeo_sec,
                            ipcp_msg_t * ret_msg)
{
        int fd;

        log_info("Deallocating flow %d.", flow_id);

        if (ipcpd.ops->ipcp_flow_dealloc == NULL) {
                log_err("Failed to dealloc: operation unsupported.");
                ret_msg->result = -ENOTSUP;
                return;
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_err("Failed to enroll: IPCP in state <%s>, need <%s>.",
                        ipcp_state_str[ipcp_get_state()],
                        ipcp_state_str[IPCP_OPERATIONAL]);
                ret_msg->result = -EIPCPSTATE;
                return;
        }

        fd = np1_flow_dealloc(flow_id, timeo_sec);
        if (fd < 0) {
                log_warn("Could not deallocate flow_id %d.", flow_id);
                ret_msg->result = -1;
                return;
        }

        ret_msg->result = ipcpd.ops->ipcp_flow_dealloc(fd);

        log_info("Finished deallocating flow %d.", flow_id);
}

static void * mainloop(void * o)
{
        int          sfd;
        buffer_t     buffer;
        ipcp_msg_t * msg;

        (void) o;

        while (true) {
                ipcp_msg_t   ret_msg = IPCP_MSG__INIT;
                qosspec_t    qs;
                struct cmd * cmd;
                buffer_t     data;

                ret_msg.code = IPCP_MSG_CODE__IPCP_REPLY;

                pthread_mutex_lock(&ipcpd.cmd_lock);

                pthread_cleanup_push(__cleanup_mutex_unlock, &ipcpd.cmd_lock);

                while (list_is_empty(&ipcpd.cmds))
                        pthread_cond_wait(&ipcpd.cmd_cond, &ipcpd.cmd_lock);

                cmd = list_last_entry(&ipcpd.cmds, struct cmd, next);
                list_del(&cmd->next);

                pthread_cleanup_pop(true);

                msg = ipcp_msg__unpack(NULL, cmd->len, cmd->cbuf);
                sfd = cmd->fd;

                free(cmd);

                if (msg == NULL) {
                        close(sfd);
                        continue;
                }

                tpm_begin_work(ipcpd.tpm);

                pthread_cleanup_push(__cleanup_close_ptr, &sfd);
                pthread_cleanup_push(free_msg, msg);

                ret_msg.has_result = true;

                switch (msg->code) {
                case IPCP_MSG_CODE__IPCP_BOOTSTRAP:
                        do_bootstrap(msg->conf, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_ENROLL:
                        do_enroll(msg->dst, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_CONNECT:
                        qs = qos_spec_msg_to_s(msg->qosspec);
                        do_connect(msg->dst, msg->comp, qs, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_DISCONNECT:
                        do_disconnect(msg->dst, msg->comp, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_REG:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        do_reg(msg->hash.data, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_UNREG:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        do_unreg(msg->hash.data, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_QUERY:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        do_query(msg->hash.data, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        assert(msg->pk.len > 0 ? msg->pk.data != NULL
                                               : msg->pk.data == NULL);
                        data.len = msg->pk.len;
                        data.data = msg->pk.data;
                        qs = qos_spec_msg_to_s(msg->qosspec);
                        do_flow_alloc(msg->pid, msg->flow_id,
                                      msg->hash.data, qs,
                                      &data, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_JOIN:
                        assert(msg->hash.len == ipcp_dir_hash_len());
                        qs = qos_spec_msg_to_s(msg->qosspec);
                        do_flow_join(msg->pid, msg->flow_id,
                                     msg->hash.data, qs, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP:
                        assert(msg->pk.len > 0 ? msg->pk.data != NULL
                                               : msg->pk.data == NULL);
                        data.len = msg->pk.len;
                        data.data = msg->pk.data;
                        do_flow_alloc_resp(msg->response, msg->flow_id,
                                           &data, &ret_msg);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_DEALLOC:
                        do_flow_dealloc(msg->flow_id, msg->timeo_sec, &ret_msg);
                        break;
                default:
                        ret_msg.result = -1;
                        log_err("Unknown message code: %d.", msg->code);
                        break;
                }

                pthread_cleanup_pop(true);
                pthread_cleanup_pop(false);

                buffer.len = ipcp_msg__get_packed_size(&ret_msg);
                if (buffer.len == 0) {
                        log_err("Failed to pack reply message");
                        close(sfd);
                        tpm_end_work(ipcpd.tpm);
                        continue;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        log_err("Failed to create reply buffer.");
                        close(sfd);
                        tpm_end_work(ipcpd.tpm);
                        continue;
                }

                ipcp_msg__pack(&ret_msg, buffer.data);

                if (ret_msg.layer_info != NULL)
                        layer_info_msg__free_unpacked(ret_msg.layer_info, NULL);

                pthread_cleanup_push(free, buffer.data)
                pthread_cleanup_push(__cleanup_close_ptr, &sfd);

                if (write(sfd, buffer.data, buffer.len) == -1)
                        log_warn("Failed to send reply message");

                pthread_cleanup_pop(true); /* close sfd */
                pthread_cleanup_pop(true); /* free buffer.data */

                tpm_end_work(ipcpd.tpm);
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

        ipcpd.irmd_pid = atoi(argv[1]);

        /* argument 2: IPCP name */
        ipcpd.name = argv[2];

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

        if (parse_args(argc, argv, &log))
                return -1;

        log_init(log);

        ipcpd.type  = type;

#if defined (__linux__)
        prctl(PR_SET_TIMERSLACK, IPCP_LINUX_SLACK_NS, 0, 0, 0);
#endif
        ipcpd.sock_path = sock_path(getpid(), IPCP_SOCK_PATH_PREFIX);
        if (ipcpd.sock_path == NULL)
                goto fail_sock_path;

        ipcpd.sockfd = server_socket_open(ipcpd.sock_path);
        if (ipcpd.sockfd < 0) {
                log_err("Failed to open server socket at %s.",
                        ipcpd.sock_path);
                goto fail_serv_sock;
        }

        ipcpd.ops = ops;

        if (pthread_mutex_init(&ipcpd.state_mtx, NULL)) {
                log_err("Failed to create mutex.");
                goto fail_state_mtx;
        }

        if (pthread_condattr_init(&cattr)) {
                log_err("Failed to create condattr.");
                goto fail_cond_attr;
        }

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&ipcpd.state_cond, &cattr)) {
                log_err("Failed to init condvar.");
                goto fail_state_cond;
        }

        if (pthread_mutex_init(&ipcpd.alloc_lock, NULL)) {
                log_err("Failed to init mutex.");
                goto fail_alloc_lock;
        }

        if (pthread_cond_init(&ipcpd.alloc_cond, &cattr)) {
                log_err("Failed to init convar.");
                goto fail_alloc_cond;
        }

        if (pthread_mutex_init(&ipcpd.cmd_lock, NULL)) {
                log_err("Failed to init mutex.");
                goto fail_cmd_lock;
        }

        if (pthread_cond_init(&ipcpd.cmd_cond, &cattr)) {
                log_err("Failed to init convar.");
                goto fail_cmd_cond;
        }

        if (rib_init(ipcpd.name)) {
                log_err("Failed to initialize RIB.");
                goto fail_rib_init;
        }

        if (rib_reg(IPCP_INFO, &r_ops)) {
                log_err("Failed to register rib.");
                goto fail_rib_reg;
        }

        list_head_init(&ipcpd.cmds);

        ipcpd.tpm = tpm_create(IPCP_MIN_THREADS, IPCP_ADD_THREADS,
                               mainloop, NULL);
        if (ipcpd.tpm == NULL) {
                log_err("Failed to create threadpool manager.");
                goto fail_tpm_create;
        }

        ipcpd.alloc_id = -1;

        pthread_condattr_destroy(&cattr);

        ipcp_set_state(IPCP_INIT);

        log_info("IPCP %s %d initialized.", ipcp_type_str[ipcpd.type],
                 getpid());

        return 0;

 fail_tpm_create:
        rib_unreg(IPCP_INFO);
 fail_rib_reg:
        rib_fini();
 fail_rib_init:
        pthread_cond_destroy(&ipcpd.cmd_cond);
 fail_cmd_cond:
        pthread_mutex_destroy(&ipcpd.cmd_lock);
 fail_cmd_lock:
        pthread_cond_destroy(&ipcpd.alloc_cond);
 fail_alloc_cond:
        pthread_mutex_destroy(&ipcpd.alloc_lock);
 fail_alloc_lock:
        pthread_cond_destroy(&ipcpd.state_cond);
 fail_state_cond:
        pthread_condattr_destroy(&cattr);
 fail_cond_attr:
        pthread_mutex_destroy(&ipcpd.state_mtx);
 fail_state_mtx:
        close(ipcpd.sockfd);
 fail_serv_sock:
        free(ipcpd.sock_path);
 fail_sock_path:
        return -1;
}

int ipcp_start(void)
{
        sigset_t         sigset;
        struct ipcp_info info;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        info.pid  = getpid();
        info.type = ipcpd.type;
        strcpy(info.name, ipcpd.name);
        info.state = IPCP_BOOT;

        ipcp_set_state(IPCP_BOOT);

        if (tpm_start(ipcpd.tpm)) {
                log_err("Failed to start threadpool manager.");
                goto fail_tpm_start;
        }

        if (pthread_create(&ipcpd.acceptor, NULL, acceptloop, NULL)) {
                log_err("Failed to create acceptor thread.");
                goto fail_acceptor;
        }

        if (ipcp_create_r(&info)) {
                log_err("Failed to notify IRMd we are initialized.");
                goto fail_create_r;
        }

        return 0;

 fail_create_r:
        pthread_cancel(ipcpd.acceptor);
        pthread_join(ipcpd.acceptor, NULL);
 fail_acceptor:
        tpm_stop(ipcpd.tpm);
 fail_tpm_start:
        tpm_destroy(ipcpd.tpm);
        ipcp_set_state(IPCP_INIT);
        ipcp_create_r(&info);
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

        while(ipcp_get_state() != IPCP_INIT &&
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
                info.si_pid   = ipcpd.irmd_pid;
#endif
                switch(info.si_signo) {
                case SIGINT:
                        /* FALLTHRU */
                case SIGTERM:
                        /* FALLTHRU */
                case SIGHUP:
                        /* FALLTHRU */
                case SIGQUIT:
                        if (info.si_pid == ipcpd.irmd_pid) {
                                if (ipcp_get_state() == IPCP_BOOT)
                                        ipcp_set_state(IPCP_INIT);

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

        pthread_cancel(ipcpd.acceptor);
        pthread_join(ipcpd.acceptor, NULL);

        tpm_stop(ipcpd.tpm);

        ipcp_set_state(IPCP_INIT);
}

void ipcp_fini(void)
{

        tpm_destroy(ipcpd.tpm);

        rib_unreg(IPCP_INFO);

        rib_fini();

        close(ipcpd.sockfd);
        if (unlink(ipcpd.sock_path))
                log_warn("Could not unlink %s.", ipcpd.sock_path);

        free(ipcpd.sock_path);

        pthread_cond_destroy(&ipcpd.state_cond);
        pthread_mutex_destroy(&ipcpd.state_mtx);
        pthread_cond_destroy(&ipcpd.alloc_cond);
        pthread_mutex_destroy(&ipcpd.alloc_lock);
        pthread_cond_destroy(&ipcpd.cmd_cond);
        pthread_mutex_destroy(&ipcpd.cmd_lock);

        log_info("IPCP %d out.", getpid());

        log_fini();

        ipcpd.state = IPCP_NULL;
}

void ipcp_set_state(enum ipcp_state state)
{
        pthread_mutex_lock(&ipcpd.state_mtx);

        ipcpd.state = state;

        pthread_cond_broadcast(&ipcpd.state_cond);
        pthread_mutex_unlock(&ipcpd.state_mtx);
}

enum ipcp_state ipcp_get_state(void)
{
        enum ipcp_state state;

        pthread_mutex_lock(&ipcpd.state_mtx);

        state = ipcpd.state;

        pthread_mutex_unlock(&ipcpd.state_mtx);

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
