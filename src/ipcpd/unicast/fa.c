/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Flow allocator of the IPC Process
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
#endif

#include "config.h"

#define FA               "flow-allocator"
#define OUROBOROS_PREFIX FA

#include <ouroboros/logs.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/rib.h>

#include "dir.h"
#include "fa.h"
#include "psched.h"
#include "ipcp.h"
#include "dt.h"
#include "ca.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define TIMEOUT 10000 /* nanoseconds */

#define FLOW_REQ    0
#define FLOW_REPLY  1
#define FLOW_UPDATE 2
#define MSGBUFSZ    2048

#define STAT_FILE_LEN 0

struct fa_msg {
        uint64_t s_addr;
        uint32_t r_eid;
        uint32_t s_eid;
        uint8_t  code;
        int8_t   response;
        uint16_t ece;
        /* QoS parameters from spec, aligned */
        uint8_t  availability;
        uint8_t  in_order;
        uint32_t delay;
        uint64_t bandwidth;
        uint32_t loss;
        uint32_t ber;
        uint32_t max_gap;
        uint16_t cypher_s;
} __attribute__((packed));

struct cmd {
        struct list_head     next;
        struct shm_du_buff * sdb;
};

struct fa_flow {
#ifdef IPCP_FLOW_STATS
        time_t   stamp;
#endif
        int      r_eid;  /* remote endpoint id               */
        uint64_t r_addr; /* remote address                   */
        void *   ctx;    /* congestion avoidance context     */
};

struct {
        pthread_rwlock_t flows_lock;
        struct fa_flow   flows[PROG_MAX_FLOWS];
#ifdef IPCP_FLOW_STATS
        size_t           n_flows;
#endif
        int              fd;

        struct list_head cmds;
        pthread_cond_t   cond;
        pthread_mutex_t  mtx;
        pthread_t        worker;

        struct psched *  psched;
} fa;

static int fa_stat_read(const char * path,
                        char *       buf,
                        size_t       len)
{
#ifdef IPCP_FLOW_STATS
        struct fa_flow * flow;
        int              fd;
        char             r_addrstr[20];
        char             tmstr[20];
        char             castr[1024];
        struct tm *      tm;

        fd = atoi(path);

        if (fd < 0 || fd > PROG_MAX_FLOWS)
                return -1;

        if (len < 1536)
                return 0;

        flow = &fa.flows[fd];

        buf[0] = '\0';

        pthread_rwlock_rdlock(&fa.flows_lock);

        if (flow->stamp ==0) {
                pthread_rwlock_unlock(&fa.flows_lock);
                return 0;
        }

        sprintf(r_addrstr, "%" PRIu64, flow->r_addr);

        tm = localtime(&flow->stamp);
        strftime(tmstr, sizeof(tmstr), "%F %T", tm);

        ca_print_stats(flow->ctx, castr, 1024);

        sprintf(buf,
                "Flow established at:             %20s\n"
                "Remote address:                  %20s\n"
                "Local endpoint ID:               %20d\n"
                "Remote endpoint ID:              %20d\n"
                "%s",
                tmstr, r_addrstr, fd, flow->r_eid,
                castr);

        pthread_rwlock_unlock(&fa.flows_lock);

        return strlen(buf);
#else
        (void) path;
        (void) buf;
        (void) len;
        return 0;
#endif
}

static int fa_stat_readdir(char *** buf)
{
#ifdef IPCP_FLOW_STATS
        char   entry[RIB_PATH_LEN + 1];
        size_t i;
        int    idx = 0;

        pthread_rwlock_rdlock(&fa.flows_lock);

        if (fa.n_flows < 1) {
                pthread_rwlock_unlock(&fa.flows_lock);
                return 0;
        }

        *buf = malloc(sizeof(**buf) * fa.n_flows);
        if (*buf == NULL) {
                pthread_rwlock_unlock(&fa.flows_lock);
                return -ENOMEM;
        }

        for (i = 0; i < PROG_MAX_FLOWS; ++i) {
                struct fa_flow * flow;

                flow = &fa.flows[i];
                if (flow->stamp == 0)
                        continue;

                sprintf(entry, "%zu", i);

                (*buf)[idx] = malloc(strlen(entry) + 1);
                if ((*buf)[idx] == NULL) {
                        while (idx-- > 0)
                                free((*buf)[idx]);
                        free(buf);
                        pthread_rwlock_unlock(&fa.flows_lock);
                        return -ENOMEM;
                }

                strcpy((*buf)[idx++], entry);
        }

        assert((size_t) idx == fa.n_flows);

        pthread_rwlock_unlock(&fa.flows_lock);

        return idx;
#else
        (void) buf;
        return 0;
#endif
}

static int fa_stat_getattr(const char *  path,
                           struct stat * st)
{
#ifdef IPCP_FLOW_STATS
        int              fd;
        struct fa_flow * flow;

        fd = atoi(path);

        st->st_mode  = S_IFREG | 0755;
        st->st_nlink = 1;
        st->st_uid   = getuid();
        st->st_gid   = getgid();

        flow = &fa.flows[fd];

        pthread_rwlock_rdlock(&fa.flows_lock);

        if (flow->stamp != 0) {
                st->st_size  = 1536;
                st->st_mtime = flow->stamp;
        } else {
                st->st_size  = 0;
                st->st_mtime = 0;
        }

        pthread_rwlock_unlock(&fa.flows_lock);
#else
        (void) path;
        (void) st;
#endif
        return 0;
}

static struct rib_ops r_ops = {
        .read    = fa_stat_read,
        .readdir = fa_stat_readdir,
        .getattr = fa_stat_getattr
};

static void packet_handler(int                  fd,
                           qoscube_t            qc,
                           struct shm_du_buff * sdb)
{
        struct fa_flow * flow;
        uint64_t         r_addr;
        uint32_t         r_eid;
        ca_wnd_t         wnd;
        size_t           len;

        flow = &fa.flows[fd];

        pthread_rwlock_wrlock(&fa.flows_lock);

        len = shm_du_buff_tail(sdb) - shm_du_buff_head(sdb);

        wnd = ca_ctx_update_snd(flow->ctx, len);

        r_addr = flow->r_addr;
        r_eid  = flow->r_eid;

        pthread_rwlock_unlock(&fa.flows_lock);

        ca_wnd_wait(wnd);

        if (dt_write_packet(r_addr, qc, r_eid, sdb)) {
                ipcp_sdb_release(sdb);
                log_warn("Failed to forward packet.");
                return;
        }
}

static int fa_flow_init(struct fa_flow * flow)
{
#ifdef IPCP_FLOW_STATS
        struct timespec now;
#endif
        memset(flow, 0, sizeof(*flow));

        flow->r_eid  = -1;
        flow->r_addr = INVALID_ADDR;

        flow->ctx = ca_ctx_create();
        if (flow->ctx == NULL)
                return -1;

#ifdef IPCP_FLOW_STATS
        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        flow->stamp = now.tv_sec;

        ++fa.n_flows;
#endif
        return 0;
}

static void fa_flow_fini(struct fa_flow * flow)
{
        ca_ctx_destroy(flow->ctx);

        memset(flow, 0, sizeof(*flow));

        flow->r_eid  = -1;
        flow->r_addr = INVALID_ADDR;

#ifdef IPCP_FLOW_STATS
        --fa.n_flows;
#endif
}

static void fa_post_packet(void *               comp,
                           struct shm_du_buff * sdb)
{
        struct cmd * cmd;

        assert(comp == &fa);

        (void) comp;

        cmd = malloc(sizeof(*cmd));
        if (cmd == NULL) {
                log_err("Command failed. Out of memory.");
                ipcp_sdb_release(sdb);
                return;
        }

        cmd->sdb = sdb;

        pthread_mutex_lock(&fa.mtx);

        list_add(&cmd->next, &fa.cmds);

        pthread_cond_signal(&fa.cond);

        pthread_mutex_unlock(&fa.mtx);
}

static void * fa_handle_packet(void * o)
{
        struct timespec ts  = {0, TIMEOUT * 1000};

        (void) o;

        while (true) {
                struct timespec  abstime;
                int              fd;
                uint8_t          buf[MSGBUFSZ];
                struct fa_msg *  msg;
                qosspec_t        qs;
                struct cmd *     cmd;
                size_t           len;
                size_t           msg_len;
                struct fa_flow * flow;

                pthread_mutex_lock(&fa.mtx);

                pthread_cleanup_push((void (*)(void *)) pthread_mutex_unlock,
                                     &fa.mtx);

                while (list_is_empty(&fa.cmds))
                        pthread_cond_wait(&fa.cond, &fa.mtx);

                cmd = list_last_entry(&fa.cmds, struct cmd, next);
                list_del(&cmd->next);

                pthread_cleanup_pop(true);

                len = shm_du_buff_tail(cmd->sdb) - shm_du_buff_head(cmd->sdb);

                if (len > MSGBUFSZ) {
                        log_err("Message over buffer size.");
                        free(cmd);
                        continue;
                }

                msg = (struct fa_msg *) buf;

                /* Depending on the message call the function in ipcp-dev.h */

                memcpy(msg, shm_du_buff_head(cmd->sdb), len);

                ipcp_sdb_release(cmd->sdb);

                free(cmd);

                switch (msg->code) {
                case FLOW_REQ:
                        msg_len = sizeof(*msg) + ipcp_dir_hash_len();

                        assert(len >= msg_len);

                        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

                        pthread_mutex_lock(&ipcpi.alloc_lock);

                        while (ipcpi.alloc_id != -1 &&
                               ipcp_get_state() == IPCP_OPERATIONAL) {
                                ts_add(&abstime, &ts, &abstime);
                                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                                       &ipcpi.alloc_lock,
                                                       &abstime);
                        }

                        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                                pthread_mutex_unlock(&ipcpi.alloc_lock);
                                log_dbg("Won't allocate over non-operational"
                                        "IPCP.");
                                continue;
                        }

                        assert(ipcpi.alloc_id == -1);

                        qs.delay        = ntoh32(msg->delay);
                        qs.bandwidth    = ntoh64(msg->bandwidth);
                        qs.availability = msg->availability;
                        qs.loss         = ntoh32(msg->loss);
                        qs.ber          = ntoh32(msg->ber);
                        qs.in_order     = msg->in_order;
                        qs.max_gap      = ntoh32(msg->max_gap);
                        qs.cypher_s     = ntoh16(msg->cypher_s);

                        fd = ipcp_flow_req_arr((uint8_t *) (msg + 1),
                                               ipcp_dir_hash_len(),
                                               qs,
                                               buf + msg_len,
                                               len - msg_len);
                        if (fd < 0) {
                                pthread_mutex_unlock(&ipcpi.alloc_lock);
                                log_err("Failed to get fd for flow.");
                                continue;
                        }

                        flow = &fa.flows[fd];

                        pthread_rwlock_wrlock(&fa.flows_lock);

                        fa_flow_init(flow);

                        flow->r_eid  = ntoh32(msg->s_eid);
                        flow->r_addr = ntoh64(msg->s_addr);

                        pthread_rwlock_unlock(&fa.flows_lock);

                        ipcpi.alloc_id = fd;
                        pthread_cond_broadcast(&ipcpi.alloc_cond);

                        pthread_mutex_unlock(&ipcpi.alloc_lock);

                        break;
                case FLOW_REPLY:
                        assert(len >= sizeof(*msg));

                        flow = &fa.flows[ntoh32(msg->r_eid)];

                        pthread_rwlock_wrlock(&fa.flows_lock);

                        flow->r_eid = ntoh32(msg->s_eid);

                        if (msg->response < 0)
                                fa_flow_fini(flow);
                        else
                                psched_add(fa.psched, ntoh32(msg->r_eid));

                        pthread_rwlock_unlock(&fa.flows_lock);

                        ipcp_flow_alloc_reply(ntoh32(msg->r_eid),
                                              msg->response,
                                              buf + sizeof(*msg),
                                              len - sizeof(*msg));
                        break;
                case FLOW_UPDATE:
                        assert(len >= sizeof(*msg));

                        flow = &fa.flows[ntoh32(msg->r_eid)];

                        pthread_rwlock_wrlock(&fa.flows_lock);

                        ca_ctx_update_ece(flow->ctx, ntoh16(msg->ece));

                        pthread_rwlock_unlock(&fa.flows_lock);

                        break;
                default:
                        log_err("Got an unknown flow allocation message.");
                        break;
                }
        }
}

int fa_init(void)
{
        pthread_condattr_t cattr;
        char               fastr[256];

        if (pthread_rwlock_init(&fa.flows_lock, NULL))
                goto fail_rwlock;

        if (pthread_mutex_init(&fa.mtx, NULL))
                goto fail_mtx;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&fa.cond, &cattr))
                goto fail_cond;

        pthread_condattr_destroy(&cattr);

        list_head_init(&fa.cmds);

        fa.fd = dt_reg_comp(&fa, &fa_post_packet, FA);

        sprintf(fastr, "%s", FA);
        if (rib_reg(fastr, &r_ops))
                goto fail_rib_reg;

        return 0;

 fail_rib_reg:
        pthread_cond_destroy(&fa.cond);
 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(&fa.mtx);
 fail_mtx:
        pthread_rwlock_destroy(&fa.flows_lock);
 fail_rwlock:
        log_err("Failed to initialize flow allocator.");
        return -1;
}

void fa_fini(void)
{
        pthread_cond_destroy(&fa.cond);;
        pthread_mutex_destroy(&fa.mtx);
        pthread_rwlock_destroy(&fa.flows_lock);
}

int fa_start(void)
{
        struct sched_param  par;
        int                 pol;
        int                 max;

        fa.psched = psched_create(packet_handler);
        if (fa.psched == NULL) {
                log_err("Failed to start packet scheduler.");
                goto fail_psched;
        }

        if (pthread_create(&fa.worker, NULL, fa_handle_packet, NULL)) {
                log_err("Failed to create worker thread.");
                goto fail_thread;
        }

        if (pthread_getschedparam(fa.worker, &pol, &par)) {
                log_err("Failed to get worker thread scheduling parameters.");
                goto fail_sched;
        }

        max = sched_get_priority_max(pol);
        if (max < 0) {
                log_err("Failed to get max priority for scheduler.");
                goto fail_sched;
        }

        par.sched_priority = max;

        if (pthread_setschedparam(fa.worker, pol, &par)) {
                log_err("Failed to set scheduler priority to maximum.");
                goto fail_sched;
        }

        return 0;

 fail_sched:
        pthread_cancel(fa.worker);
        pthread_join(fa.worker, NULL);
 fail_thread:
        psched_destroy(fa.psched);
 fail_psched:
        log_err("Failed to start flow allocator.");
        return -1;
}

void fa_stop(void)
{
        pthread_cancel(fa.worker);
        pthread_join(fa.worker, NULL);

        psched_destroy(fa.psched);
}

int fa_alloc(int             fd,
             const uint8_t * dst,
             qosspec_t       qs,
             const void *    data,
             size_t          dlen)
{
        struct fa_msg *      msg;
        struct shm_du_buff * sdb;
        struct fa_flow *     flow;
        uint64_t             addr;
        qoscube_t            qc = QOS_CUBE_BE;
        size_t               len;

        addr = dir_query(dst);
        if (addr == 0)
                return -1;

        len = sizeof(*msg) + ipcp_dir_hash_len();

        if (ipcp_sdb_reserve(&sdb, len + dlen))
                return -1;

        msg = (struct fa_msg *) shm_du_buff_head(sdb);
        memset(msg, 0, sizeof(*msg));

        msg->code         = FLOW_REQ;
        msg->s_eid        = hton32(fd);
        msg->s_addr       = hton64(ipcpi.dt_addr);
        msg->delay        = hton32(qs.delay);
        msg->bandwidth    = hton64(qs.bandwidth);
        msg->availability = qs.availability;
        msg->loss         = hton32(qs.loss);
        msg->ber          = hton32(qs.ber);
        msg->in_order     = qs.in_order;
        msg->max_gap      = hton32(qs.max_gap);
        msg->cypher_s     = hton16(qs.cypher_s);

        memcpy(msg + 1, dst, ipcp_dir_hash_len());
        memcpy(shm_du_buff_head(sdb) + len, data, dlen);

        if (dt_write_packet(addr, qc, fa.fd, sdb)) {
                ipcp_sdb_release(sdb);
                return -1;
        }

        flow = &fa.flows[fd];

        pthread_rwlock_wrlock(&fa.flows_lock);

        fa_flow_init(flow);
        flow->r_addr = addr;

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

int fa_alloc_resp(int          fd,
                  int          response,
                  const void * data,
                  size_t       len)
{
        struct timespec      ts = {0, TIMEOUT * 1000};
        struct timespec      abstime;
        struct fa_msg *      msg;
        struct shm_du_buff * sdb;
        struct fa_flow *     flow;
        qoscube_t            qc = QOS_CUBE_BE;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        flow = &fa.flows[fd];

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != fd && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                return -1;
        }

        ipcpi.alloc_id = -1;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg) + len)) {
                fa_flow_fini(flow);
                return -1;
        }

        msg = (struct fa_msg *) shm_du_buff_head(sdb);
        memset(msg, 0, sizeof(*msg));

        pthread_rwlock_wrlock(&fa.flows_lock);

        msg->code     = FLOW_REPLY;
        msg->r_eid    = hton32(flow->r_eid);
        msg->s_eid    = hton32(fd);
        msg->response = response;

        memcpy(msg + 1, data, len);

        if (response < 0) {
                fa_flow_fini(flow);
                ipcp_sdb_release(sdb);
        } else {
                psched_add(fa.psched, fd);
        }

        if (dt_write_packet(flow->r_addr, qc, fa.fd, sdb)) {
                fa_flow_fini(flow);
                pthread_rwlock_unlock(&fa.flows_lock);
                ipcp_sdb_release(sdb);
                return -1;
        }

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

int fa_dealloc(int fd)
{
        if (ipcp_flow_fini(fd) < 0)
                return 0;

        psched_del(fa.psched, fd);

        pthread_rwlock_wrlock(&fa.flows_lock);

        fa_flow_fini(&fa.flows[fd]);

        pthread_rwlock_unlock(&fa.flows_lock);

        flow_dealloc(fd);

        return 0;
}

static int fa_update_remote(int      fd,
                            uint16_t ece)
{
        struct fa_msg *      msg;
        struct shm_du_buff * sdb;
        qoscube_t            qc = QOS_CUBE_BE;
        struct fa_flow *     flow;
        uint64_t             r_addr;

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg))) {
                return -1;
        }

        msg = (struct fa_msg *) shm_du_buff_head(sdb);

        memset(msg, 0, sizeof(*msg));

        flow = &fa.flows[fd];

        pthread_rwlock_rdlock(&fa.flows_lock);

        msg->code  = FLOW_UPDATE;
        msg->r_eid = hton32(flow->r_eid);
        msg->ece   = hton16(ece);

        r_addr = flow->r_addr;

        pthread_rwlock_unlock(&fa.flows_lock);


        if (dt_write_packet(r_addr, qc, fa.fd, sdb)) {
                ipcp_sdb_release(sdb);
                return -1;
        }

        return 0;
}

void  fa_ecn_update(int     eid,
                    uint8_t ecn,
                    size_t  len)
{
        struct fa_flow * flow;
        bool             update;
        uint16_t         ece;

        flow = &fa.flows[eid];

        pthread_rwlock_wrlock(&fa.flows_lock);

        if (flow->r_eid == -1) {
                pthread_rwlock_unlock(&fa.flows_lock);
                return;
        }

        update = ca_ctx_update_rcv(flow->ctx, len, ecn, &ece);

        pthread_rwlock_unlock(&fa.flows_lock);

        if (update)
                fa_update_remote(eid, ece);
}
