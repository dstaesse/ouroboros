/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Flow allocator of the IPC Process
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

#include "config.h"

#define FA               "flow-allocator"
#define OUROBOROS_PREFIX FA

#include <ouroboros/endian.h>
#include <ouroboros/logs.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/rib.h>
#include <ouroboros/random.h>
#include <ouroboros/pthread.h>

#include "dir.h"
#include "fa.h"
#include "psched.h"
#include "ipcp.h"
#include "dt.h"
#include "ca.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#if defined (IPCP_FLOW_STATS) && !defined(CLOCK_REALTIME_COARSE)
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

#define TIMEOUT 10 * MILLION /* nanoseconds */

#define FLOW_REQ    0
#define FLOW_REPLY  1
#define FLOW_UPDATE 2
#define MSGBUFSZ    2048

#define STAT_FILE_LEN 0

struct fa_msg {
        uint64_t s_addr;
        uint64_t r_eid;
        uint64_t s_eid;
        uint8_t  code;
        int8_t   response;
        uint16_t ece;
        /* QoS parameters from spec, aligned */
        uint32_t delay;
        uint64_t bandwidth;
        uint32_t loss;
        uint32_t ber;
        uint32_t max_gap;
        uint32_t timeout;
        uint16_t cypher_s;
        uint8_t  availability;
        uint8_t  in_order;
} __attribute__((packed));

struct cmd {
        struct list_head     next;
        struct shm_du_buff * sdb;
};

struct fa_flow {
#ifdef IPCP_FLOW_STATS
        time_t   stamp;    /* Flow creation                  */
        size_t   p_snd;    /* Packets sent                   */
        size_t   p_snd_f;  /* Packets sent fail              */
        size_t   b_snd;    /* Bytes sent                     */
        size_t   b_snd_f;  /* Bytes sent fail                */
        size_t   p_rcv;    /* Packets received               */
        size_t   p_rcv_f;  /* Packets received fail          */
        size_t   b_rcv;    /* Bytes received                 */
        size_t   b_rcv_f;  /* Bytes received fail            */
        size_t   u_snd;    /* Flow updates sent              */
        size_t   u_rcv;    /* Flow updates received          */
#endif
        uint64_t s_eid;  /* Local endpoint id                */
        uint64_t r_eid;  /* Remote endpoint id               */
        uint64_t r_addr; /* Remote address                   */
        void *   ctx;    /* Congestion avoidance context     */
};

struct {
        pthread_rwlock_t flows_lock;
        struct fa_flow   flows[PROG_MAX_FLOWS];
#ifdef IPCP_FLOW_STATS
        size_t           n_flows;
#endif
        uint32_t         eid;

        struct list_head cmds;
        pthread_cond_t   cond;
        pthread_mutex_t  mtx;
        pthread_t        worker;

        struct psched *  psched;
} fa;

static int fa_rib_read(const char * path,
                       char *       buf,
                       size_t       len)
{
#ifdef IPCP_FLOW_STATS
        struct fa_flow * flow;
        int              fd;
        char             r_addrstr[21];
        char             s_eidstr[21];
        char             r_eidstr[21];
        char             tmstr[20];
        char             castr[1024];
        char *           entry;
        struct tm *      tm;

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        fd = atoi(entry);

        if (fd < 0 || fd >= PROG_MAX_FLOWS)
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
        sprintf(s_eidstr, "%" PRIu64, flow->s_eid);
        sprintf(r_eidstr, "%" PRIu64, flow->r_eid);

        tm = localtime(&flow->stamp);
        strftime(tmstr, sizeof(tmstr), "%F %T", tm);

        ca_print_stats(flow->ctx, castr, 1024);

        sprintf(buf,
                "Flow established at:             %20s\n"
                "Remote address:                  %20s\n"
                "Local endpoint ID:               %20s\n"
                "Remote endpoint ID:              %20s\n"
                "Sent (packets):                  %20zu\n"
                "Sent (bytes):                    %20zu\n"
                "Send failed (packets):           %20zu\n"
                "Send failed (bytes):             %20zu\n"
                "Received (packets):              %20zu\n"
                "Received (bytes):                %20zu\n"
                "Receive failed (packets):        %20zu\n"
                "Receive failed (bytes):          %20zu\n"
                "Sent flow updates (packets):     %20zu\n"
                "Received flow updates (packets): %20zu\n"
                "%s",
                tmstr, r_addrstr,
                s_eidstr, r_eidstr,
                flow->p_snd, flow->b_snd,
                flow->p_snd_f, flow->b_snd_f,
                flow->p_rcv, flow->b_rcv,
                flow->b_rcv_f, flow->b_rcv_f,
                flow->u_snd, flow->u_rcv,
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

static int fa_rib_readdir(char *** buf)
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
                        free(*buf);
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

static int fa_rib_getattr(const char *      path,
                          struct rib_attr * attr)
{
#ifdef IPCP_FLOW_STATS
        int              fd;
        char *           entry;
        struct fa_flow * flow;

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        fd = atoi(entry);

        flow = &fa.flows[fd];

        pthread_rwlock_rdlock(&fa.flows_lock);

        if (flow->stamp != 0) {
                attr->size  = 1536;
                attr->mtime = flow->stamp;
        } else {
                attr->size  = 0;
                attr->mtime = 0;
        }

        pthread_rwlock_unlock(&fa.flows_lock);
#else
        (void) path;
        (void) attr;
#endif
        return 0;
}

static struct rib_ops r_ops = {
        .read    = fa_rib_read,
        .readdir = fa_rib_readdir,
        .getattr = fa_rib_getattr
};

static int eid_to_fd(uint64_t eid)
{
        struct fa_flow * flow;
        int              fd;

        fd = eid & 0xFFFFFFFF;

        if (fd < 0 || fd >= PROG_MAX_FLOWS)
                return -1;

        flow = &fa.flows[fd];

        if (flow->s_eid == eid)
                return fd;

        return -1;
}

static uint64_t gen_eid(int fd)
{
        uint32_t rnd;

        if (random_buffer(&rnd, sizeof(rnd)) < 0)
                return fa.eid; /* INVALID */

        fd &= 0xFFFFFFFF;

        return ((uint64_t) rnd << 32) + fd;
}

static void packet_handler(int                  fd,
                           qoscube_t            qc,
                           struct shm_du_buff * sdb)
{
        struct fa_flow * flow;
        uint64_t         r_addr;
        uint64_t         r_eid;
        ca_wnd_t         wnd;
        size_t           len;

        flow = &fa.flows[fd];

        pthread_rwlock_wrlock(&fa.flows_lock);

        len = shm_du_buff_len(sdb);

#ifdef IPCP_FLOW_STATS
        ++flow->p_snd;
        flow->b_snd += len;
#endif
        wnd = ca_ctx_update_snd(flow->ctx, len);

        r_addr = flow->r_addr;
        r_eid  = flow->r_eid;

        pthread_rwlock_unlock(&fa.flows_lock);

        ca_wnd_wait(wnd);

        if (dt_write_packet(r_addr, qc, r_eid, sdb)) {
                ipcp_sdb_release(sdb);
                log_warn("Failed to forward packet.");
#ifdef IPCP_FLOW_STATS
                pthread_rwlock_wrlock(&fa.flows_lock);
                ++flow->p_snd_f;
                flow->b_snd_f += len;
                pthread_rwlock_unlock(&fa.flows_lock);
#endif
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
        flow->s_eid  = -1;
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
        flow->s_eid  = -1;
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

static size_t fa_wait_for_fa_msg(struct fa_msg * msg)
{
        struct cmd * cmd;
        size_t       len;

        pthread_mutex_lock(&fa.mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, &fa.mtx);

        while (list_is_empty(&fa.cmds))
                pthread_cond_wait(&fa.cond, &fa.mtx);

        cmd = list_last_entry(&fa.cmds, struct cmd, next);
        list_del(&cmd->next);

        pthread_cleanup_pop(true);

        len = shm_du_buff_len(cmd->sdb);
        if (len > MSGBUFSZ || len < sizeof(*msg)) {
                log_warn("Invalid flow allocation message (len: %zd)\n", len);
                free(cmd);
                return 0; /* No valid message */
        }

        memcpy(msg, shm_du_buff_head(cmd->sdb), len);

        ipcp_sdb_release(cmd->sdb);

        free(cmd);

        return len;
}

static int fa_wait_irmd_alloc(uint8_t *    dst,
                              qosspec_t    qs,
                              const void * data,
                              size_t       len)
{
        struct timespec ts  = {0, TIMEOUT};
        struct timespec abstime;
        int             fd;
        time_t          mpl = IPCP_UNICAST_MPL;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != -1 && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                log_dbg("Won't allocate over non-operational IPCP.");
                return -EIPCPSTATE;
        }

        assert(ipcpi.alloc_id == -1);

        fd = ipcp_flow_req_arr(dst, ipcp_dir_hash_len(), qs, mpl, data, len);
        if (fd < 0) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                log_dbg("Failed to get fd for flow.");
                return -ENOTALLOC;
        }

        ipcpi.alloc_id = fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        return fd;
}

static int fa_wait_irmd_alloc_resp(int fd)
{
        struct timespec      ts = {0, TIMEOUT};
        struct timespec      abstime;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

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

        assert(ipcpi.alloc_id == fd);

        ipcpi.alloc_id = -1;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        return 0;
}

static int fa_handle_flow_req(struct fa_msg * msg,
                              size_t          len)
{
        size_t           msg_len;
        int              fd;
        qosspec_t        qs;
        struct fa_flow * flow;
        uint8_t *        data;  /* Piggbacked data on flow alloc request. */
        size_t           dlen;  /* Length of piggybacked data.            */

        msg_len = sizeof(*msg) + ipcp_dir_hash_len();
        if (len < msg_len) {
                log_err("Invalid flow allocation request");
                return -EPERM;
        }

        data = (uint8_t *) msg + msg_len;
        dlen = len - msg_len;

        qs.delay        = ntoh32(msg->delay);
        qs.bandwidth    = ntoh64(msg->bandwidth);
        qs.availability = msg->availability;
        qs.loss         = ntoh32(msg->loss);
        qs.ber          = ntoh32(msg->ber);
        qs.in_order     = msg->in_order;
        qs.max_gap      = ntoh32(msg->max_gap);
        qs.cypher_s     = ntoh16(msg->cypher_s);
        qs.timeout      = ntoh32(msg->timeout);

        fd = fa_wait_irmd_alloc((uint8_t *) (msg + 1), qs, data, dlen);
        if (fd < 0)
                return fd;

        flow = &fa.flows[fd];

        pthread_rwlock_wrlock(&fa.flows_lock);

        fa_flow_init(flow);

        flow->s_eid  = gen_eid(fd);
        flow->r_eid  = ntoh64(msg->s_eid);
        flow->r_addr = ntoh64(msg->s_addr);

        pthread_rwlock_unlock(&fa.flows_lock);

        return fd;
}

static int fa_handle_flow_reply(struct fa_msg * msg,
                                size_t          len)
{
        int              fd;
        struct fa_flow * flow;
        uint8_t *        data;  /* Piggbacked data on flow alloc request. */
        size_t           dlen;  /* Length of piggybacked data.            */
        time_t           mpl = IPCP_UNICAST_MPL;

        assert(len >= sizeof(*msg));

        data = (uint8_t *) msg + sizeof(*msg);
        dlen = len - sizeof(*msg);

        pthread_rwlock_wrlock(&fa.flows_lock);

        fd = eid_to_fd(ntoh64(msg->r_eid));
        if (fd < 0) {
                pthread_rwlock_unlock(&fa.flows_lock);
                return -ENOTALLOC;
        }

        flow = &fa.flows[fd];

        flow->r_eid = ntoh64(msg->s_eid);

        if (msg->response < 0)
                fa_flow_fini(flow);
        else
                psched_add(fa.psched, fd);

        pthread_rwlock_unlock(&fa.flows_lock);

        if (ipcp_flow_alloc_reply(fd, msg->response, mpl, data, dlen))
                return -EIRMD;

        return 0;
}

static int fa_handle_flow_update(struct fa_msg * msg,
                                 size_t          len)
{
        struct fa_flow * flow;
        int              fd;

        (void) len;
        assert(len >= sizeof(*msg));

        pthread_rwlock_wrlock(&fa.flows_lock);

        fd = eid_to_fd(ntoh64(msg->r_eid));
        if (fd < 0) {
                pthread_rwlock_unlock(&fa.flows_lock);
                return -EPERM;
        }

        flow = &fa.flows[fd];
#ifdef IPCP_FLOW_STATS
        flow->u_rcv++;
#endif
        ca_ctx_update_ece(flow->ctx, ntoh16(msg->ece));

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

static void * fa_handle_packet(void * o)
{
        (void) o;

        while (true) {
                uint8_t          buf[MSGBUFSZ];
                struct fa_msg *  msg;
                size_t           len;

                msg = (struct fa_msg *) buf;

                len = fa_wait_for_fa_msg(msg);
                if (len == 0)
                        continue;

                switch (msg->code) {
                case FLOW_REQ:
                        if (fa_handle_flow_req(msg, len) < 0)
                                log_err("Error handling flow alloc request.");
                        break;
                case FLOW_REPLY:
                        if (fa_handle_flow_reply(msg, len) < 0)
                                log_err("Error handling flow reply.");
                        break;
                case FLOW_UPDATE:
                        if (fa_handle_flow_update(msg, len) < 0)
                                log_err("Error handling flow update.");
                        break;
                default:
                        log_warn("Recieved unknown flow allocation message.");
                        break;
                }
        }

        return (void *) 0;
}

int fa_init(void)
{
        pthread_condattr_t cattr;

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

        if (rib_reg(FA, &r_ops))
                goto fail_rib_reg;

        fa.eid = dt_reg_comp(&fa, &fa_post_packet, FA);
        if ((int) fa.eid < 0)
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
        rib_unreg(FA);

        pthread_cond_destroy(&fa.cond);;
        pthread_mutex_destroy(&fa.mtx);
        pthread_rwlock_destroy(&fa.flows_lock);
}

int fa_start(void)
{
        struct sched_param  par;
        int                 pol;
        int                 max;

        fa.psched = psched_create(packet_handler, np1_flow_read);
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
        uint64_t             eid;

        addr = dir_query(dst);
        if (addr == 0)
                return -1;

        len = sizeof(*msg) + ipcp_dir_hash_len();

        if (ipcp_sdb_reserve(&sdb, len + dlen))
                return -1;

        msg = (struct fa_msg *) shm_du_buff_head(sdb);
        memset(msg, 0, sizeof(*msg));

        eid = gen_eid(fd);

        msg->code         = FLOW_REQ;
        msg->s_eid        = hton64(eid);
        msg->s_addr       = hton64(ipcpi.dt_addr);
        msg->delay        = hton32(qs.delay);
        msg->bandwidth    = hton64(qs.bandwidth);
        msg->availability = qs.availability;
        msg->loss         = hton32(qs.loss);
        msg->ber          = hton32(qs.ber);
        msg->in_order     = qs.in_order;
        msg->max_gap      = hton32(qs.max_gap);
        msg->cypher_s     = hton16(qs.cypher_s);
        msg->timeout      = hton32(qs.timeout);

        memcpy(msg + 1, dst, ipcp_dir_hash_len());
        if (dlen > 0)
                memcpy(shm_du_buff_head(sdb) + len, data, dlen);

        if (dt_write_packet(addr, qc, fa.eid, sdb)) {
                ipcp_sdb_release(sdb);
                return -1;
        }

        flow = &fa.flows[fd];

        pthread_rwlock_wrlock(&fa.flows_lock);

        fa_flow_init(flow);
        flow->r_addr = addr;
        flow->s_eid  = eid;

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

int fa_alloc_resp(int          fd,
                  int          response,
                  const void * data,
                  size_t       len)
{
        struct fa_msg *      msg;
        struct shm_du_buff * sdb;
        struct fa_flow *     flow;
        qoscube_t            qc = QOS_CUBE_BE;

        flow = &fa.flows[fd];

        if (fa_wait_irmd_alloc_resp(fd) < 0)
                goto fail_alloc_resp;

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg) + len)) {
                goto fail_reserve;
        }

        msg = (struct fa_msg *) shm_du_buff_head(sdb);
        memset(msg, 0, sizeof(*msg));

        msg->code     = FLOW_REPLY;
        msg->response = response;
        if (len > 0)
                memcpy(msg + 1, data, len);

        pthread_rwlock_rdlock(&fa.flows_lock);

        msg->r_eid    = hton64(flow->r_eid);
        msg->s_eid    = hton64(flow->s_eid);

        pthread_rwlock_unlock(&fa.flows_lock);

        if (dt_write_packet(flow->r_addr, qc, fa.eid, sdb))
                goto fail_packet;

        if (response < 0) {
                pthread_rwlock_rdlock(&fa.flows_lock);
                fa_flow_fini(flow);
                pthread_rwlock_unlock(&fa.flows_lock);
        } else {
                psched_add(fa.psched, fd);
        }

        return 0;

 fail_packet:
        ipcp_sdb_release(sdb);
 fail_reserve:
        pthread_rwlock_wrlock(&fa.flows_lock);
        fa_flow_fini(flow);
        pthread_rwlock_unlock(&fa.flows_lock);
 fail_alloc_resp:
        return -1;
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

        pthread_rwlock_wrlock(&fa.flows_lock);

        msg->code  = FLOW_UPDATE;
        msg->r_eid = hton64(flow->r_eid);
        msg->ece   = hton16(ece);

        r_addr = flow->r_addr;
#ifdef IPCP_FLOW_STATS
        flow->u_snd++;
#endif
        pthread_rwlock_unlock(&fa.flows_lock);


        if (dt_write_packet(r_addr, qc, fa.eid, sdb)) {
                ipcp_sdb_release(sdb);
                return -1;
        }

        return 0;
}

void  fa_np1_rcv(uint64_t             eid,
                 uint8_t              ecn,
                 struct shm_du_buff * sdb)
{
        struct fa_flow * flow;
        bool             update;
        uint16_t         ece;
        int              fd;
        size_t           len;

        len = shm_du_buff_len(sdb);

        pthread_rwlock_wrlock(&fa.flows_lock);

        fd = eid_to_fd(eid);
        if (fd < 0) {
                pthread_rwlock_unlock(&fa.flows_lock);
                ipcp_sdb_release(sdb);
                return;
        }

        flow = &fa.flows[fd];

#ifdef IPCP_FLOW_STATS
        ++flow->p_rcv;
        flow->b_rcv += len;
#endif
        update = ca_ctx_update_rcv(flow->ctx, len, ecn, &ece);

        pthread_rwlock_unlock(&fa.flows_lock);

        if (ipcp_flow_write(fd, sdb) < 0) {
                ipcp_sdb_release(sdb);
#ifdef IPCP_FLOW_STATS
                pthread_rwlock_wrlock(&fa.flows_lock);
                ++flow->p_rcv_f;
                flow->b_rcv_f += len;
                pthread_rwlock_unlock(&fa.flows_lock);
#endif
        }

        if (update)
                fa_update_remote(eid, ece);
}
