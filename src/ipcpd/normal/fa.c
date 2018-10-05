/*
 * Ouroboros - Copyright (C) 2016 - 2018
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

#include "dir.h"
#include "fa.h"
#include "packet_sched.h"
#include "ipcp.h"
#include "dt.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define TIMEOUT 10000 /* nanoseconds */

#define FLOW_REQ   0
#define FLOW_REPLY 1

struct fa_msg {
        uint64_t s_addr;
        uint32_t r_eid;
        uint32_t s_eid;
        uint8_t  code;
        int8_t   response;
        /* QoS parameters from spec, aligned */
        uint8_t  availability;
        uint8_t  in_order;
        uint32_t delay;
        uint64_t bandwidth;
        uint32_t loss;
        uint32_t ber;
        uint32_t max_gap;
} __attribute__((packed));

struct {
        pthread_rwlock_t   flows_lock;
        int                r_eid[PROG_MAX_FLOWS];
        uint64_t           r_addr[PROG_MAX_FLOWS];
        int                fd;

        struct packet_sched * packet_sched;
} fa;

static void packet_handler(int                  fd,
                           qoscube_t            qc,
                           struct shm_du_buff * sdb)
{
        pthread_rwlock_rdlock(&fa.flows_lock);

        if (dt_write_packet(fa.r_addr[fd], qc, fa.r_eid[fd], sdb)) {
                pthread_rwlock_unlock(&fa.flows_lock);
                ipcp_sdb_release(sdb);
                log_warn("Failed to forward packet.");
                return;
        }

        pthread_rwlock_unlock(&fa.flows_lock);
}

static void destroy_conn(int fd)
{
        fa.r_eid[fd]   = -1;
        fa.r_addr[fd] = INVALID_ADDR;
}

static void fa_post_packet(void *               comp,
                        struct shm_du_buff * sdb)
{
        struct timespec ts  = {0, TIMEOUT * 1000};
        struct timespec abstime;
        int             fd;
        uint8_t *       buf;
        struct fa_msg * msg;
        qosspec_t       qs;

        (void) comp;

        assert(comp == &fa);
        assert(sdb);

        buf = malloc(sizeof(*msg) + ipcp_dir_hash_len());
        if (buf == NULL)
                return;

        msg = (struct fa_msg *) buf;

        /* Depending on the message call the function in ipcp-dev.h */

        memcpy(msg, shm_du_buff_head(sdb),
               shm_du_buff_tail(sdb) - shm_du_buff_head(sdb));

        ipcp_sdb_release(sdb);

        switch (msg->code) {
        case FLOW_REQ:
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
                        log_dbg("Won't allocate over non-operational IPCP.");
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        free(msg);
                        return;
                }

                assert(ipcpi.alloc_id == -1);

                qs.delay        = ntoh32(msg->delay);
                qs.bandwidth    = ntoh64(msg->bandwidth);
                qs.availability = msg->availability;
                qs.loss         = ntoh32(msg->loss);
                qs.ber          = ntoh32(msg->ber);
                qs.in_order     = msg->in_order;
                qs.max_gap      = ntoh32(msg->max_gap);

                fd = ipcp_flow_req_arr(getpid(),
                                       (uint8_t *) (msg + 1),
                                       ipcp_dir_hash_len(),
                                       qs);
                if (fd < 0) {
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        log_err("Failed to get fd for flow.");
                        free(msg);
                        return;
                }

                pthread_rwlock_wrlock(&fa.flows_lock);

                fa.r_eid[fd]  = ntoh32(msg->s_eid);
                fa.r_addr[fd] = ntoh64(msg->s_addr);

                pthread_rwlock_unlock(&fa.flows_lock);

                ipcpi.alloc_id = fd;
                pthread_cond_broadcast(&ipcpi.alloc_cond);

                pthread_mutex_unlock(&ipcpi.alloc_lock);

                break;
        case FLOW_REPLY:
                pthread_rwlock_wrlock(&fa.flows_lock);

                fa.r_eid[ntoh32(msg->r_eid)] = ntoh32(msg->s_eid);

                ipcp_flow_alloc_reply(ntoh32(msg->r_eid), msg->response);

                if (msg->response < 0)
                        destroy_conn(ntoh32(msg->r_eid));
                else
                        packet_sched_add(fa.packet_sched, ntoh32(msg->r_eid));

                pthread_rwlock_unlock(&fa.flows_lock);

                break;
        default:
                log_err("Got an unknown flow allocation message.");
                break;
        }

        free(msg);
}

int fa_init(void)
{
        int i;

        for (i = 0; i < PROG_MAX_FLOWS; ++i)
                destroy_conn(i);

        if (pthread_rwlock_init(&fa.flows_lock, NULL))
                return -1;

        fa.fd = dt_reg_comp(&fa, &fa_post_packet, FA);

        return 0;
}

void fa_fini(void)
{
        pthread_rwlock_destroy(&fa.flows_lock);
}

int fa_start(void)
{
        fa.packet_sched = packet_sched_create(packet_handler);
        if (fa.packet_sched == NULL) {
                log_err("Failed to create packet scheduler.");
                return -1;
        }

        return 0;
}

void fa_stop(void)
{
        packet_sched_destroy(fa.packet_sched);
}

int fa_alloc(int             fd,
             const uint8_t * dst,
             qosspec_t       qs)
{
        struct fa_msg *      msg;
        uint64_t             addr;
        struct shm_du_buff * sdb;
        qoscube_t            qc;

        addr = dir_query(dst);
        if (addr == 0)
                return -1;

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg) + ipcp_dir_hash_len()))
                return -1;

        msg               = (struct fa_msg *) shm_du_buff_head(sdb);
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

        memcpy(msg + 1, dst, ipcp_dir_hash_len());

        qc = qos_spec_to_cube(qs);

        if (dt_write_packet(addr, qc, fa.fd, sdb)) {
                ipcp_sdb_release(sdb);
                return -1;
        }

        pthread_rwlock_wrlock(&fa.flows_lock);

        assert(fa.r_eid[fd] == -1);
        fa.r_addr[fd] = addr;

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

int fa_alloc_resp(int fd,
                  int response)
{
        struct timespec      ts = {0, TIMEOUT * 1000};
        struct timespec      abstime;
        struct fa_msg *      msg;
        struct shm_du_buff * sdb;
        qoscube_t            qc;

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

        ipcpi.alloc_id = -1;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg) + ipcp_dir_hash_len())) {
                destroy_conn(fd);
                return -1;
        }

        pthread_rwlock_wrlock(&fa.flows_lock);

        msg           = (struct fa_msg *) shm_du_buff_head(sdb);
        msg->code     = FLOW_REPLY;
        msg->r_eid    = hton32(fa.r_eid[fd]);
        msg->s_eid    = hton32(fd);
        msg->response = response;

        if (response < 0) {
                destroy_conn(fd);
                ipcp_sdb_release(sdb);
        } else {
                packet_sched_add(fa.packet_sched, fd);
        }

        ipcp_flow_get_qoscube(fd, &qc);

        assert(qc >= 0 && qc < QOS_CUBE_MAX);

        if (dt_write_packet(fa.r_addr[fd], qc, fa.fd, sdb)) {
                destroy_conn(fd);
                pthread_rwlock_unlock(&fa.flows_lock);
                ipcp_sdb_release(sdb);
                return -1;
        }

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

int fa_dealloc(int fd)
{
        ipcp_flow_fini(fd);

        pthread_rwlock_wrlock(&fa.flows_lock);

        packet_sched_del(fa.packet_sched, fd);

        destroy_conn(fd);

        pthread_rwlock_unlock(&fa.flows_lock);

        flow_dealloc(fd);

        return 0;
}
