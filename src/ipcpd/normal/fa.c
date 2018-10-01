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
#include "sdu_sched.h"
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
        uint8_t  qc;
        int8_t   response;
} __attribute__((packed));

struct {
        pthread_rwlock_t   flows_lock;
        int                r_eid[PROG_MAX_FLOWS];
        uint64_t           r_addr[PROG_MAX_FLOWS];
        int                fd;

        struct sdu_sched * sdu_sched;
} fa;

static void sdu_handler(int                  fd,
                        qoscube_t            qc,
                        struct shm_du_buff * sdb)
{
        pthread_rwlock_rdlock(&fa.flows_lock);

        if (dt_write_sdu(fa.r_addr[fd], qc, fa.r_eid[fd], sdb)) {
                pthread_rwlock_unlock(&fa.flows_lock);
                ipcp_sdb_release(sdb);
                log_warn("Failed to forward SDU.");
                return;
        }

        pthread_rwlock_unlock(&fa.flows_lock);
}

static void destroy_conn(int fd)
{
        fa.r_eid[fd]   = -1;
        fa.r_addr[fd] = INVALID_ADDR;
}

static void fa_post_sdu(void *               comp,
                        struct shm_du_buff * sdb)
{
        struct timespec ts  = {0, TIMEOUT * 1000};
        struct timespec abstime;
        int             fd;
        uint8_t *       buf;
        struct fa_msg * msg;

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

                fd = ipcp_flow_req_arr(getpid(),
                                       (uint8_t *) (msg + 1),
                                       ipcp_dir_hash_len(),
                                       msg->qc);
                if (fd < 0) {
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        log_err("Failed to get fd for flow.");
                        free(msg);
                        return;
                }

                pthread_rwlock_wrlock(&fa.flows_lock);

                fa.r_eid[fd]  = msg->s_eid;
                fa.r_addr[fd] = msg->s_addr;

                pthread_rwlock_unlock(&fa.flows_lock);

                ipcpi.alloc_id = fd;
                pthread_cond_broadcast(&ipcpi.alloc_cond);

                pthread_mutex_unlock(&ipcpi.alloc_lock);

                break;
        case FLOW_REPLY:
                pthread_rwlock_wrlock(&fa.flows_lock);

                fa.r_eid[msg->r_eid] = msg->s_eid;

                ipcp_flow_alloc_reply(msg->r_eid, msg->response);

                if (msg->response < 0)
                        destroy_conn(msg->r_eid);
                else
                        sdu_sched_add(fa.sdu_sched, msg->r_eid);

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

        fa.fd = dt_reg_comp(&fa, &fa_post_sdu, FA);

        return 0;
}

void fa_fini(void)
{
        pthread_rwlock_destroy(&fa.flows_lock);
}

int fa_start(void)
{
        fa.sdu_sched = sdu_sched_create(sdu_handler);
        if (fa.sdu_sched == NULL) {
                log_err("Failed to create SDU scheduler.");
                return -1;
        }

        return 0;
}

void fa_stop(void)
{
        sdu_sched_destroy(fa.sdu_sched);
}

int fa_alloc(int             fd,
             const uint8_t * dst,
             qoscube_t       qc)
{
        struct fa_msg *      msg;
        uint64_t             addr;
        struct shm_du_buff * sdb;

        addr = dir_query(dst);
        if (addr == 0)
                return -1;

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg) + ipcp_dir_hash_len()))
                return -1;

        msg         = (struct fa_msg *) shm_du_buff_head(sdb);
        msg->code   = FLOW_REQ;
        msg->qc     = qc;
        msg->s_eid  = fd;
        msg->s_addr = ipcpi.dt_addr;

        memcpy(msg + 1, dst, ipcp_dir_hash_len());

        if (dt_write_sdu(addr, qc, fa.fd, sdb)) {
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
        msg->r_eid    = fa.r_eid[fd];
        msg->s_eid    = fd;
        msg->response = response;

        if (response < 0) {
                destroy_conn(fd);
                ipcp_sdb_release(sdb);
        } else {
                sdu_sched_add(fa.sdu_sched, fd);
        }

        ipcp_flow_get_qoscube(fd, &qc);

        assert(qc >= 0 && qc < QOS_CUBE_MAX);

        if (dt_write_sdu(fa.r_addr[fd], qc, fa.fd, sdb)) {
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

        sdu_sched_del(fa.sdu_sched, fd);

        destroy_conn(fd);

        pthread_rwlock_unlock(&fa.flows_lock);

        flow_dealloc(fd);

        return 0;
}
