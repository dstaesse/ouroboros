/*
 * Ouroboros - Copyright (C) 2016 - 2017
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "flow-allocator"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/rib.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>

#include "dt_pci.h"
#include "fa.h"
#include "sdu_sched.h"
#include "ipcp.h"
#include "ribconfig.h"
#include "dt.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "flow_alloc.pb-c.h"
typedef FlowAllocMsg flow_alloc_msg_t;

#define TIMEOUT 10000 /* nanoseconds */

struct {
        pthread_rwlock_t   flows_lock;
        cep_id_t           fd_to_cep_id[AP_MAX_FLOWS];
        int                cep_id_to_fd[IPCPD_MAX_CONNS];

        struct sdu_sched * sdu_sched;
} fa;

static int sdu_handler(int                  fd,
                       qoscube_t            qc,
                       struct shm_du_buff * sdb)
{
        (void) qc;

        pthread_rwlock_rdlock(&fa.flows_lock);

        if (frct_i_write_sdu(fa.fd_to_cep_id[fd], sdb)) {
                pthread_rwlock_unlock(&fa.flows_lock);
                ipcp_sdb_release(sdb);
                log_warn("Failed to hand SDU to FRCT.");
                return -1;
        }

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

int fa_init(void)
{
        int i;

        for (i = 0; i < AP_MAX_FLOWS; ++i)
                fa.fd_to_cep_id[i] = INVALID_CEP_ID;

        for (i = 0; i < IPCPD_MAX_CONNS; ++i)
                fa.cep_id_to_fd[i] = -1;

        if (pthread_rwlock_init(&fa.flows_lock, NULL))
                return -1;

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

static struct shm_du_buff * create_fa_sdb(flow_alloc_msg_t * msg)
{
        struct shm_du_buff * sdb;
        size_t len;

        len = flow_alloc_msg__get_packed_size(msg);
        if (len == 0)
                return NULL;

        if (ipcp_sdb_reserve(&sdb, len))
                return NULL;

        flow_alloc_msg__pack(msg, shm_du_buff_head(sdb));

        return sdb;
}

static void destroy_conn(int      fd,
                         cep_id_t cep_id)
{
        fa.fd_to_cep_id[fd] = INVALID_CEP_ID;
        fa.cep_id_to_fd[cep_id] = -1;
        frct_i_destroy(cep_id);
}

int fa_alloc(int             fd,
             const uint8_t * dst,
             qoscube_t       qc)
{
        cep_id_t             cep_id;
        flow_alloc_msg_t     msg = FLOW_ALLOC_MSG__INIT;
        char                 path[RIB_MAX_PATH_LEN + 1];
        uint64_t             addr;
        ssize_t              ch;
        ssize_t              i;
        char **              children;
        char                 hashstr[ipcp_dir_hash_strlen() + 1];
        char *               dst_ipcp = NULL;
        struct shm_du_buff * sdb;

        ipcp_hash_str(hashstr, dst);

        assert(strlen(hashstr) + strlen(DIR_PATH) + 1
               < RIB_MAX_PATH_LEN);

        strcpy(path, DIR_PATH);

        rib_path_append(path, hashstr);

        ch = rib_children(path, &children);
        if (ch <= 0)
                return -1;

        for (i = 0; i < ch; ++i)
                if (dst_ipcp == NULL && strcmp(children[i], ipcpi.name) != 0)
                        dst_ipcp = children[i];
                else
                        free(children[i]);

        free(children);

        if (dst_ipcp == NULL)
                return -1;

        strcpy(path, MEMBERS_PATH);

        rib_path_append(path, dst_ipcp);

        free(dst_ipcp);

        if (rib_read(path, &addr, sizeof(addr)) < 0)
                return -1;

        cep_id = frct_i_create(addr, qc);
        if (cep_id == INVALID_CEP_ID)
                return -1;

        msg.code         = FLOW_ALLOC_CODE__FLOW_REQ;
        msg.has_hash     = true;
        msg.hash.len     = ipcp_dir_hash_len();
        msg.hash.data    = (uint8_t *) dst;
        msg.has_qc       = true;
        msg.qc           = qc;
        msg.has_s_cep_id = true;
        msg.s_cep_id     = cep_id;
        msg.has_s_addr   = true;
        msg.s_addr       = ipcpi.dt_addr;

        sdb = create_fa_sdb(&msg);
        if (sdb == NULL) {
                frct_i_destroy(cep_id);
                return -1;
        }

        pthread_rwlock_wrlock(&fa.flows_lock);

        if (dt_write_sdu(addr, qc, PDU_TYPE_FA, sdb)) {
                frct_i_destroy(cep_id);
                pthread_rwlock_unlock(&fa.flows_lock);
                ipcp_sdb_release(sdb);
                return -1;
        }

        fa.fd_to_cep_id[fd] = cep_id;
        fa.cep_id_to_fd[cep_id] = fd;

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

int fa_alloc_resp(int fd,
                  int response)
{
        struct timespec      ts = {0, TIMEOUT * 1000};
        flow_alloc_msg_t     msg = FLOW_ALLOC_MSG__INIT;
        struct shm_du_buff * sdb;
        qoscube_t            qc;

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != fd && ipcp_get_state() == IPCP_OPERATIONAL)
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &ts);

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                return -1;
        }

        ipcpi.alloc_id = -1;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        pthread_rwlock_wrlock(&fa.flows_lock);

        msg.code         = FLOW_ALLOC_CODE__FLOW_REPLY;
        msg.has_cep_id   = true;
        msg.cep_id       = frct_i_get_id(fa.fd_to_cep_id[fd]);
        msg.s_cep_id     = fa.fd_to_cep_id[fd];
        msg.has_s_cep_id = true;
        msg.response     = response;
        msg.has_response = true;

        sdb = create_fa_sdb(&msg);
        if (sdb == NULL) {
                destroy_conn(fd, fa.fd_to_cep_id[fd]);
                pthread_rwlock_unlock(&fa.flows_lock);
                return -1;
        }

        if (response < 0) {
                destroy_conn(fd, fa.fd_to_cep_id[fd]);
                ipcp_sdb_release(sdb);
        } else {
                sdu_sched_add(fa.sdu_sched, fd);
        }

        ipcp_flow_get_qoscube(fd, &qc);

        assert(qc >= 0 && qc < QOS_CUBE_MAX);

        if (dt_write_sdu(frct_i_get_addr(fa.fd_to_cep_id[fd]),
                         qc,
                         PDU_TYPE_FA,
                         sdb)) {
                destroy_conn(fd, fa.fd_to_cep_id[fd]);
                ipcp_sdb_release(sdb);
                return -1;
        }

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}

int fa_dealloc(int fd)
{
        flow_alloc_msg_t     msg = FLOW_ALLOC_MSG__INIT;
        struct shm_du_buff * sdb;
        qoscube_t            qc;

        pthread_rwlock_wrlock(&fa.flows_lock);

        sdu_sched_del(fa.sdu_sched, fd);

        destroy_conn(fd, fa.fd_to_cep_id[fd]);

        msg.code       = FLOW_ALLOC_CODE__FLOW_DEALLOC;
        msg.has_cep_id = true;
        msg.cep_id     = frct_i_get_id(fa.fd_to_cep_id[fd]);

        sdb = create_fa_sdb(&msg);
        if (sdb == NULL) {
                pthread_rwlock_unlock(&fa.flows_lock);
                return -1;
        }

        pthread_rwlock_unlock(&fa.flows_lock);

        ipcp_flow_get_qoscube(fd, &qc);

        assert(qc >= 0 && qc < QOS_CUBE_MAX);

        if (dt_write_sdu(frct_i_get_addr(fa.fd_to_cep_id[fd]),
                         qc,
                         PDU_TYPE_FA,
                         sdb)) {
                ipcp_sdb_release(sdb);
                return -1;
        }

        return 0;
}

int fa_post_sdu(struct shm_du_buff * sdb)
{
        struct timespec    ts  = {0, TIMEOUT * 1000};
        int                fd;
        flow_alloc_msg_t * msg;
        cep_id_t           cep_id;

        assert(sdb);

        /* Depending on the message call the function in ipcp-dev.h */

        msg = flow_alloc_msg__unpack(NULL,
                                     shm_du_buff_tail(sdb) -
                                     shm_du_buff_head(sdb),
                                     shm_du_buff_head(sdb));
        if (msg == NULL) {
                log_err("Failed to unpack flow alloc message");
                return -1;
        }

        switch (msg->code) {
        case FLOW_ALLOC_CODE__FLOW_REQ:
                pthread_mutex_lock(&ipcpi.alloc_lock);

                if (!msg->has_hash) {
                        log_err("Bad flow request.");
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        return -1;
                }

                while (ipcpi.alloc_id != -1 &&
                       ipcp_get_state() == IPCP_OPERATIONAL)
                        pthread_cond_timedwait(&ipcpi.alloc_cond,
                                               &ipcpi.alloc_lock,
                                               &ts);

                if (ipcp_get_state() != IPCP_OPERATIONAL) {
                        log_dbg("Won't allocate over non-operational IPCP.");
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        return -1;
                }

                assert(ipcpi.alloc_id == -1);

                cep_id = frct_i_create(msg->s_addr, msg->qc);
                if (cep_id == INVALID_CEP_ID) {
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        return -1;
                }

                if (frct_i_set_id(cep_id, msg->s_cep_id)) {
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        frct_i_destroy(cep_id);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        return -1;
                }

                fd = ipcp_flow_req_arr(getpid(),
                                       msg->hash.data,
                                       ipcp_dir_hash_len(),
                                       msg->qc);
                if (fd < 0) {
                        pthread_mutex_unlock(&ipcpi.alloc_lock);
                        frct_i_destroy(cep_id);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        log_err("Failed to get fd for flow.");
                        return -1;
                }

                pthread_rwlock_wrlock(&fa.flows_lock);

                fa.fd_to_cep_id[fd] = cep_id;
                fa.cep_id_to_fd[cep_id] = fd;

                pthread_rwlock_unlock(&fa.flows_lock);

                ipcpi.alloc_id = fd;
                pthread_cond_broadcast(&ipcpi.alloc_cond);

                pthread_mutex_unlock(&ipcpi.alloc_lock);

                break;
        case FLOW_ALLOC_CODE__FLOW_REPLY:
                pthread_rwlock_wrlock(&fa.flows_lock);

                fd = fa.cep_id_to_fd[msg->cep_id];
                ipcp_flow_alloc_reply(fd, msg->response);
                if (msg->response < 0) {
                        destroy_conn(fd, msg->cep_id);
                } else {
                        frct_i_set_id(msg->cep_id, msg->s_cep_id);
                        sdu_sched_add(fa.sdu_sched,
                                      fa.cep_id_to_fd[msg->cep_id]);
                }

                pthread_rwlock_unlock(&fa.flows_lock);

                break;
        case FLOW_ALLOC_CODE__FLOW_DEALLOC:
                fd = fa.cep_id_to_fd[msg->cep_id];
                sdu_sched_del(fa.sdu_sched, fd);
                flow_dealloc(fd);
                break;
        default:
                log_err("Got an unknown flow allocation message.");
                flow_alloc_msg__free_unpacked(msg, NULL);
                return -1;
        }

        flow_alloc_msg__free_unpacked(msg, NULL);
        ipcp_sdb_release(sdb);

        return 0;
}

int fa_post_sdu_user(cep_id_t             cep_id,
                     struct shm_du_buff * sdb)
{
        int fd;

        assert(sdb);

        pthread_rwlock_rdlock(&fa.flows_lock);

        fd = fa.cep_id_to_fd[cep_id];
        if (ipcp_flow_write(fd, sdb)) {
                pthread_rwlock_unlock(&fa.flows_lock);
                log_err("Failed to hand SDU to N flow.");
                return -1;
        }

        pthread_rwlock_unlock(&fa.flows_lock);

        return 0;
}
