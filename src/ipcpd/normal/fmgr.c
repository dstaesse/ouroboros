/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Flow manager of the IPC Process
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "flow-manager"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/list.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/errno.h>
#include <ouroboros/cacep.h>
#include <ouroboros/rib.h>

#include "fmgr.h"
#include "frct.h"
#include "ipcp.h"
#include "shm_pci.h"
#include "gam.h"
#include "ribconfig.h"

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>

#include "flow_alloc.pb-c.h"
typedef FlowAllocMsg flow_alloc_msg_t;

#define FD_UPDATE_TIMEOUT 100000 /* nanoseconds */

struct nm1_flow {
        struct list_head   next;
        int                fd;
        qosspec_t          qs;
        struct conn_info * info;
};

struct {
        flow_set_t *       nm1_set[QOS_CUBE_MAX];
        fqueue_t *         nm1_fqs[QOS_CUBE_MAX];
        struct list_head   nm1_flows;
        pthread_rwlock_t   nm1_flows_lock;

        flow_set_t *       np1_set[QOS_CUBE_MAX];
        fqueue_t *         np1_fqs[QOS_CUBE_MAX];
        pthread_rwlock_t   np1_flows_lock;

        cep_id_t           np1_fd_to_cep_id[AP_MAX_FLOWS];
        int                np1_cep_id_to_fd[IPCPD_MAX_CONNS];

        pthread_t          np1_sdu_reader;
        pthread_t          nm1_sdu_reader;
        pthread_t          nm1_flow_wait;

        /* FIXME: Replace with PFF */
        int fd;

        struct gam *       gam;
} fmgr;

static void * fmgr_np1_sdu_reader(void * o)
{
        struct shm_du_buff * sdb;
        struct timespec      timeout = {0, FD_UPDATE_TIMEOUT};
        int                  fd;
        int                  i = 0;
        int                  ret;

        (void) o;

        while (true) {
                /* FIXME: replace with scheduling policy call */
                i = (i + 1) % QOS_CUBE_MAX;

                ret = flow_event_wait(fmgr.np1_set[i],
                                      fmgr.np1_fqs[i],
                                      &timeout);
                if (ret == -ETIMEDOUT)
                        continue;

                if (ret < 0) {
                        log_warn("Event error: %d.", ret);
                        continue;
                }

                while ((fd = fqueue_next(fmgr.np1_fqs[i])) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_warn("Failed to read SDU from fd %d.", fd);
                                continue;
                        }

                        pthread_rwlock_rdlock(&fmgr.np1_flows_lock);

                        if (frct_i_write_sdu(fmgr.np1_fd_to_cep_id[fd], sdb)) {
                                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                                ipcp_flow_del(sdb);
                                log_warn("Failed to hand SDU to FRCT.");
                                continue;
                        }

                        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

                }
        }

        return (void *) 0;
}

void * fmgr_nm1_sdu_reader(void * o)
{
        struct timespec      timeout = {0, FD_UPDATE_TIMEOUT};
        struct shm_du_buff * sdb;
        struct pci           pci;
        int                  fd;
        int                  i = 0;
        int                  ret;

        (void) o;

        memset(&pci, 0, sizeof(pci));

        while (true) {
                /* FIXME: replace with scheduling policy call */
                i = (i + 1) % QOS_CUBE_MAX;

                ret = flow_event_wait(fmgr.nm1_set[i],
                                      fmgr.nm1_fqs[i],
                                      &timeout);
                if (ret == -ETIMEDOUT)
                        continue;

                if (ret < 0) {
                        log_err("Event error: %d.", ret);
                        continue;
                }

                while ((fd = fqueue_next(fmgr.nm1_fqs[i])) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_err("Failed to read SDU from fd %d.", fd);
                                continue;
                        }

                        shm_pci_des(sdb, &pci);

                        if (pci.dst_addr != ipcpi.address) {
                                log_dbg("PDU needs to be forwarded.");

                                if (pci.ttl == 0) {
                                        log_dbg("TTL was zero.");
                                        ipcp_flow_del(sdb);
                                        continue;
                                }

                                /*
                                 * FIXME: Dropping for now, since
                                 * we don't have a PFF yet
                                 */
                                ipcp_flow_del(sdb);
                                continue;
                        }

                        shm_pci_shrink(sdb);

                        if (frct_nm1_post_sdu(&pci, sdb)) {
                                log_err("Failed to hand PDU to FRCT.");
                                ipcp_flow_del(sdb);
                                continue;
                        }
                }
        }

        return (void *) 0;
}

static void * fmgr_nm1_flow_wait(void * o)
{
        qoscube_t          cube;
        struct conn_info * info;
        int                fd;
        qosspec_t          qs;
        struct nm1_flow *  flow;

        (void) o;

        while (true) {
                if (gam_flow_wait(fmgr.gam, &fd, &info, &qs)) {
                        log_err("Failed to get next flow descriptor.");
                        continue;
                }

                ipcp_flow_get_qoscube(fd, &cube);
                flow_set_add(fmgr.nm1_set[cube], fd);

                /* FIXME: Temporary, until we have a PFF */
                fmgr.fd = fd;

                pthread_rwlock_wrlock(&fmgr.nm1_flows_lock);
                flow = malloc(sizeof(*flow));
                if (flow == NULL) {
                        free(info);
                        pthread_rwlock_unlock(&fmgr.nm1_flows_lock);
                        continue;
                }

                flow->info = info;
                flow->fd = fd;
                flow->qs = qs;

                list_head_init(&flow->next);
                list_add(&flow->next, &fmgr.nm1_flows);

                pthread_rwlock_unlock(&fmgr.nm1_flows_lock);
        }

        return (void *) 0;
}

static void fmgr_destroy_flows(void)
{
        int i;

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                flow_set_destroy(fmgr.nm1_set[i]);
                flow_set_destroy(fmgr.np1_set[i]);
                fqueue_destroy(fmgr.nm1_fqs[i]);
                fqueue_destroy(fmgr.np1_fqs[i]);
        }
}

int fmgr_init(void)
{
        enum pol_cacep     pc;
        enum pol_gam       pg;

        int i;

        for (i = 0; i < AP_MAX_FLOWS; ++i)
                fmgr.np1_fd_to_cep_id[i] = INVALID_CEP_ID;

        for (i = 0; i < IPCPD_MAX_CONNS; ++i)
                fmgr.np1_cep_id_to_fd[i] = -1;

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                fmgr.np1_set[i] = flow_set_create();
                if (fmgr.np1_set[i] == NULL) {
                        fmgr_destroy_flows();
                        return -1;
                }

                fmgr.np1_fqs[i] = fqueue_create();
                if (fmgr.np1_fqs[i] == NULL) {
                        fmgr_destroy_flows();
                        return -1;
                }

                fmgr.nm1_set[i] = flow_set_create();
                if (fmgr.nm1_set[i] == NULL) {
                        fmgr_destroy_flows();
                        return -1;
                }

                fmgr.nm1_fqs[i] = fqueue_create();
                if (fmgr.nm1_fqs[i] == NULL) {
                        fmgr_destroy_flows();
                        return -1;
                }
        }

        if (rib_read(BOOT_PATH "/dt/gam/type", &pg, sizeof(pg))
            != sizeof(pg)) {
                log_err("Failed to read policy for ribmgr gam.");
                return -1;
        }

        if (rib_read(BOOT_PATH "/dt/gam/cacep", &pc, sizeof(pc))
            != sizeof(pc)) {
                log_err("Failed to read CACEP policy for ribmgr gam.");
                return -1;
        }

        /* FIXME: Implement cacep policies */
        (void) pc;

        fmgr.gam = gam_create(pg);
        if (fmgr.gam == NULL) {
                log_err("Failed to create graph adjacency manager.");
                fmgr_destroy_flows();
                return -1;
        }

        list_head_init(&fmgr.nm1_flows);

        pthread_rwlock_init(&fmgr.nm1_flows_lock, NULL);
        pthread_rwlock_init(&fmgr.np1_flows_lock, NULL);

        pthread_create(&fmgr.np1_sdu_reader, NULL, fmgr_np1_sdu_reader, NULL);
        pthread_create(&fmgr.nm1_sdu_reader, NULL, fmgr_nm1_sdu_reader, NULL);
        pthread_create(&fmgr.nm1_flow_wait, NULL, fmgr_nm1_flow_wait, NULL);

        return 0;
}

void fmgr_fini()
{
        struct list_head * pos = NULL;
        struct list_head * n = NULL;
        qoscube_t          cube;

        pthread_cancel(fmgr.np1_sdu_reader);
        pthread_cancel(fmgr.nm1_sdu_reader);
        pthread_cancel(fmgr.nm1_flow_wait);

        pthread_join(fmgr.np1_sdu_reader, NULL);
        pthread_join(fmgr.nm1_sdu_reader, NULL);
        pthread_join(fmgr.nm1_flow_wait, NULL);

        gam_destroy(fmgr.gam);

        pthread_rwlock_wrlock(&fmgr.nm1_flows_lock);

        list_for_each_safe(pos, n, &fmgr.nm1_flows) {
                struct nm1_flow * flow =
                        list_entry(pos, struct nm1_flow, next);
                list_del(&flow->next);
                flow_dealloc(flow->fd);
                ipcp_flow_get_qoscube(flow->fd, &cube);
                flow_set_del(fmgr.nm1_set[cube], flow->fd);
                free(flow->info->name);
                free(flow->info);
                free(flow);
        }

        pthread_rwlock_unlock(&fmgr.nm1_flows_lock);

        pthread_rwlock_destroy(&fmgr.nm1_flows_lock);
        pthread_rwlock_destroy(&fmgr.np1_flows_lock);

        fmgr_destroy_flows();
}

int fmgr_np1_alloc(int       fd,
                   char *    dst_ap_name,
                   qoscube_t cube)
{
        cep_id_t         cep_id;
        buffer_t         buf;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        char             path[RIB_MAX_PATH_LEN + 1];
        uint64_t         addr;
        ssize_t          ch;
        ssize_t          i;
        char **          children;
        char *           dst_ipcp = NULL;

        assert(strlen(dst_ap_name) + strlen("/" DIR_NAME) + 1
               < RIB_MAX_PATH_LEN);

        strcpy(path, DIR_PATH);

        rib_path_append(path, dst_ap_name);

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

        strcpy(path, "/" MEMBERS_NAME);

        rib_path_append(path, dst_ipcp);

        free(dst_ipcp);

        if (rib_read(path, &addr, sizeof(addr)) < 0)
                return -1;

        msg.code = FLOW_ALLOC_CODE__FLOW_REQ;
        msg.dst_name = dst_ap_name;
        msg.has_qoscube = true;
        msg.qoscube = cube;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0)
                return -1;

        buf.data = malloc(buf.len);
        if (buf.data == NULL)
                return -1;

        flow_alloc_msg__pack(&msg, buf.data);

        pthread_rwlock_wrlock(&fmgr.np1_flows_lock);

        cep_id = frct_i_create(addr, &buf, cube);
        if (cep_id == INVALID_CEP_ID) {
                free(buf.data);
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                return -1;
        }

        fmgr.np1_fd_to_cep_id[fd] = cep_id;
        fmgr.np1_cep_id_to_fd[cep_id] = fd;

        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

        return 0;
}

/* Call under np1_flows lock */
static int np1_flow_dealloc(int fd)
{
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        buffer_t         buf;
        int              ret;
        qoscube_t        cube;

        ipcp_flow_get_qoscube(fd, &cube);
        flow_set_del(fmgr.np1_set[cube], fd);

        msg.code = FLOW_ALLOC_CODE__FLOW_DEALLOC;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0)
                return -1;

        buf.data = malloc(buf.len);
        if (buf.data == NULL)
                return -ENOMEM;

        flow_alloc_msg__pack(&msg, buf.data);

        ret = frct_i_destroy(fmgr.np1_fd_to_cep_id[fd], &buf);

        fmgr.np1_cep_id_to_fd[fmgr.np1_fd_to_cep_id[fd]] = INVALID_CEP_ID;
        fmgr.np1_fd_to_cep_id[fd] = -1;

        free(buf.data);

        return ret;
}

int fmgr_np1_alloc_resp(int fd,
                        int response)
{
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        buffer_t         buf;

        msg.code = FLOW_ALLOC_CODE__FLOW_REPLY;
        msg.response = response;
        msg.has_response = true;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0)
                return -1;

        buf.data = malloc(buf.len);
        if (buf.data == NULL)
                return -ENOMEM;

        flow_alloc_msg__pack(&msg, buf.data);

        pthread_rwlock_wrlock(&fmgr.np1_flows_lock);

        if (response < 0) {
                frct_i_destroy(fmgr.np1_fd_to_cep_id[fd], &buf);
                free(buf.data);
                fmgr.np1_cep_id_to_fd[fmgr.np1_fd_to_cep_id[fd]]
                        = INVALID_CEP_ID;
                fmgr.np1_fd_to_cep_id[fd] = -1;
        } else {
                qoscube_t cube;
                ipcp_flow_get_qoscube(fd, &cube);
                if (frct_i_accept(fmgr.np1_fd_to_cep_id[fd], &buf, cube)) {
                        pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                        return -1;
                }
                flow_set_add(fmgr.np1_set[cube], fd);
        }

        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

        return 0;
}

int fmgr_np1_dealloc(int fd)
{
        int ret;

        pthread_rwlock_wrlock(&fmgr.np1_flows_lock);

        ret = np1_flow_dealloc(fd);

        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

        return ret;
}

int fmgr_np1_post_buf(cep_id_t   cep_id,
                      buffer_t * buf)
{
        int ret = 0;
        int fd;
        flow_alloc_msg_t * msg;
        qoscube_t cube;

        /* Depending on the message call the function in ipcp-dev.h */

        msg = flow_alloc_msg__unpack(NULL, buf->len, buf->data);
        if (msg == NULL) {
                log_err("Failed to unpack flow alloc message");
                return -1;
        }

        switch (msg->code) {
        case FLOW_ALLOC_CODE__FLOW_REQ:
                fd = ipcp_flow_req_arr(getpid(),
                                       msg->dst_name,
                                       msg->qoscube);
                if (fd < 0) {
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        log_err("Failed to get fd for flow.");
                        return -1;
                }

                pthread_rwlock_wrlock(&fmgr.np1_flows_lock);

                fmgr.np1_fd_to_cep_id[fd] = cep_id;
                fmgr.np1_cep_id_to_fd[cep_id] = fd;

                pthread_rwlock_unlock(&fmgr.np1_flows_lock);

                break;
        case FLOW_ALLOC_CODE__FLOW_REPLY:
                pthread_rwlock_wrlock(&fmgr.np1_flows_lock);

                fd = fmgr.np1_cep_id_to_fd[cep_id];
                ret = ipcp_flow_alloc_reply(fd, msg->response);
                if (msg->response < 0) {
                        fmgr.np1_fd_to_cep_id[fd] = INVALID_CEP_ID;
                        fmgr.np1_cep_id_to_fd[cep_id] = -1;
                } else {
                        ipcp_flow_get_qoscube(fd, &cube);
                        flow_set_add(fmgr.np1_set[cube],
                                     fmgr.np1_cep_id_to_fd[cep_id]);
                }

                pthread_rwlock_unlock(&fmgr.np1_flows_lock);

                break;
        case FLOW_ALLOC_CODE__FLOW_DEALLOC:
                fd = fmgr.np1_cep_id_to_fd[cep_id];
                ipcp_flow_get_qoscube(fd, &cube);
                flow_set_del(fmgr.np1_set[cube], fd);
                ret = flow_dealloc(fd);
                break;
        default:
                log_err("Got an unknown flow allocation message.");
                ret = -1;
                break;
        }

        flow_alloc_msg__free_unpacked(msg, NULL);

        return ret;
}

int fmgr_np1_post_sdu(cep_id_t             cep_id,
                      struct shm_du_buff * sdb)
{
        int fd;

        pthread_rwlock_rdlock(&fmgr.np1_flows_lock);

        fd = fmgr.np1_cep_id_to_fd[cep_id];
        if (ipcp_flow_write(fd, sdb)) {
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                log_err("Failed to hand SDU to N flow.");
                return -1;
        }

        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

        return 0;
}

int fmgr_nm1_flow_arr(int       fd,
                      qosspec_t qs)
{
        assert(fmgr.gam);

        if (gam_flow_arr(fmgr.gam, fd, qs)) {
                log_err("Failed to hand to graph adjacency manager.");
                return -1;
        }

        return 0;
}

int fmgr_nm1_write_sdu(struct pci *         pci,
                       struct shm_du_buff * sdb)
{
        if (pci == NULL || sdb == NULL)
                return -1;

        if (shm_pci_ser(sdb, pci)) {
                log_err("Failed to serialize PDU.");
                ipcp_flow_del(sdb);
                return -1;
        }

        if (ipcp_flow_write(fmgr.fd, sdb)) {
                log_err("Failed to write SDU to fd %d.", fmgr.fd);
                ipcp_flow_del(sdb);
                return -1;
        }

        return 0;
}

int fmgr_nm1_write_buf(struct pci * pci,
                       buffer_t *   buf)
{
        buffer_t * buffer;

        if (pci == NULL || buf == NULL || buf->data == NULL)
                return -1;

        buffer = shm_pci_ser_buf(buf, pci);
        if (buffer == NULL) {
                log_err("Failed to serialize buffer.");
                free(buf->data);
                return -1;
        }

        if (flow_write(fmgr.fd, buffer->data, buffer->len) == -1) {
                log_err("Failed to write buffer to fd.");
                free(buffer);
                return -1;
        }

        free(buffer);
        return 0;
}
