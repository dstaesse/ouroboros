/*
 * Ouroboros - Copyright (C) 2016
 *
 * Flow manager of the IPC Process
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>

#include "fmgr.h"
#include "ribmgr.h"
#include "frct.h"
#include "ipcp.h"
#include "shm_pci.h"

#include "flow_alloc.pb-c.h"
typedef FlowAllocMsg flow_alloc_msg_t;

#define FD_UPDATE_TIMEOUT 100 /* microseconds */

struct np1_flow {
        int           fd;
        cep_id_t      cep_id;
        enum qos_cube qos;
};

struct nm1_flow {
        int           fd;
        char *        ae_name;
        enum qos_cube qos;
};

struct {
        pthread_t          nm1_flow_acceptor;
        struct nm1_flow ** nm1_flows;
        pthread_rwlock_t   nm1_flows_lock;
        flow_set_t *       nm1_set;

        struct np1_flow ** np1_flows;
        struct np1_flow ** np1_flows_cep;
        pthread_rwlock_t   np1_flows_lock;
        flow_set_t *       np1_set;
        pthread_t          np1_sdu_reader;

        /* FIXME: Replace with PFF */
        int fd;
} fmgr;

static int add_nm1_fd(int fd,
                      char * ae_name,
                      enum qos_cube qos)
{
        struct nm1_flow * tmp;

        if (ae_name == NULL)
                return -1;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return -1;

        tmp->fd = fd;
        tmp->ae_name = ae_name;
        tmp->qos = qos;

        pthread_rwlock_wrlock(&fmgr.nm1_flows_lock);
        fmgr.nm1_flows[fd] = tmp;
        pthread_rwlock_unlock(&fmgr.nm1_flows_lock);

        /* FIXME: Temporary, until we have a PFF */
        fmgr.fd = fd;

        return 0;
}

static int add_np1_fd(int           fd,
                      cep_id_t      cep_id,
                      enum qos_cube qos)
{
        struct np1_flow * flow;

        flow = malloc(sizeof(*flow));
        if (flow == NULL)
                return -1;

        flow->cep_id = cep_id;
        flow->qos = qos;
        flow->fd = fd;

        fmgr.np1_flows[fd] = flow;
        fmgr.np1_flows_cep[fd] = flow;

        return 0;
}

static void * fmgr_nm1_acceptor(void * o)
{
        int    fd;
        char * ae_name;

        (void) o;

        while (true) {
                ipcp_wait_state(IPCP_ENROLLED, NULL);

                pthread_rwlock_rdlock(&ipcpi.state_lock);

                if (ipcp_get_state() == IPCP_SHUTDOWN) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        return 0;
                }

                pthread_rwlock_unlock(&ipcpi.state_lock);

                fd = flow_accept(&ae_name);
                if (fd < 0) {
                        LOG_ERR("Failed to accept flow.");
                        continue;
                }

                if (!(strcmp(ae_name, MGMT_AE) == 0 ||
                      strcmp(ae_name, DT_AE) == 0)) {
                        if (flow_alloc_resp(fd, -1))
                                LOG_ERR("Failed to reply to flow allocation.");
                        flow_dealloc(fd);
                        continue;
                }

                if (flow_alloc_resp(fd, 0)) {
                        LOG_ERR("Failed to reply to flow allocation.");
                        flow_dealloc(fd);
                        continue;
                }

                LOG_DBG("Accepted new flow allocation request for AE %s.",
                        ae_name);

                if (strcmp(ae_name, MGMT_AE) == 0) {
                        if (ribmgr_add_flow(fd)) {
                                LOG_ERR("Failed to hand fd to RIB.");
                                flow_dealloc(fd);
                                continue;
                        }
                }

                /* FIXME: Pass correct QoS cube */
                if (add_nm1_fd(fd, ae_name, QOS_CUBE_BE)) {
                        LOG_ERR("Failed to add file descriptor to list.");
                        flow_dealloc(fd);
                        continue;
                }
        }

        return (void *) 0;
}

static void * fmgr_np1_sdu_reader(void * o)
{
        struct shm_du_buff * sdb;
        struct timespec timeout = {0, FD_UPDATE_TIMEOUT};
        struct np1_flow * flow;
        int fd;
        fqueue_t * fq = fqueue_create();
        if (fq == NULL)
                return (void *) 1;

        (void) o;

        while (true) {
                int ret = flow_event_wait(fmgr.np1_set, fq, &timeout);
                if (ret == -ETIMEDOUT)
                        continue;

                if (ret < 0) {
                        LOG_ERR("Event error: %d.", ret);
                        continue;
                }

                while ((fd = fqueue_next(fq)) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                LOG_ERR("Failed to read SDU from fd %d.", fd);
                                continue;
                        }

                        pthread_rwlock_rdlock(&fmgr.np1_flows_lock);

                        flow = fmgr.np1_flows[fd];
                        if (flow == NULL) {
                                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                                ipcp_flow_del(sdb);
                                LOG_ERR("Failed to retrieve flow.");
                                continue;
                        }

                        if (frct_i_write_sdu(flow->cep_id, sdb)) {
                                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                                ipcp_flow_del(sdb);
                                LOG_ERR("Failed to hand SDU to FRCT.");
                                continue;
                        }

                        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

                }
        }

        return (void *) 0;
}

void * fmgr_nm1_sdu_reader(void * o)
{
        struct timespec timeout = {0, FD_UPDATE_TIMEOUT};
        struct shm_du_buff * sdb;
        struct pci * pci;
        int fd;
        fqueue_t * fq = fqueue_create();
        if (fq == NULL)
                return (void *) 1;

        (void) o;

        while (true) {
                int ret = flow_event_wait(fmgr.nm1_set, fq, &timeout);
                if (ret == -ETIMEDOUT)
                        continue;

                if (ret < 0) {
                        LOG_ERR("Event error: %d.", ret);
                        continue;
                }

                while ((fd = fqueue_next(fq)) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                LOG_ERR("Failed to read SDU from fd %d.", fd);
                                continue;
                        }

                        pci = shm_pci_des(sdb);
                        if (pci == NULL) {
                                LOG_ERR("Failed to get PCI.");
                                ipcp_flow_del(sdb);
                                continue;
                        }

                        if (pci->dst_addr != ribmgr_address()) {
                                LOG_DBG("PDU needs to be forwarded.");

                                if (pci->ttl == 0) {
                                        LOG_DBG("TTL was zero.");
                                        ipcp_flow_del(sdb);
                                        free(pci);
                                        continue;
                                }

                                if (shm_pci_dec_ttl(sdb)) {
                                        LOG_ERR("Failed to decrease TTL.");
                                        ipcp_flow_del(sdb);
                                        free(pci);
                                        continue;
                                }
                                /*
                                 * FIXME: Dropping for now, since
                                 * we don't have a PFF yet
                                 */
                                ipcp_flow_del(sdb);
                                free(pci);
                                continue;
                        }

                        if (shm_pci_shrink(sdb)) {
                                LOG_ERR("Failed to shrink PDU.");
                                ipcp_flow_del(sdb);
                                free(pci);
                                continue;
                        }

                        if (frct_nm1_post_sdu(pci, sdb)) {
                                LOG_ERR("Failed to hand PDU to FRCT.");
                                ipcp_flow_del(sdb);
                                free(pci);
                                continue;
                        }
                }
        }

        return (void *) 0;
}

int fmgr_init()
{
        int i;

        fmgr.nm1_flows = malloc(sizeof(*(fmgr.nm1_flows)) * IRMD_MAX_FLOWS);
        if (fmgr.nm1_flows == NULL)
                return -1;

        fmgr.np1_flows = malloc(sizeof(*(fmgr.np1_flows)) * IRMD_MAX_FLOWS);
        if (fmgr.np1_flows == NULL) {
                free(fmgr.nm1_flows);
                return -1;
        }

        fmgr.np1_flows_cep =
                malloc(sizeof(*(fmgr.np1_flows_cep)) * IRMD_MAX_FLOWS);
        if (fmgr.np1_flows_cep == NULL) {
                free(fmgr.np1_flows);
                free(fmgr.nm1_flows);
                return -1;
        }

        for (i = 0; i < IRMD_MAX_FLOWS; i++) {
                fmgr.nm1_flows[i] = NULL;
                fmgr.np1_flows[i] = NULL;
                fmgr.np1_flows_cep[i] = NULL;
        }

        pthread_rwlock_init(&fmgr.nm1_flows_lock, NULL);
        pthread_rwlock_init(&fmgr.np1_flows_lock, NULL);

        fmgr.np1_set = flow_set_create();
        if (fmgr.np1_set == NULL) {
                free(fmgr.np1_flows_cep);
                free(fmgr.np1_flows);
                free(fmgr.nm1_flows);
                return -1;
        }

        fmgr.nm1_set = flow_set_create();
        if (fmgr.nm1_set == NULL) {
                flow_set_destroy(fmgr.np1_set);
                free(fmgr.np1_flows_cep);
                free(fmgr.np1_flows);
                free(fmgr.nm1_flows);
                return -1;
        }

        pthread_create(&fmgr.nm1_flow_acceptor, NULL, fmgr_nm1_acceptor, NULL);
        pthread_create(&fmgr.np1_sdu_reader, NULL, fmgr_np1_sdu_reader, NULL);

        return 0;
}

int fmgr_fini()
{
        int i;

        pthread_cancel(fmgr.nm1_flow_acceptor);
        pthread_cancel(fmgr.np1_sdu_reader);

        pthread_join(fmgr.nm1_flow_acceptor, NULL);
        pthread_join(fmgr.np1_sdu_reader, NULL);

        for (i = 0; i < IRMD_MAX_FLOWS; i++) {
                if (fmgr.nm1_flows[i] == NULL)
                        continue;
                if (fmgr.nm1_flows[i]->ae_name != NULL)
                        free(fmgr.nm1_flows[i]->ae_name);
                if (ribmgr_remove_flow(fmgr.nm1_flows[i]->fd))
                    LOG_ERR("Failed to remove management flow.");
        }

        pthread_rwlock_destroy(&fmgr.nm1_flows_lock);
        pthread_rwlock_destroy(&fmgr.np1_flows_lock);

        flow_set_destroy(fmgr.nm1_set);
        flow_set_destroy(fmgr.np1_set);
        free(fmgr.np1_flows_cep);
        free(fmgr.np1_flows);
        free(fmgr.nm1_flows);

        return 0;
}

int fmgr_np1_alloc(int           fd,
                    char *        dst_ap_name,
                    char *        src_ae_name,
                    enum qos_cube qos)
{
        cep_id_t cep_id;
        uint32_t address = 0;
        buffer_t buf;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_ENROLLED) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("IPCP is not enrolled yet.");
                return -1; /* -ENOTINIT */
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        /* FIXME: Obtain correct address here from DIF NSM */

        msg.code = FLOW_ALLOC_CODE__FLOW_REQ;
        msg.dst_name = dst_ap_name;
        msg.src_ae_name = src_ae_name;
        msg.qos_cube = qos;
        msg.has_qos_cube = true;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0)
                return -1;

        buf.data = malloc(buf.len);
        if (buf.data == NULL)
                return -1;

        flow_alloc_msg__pack(&msg, buf.data);

        pthread_rwlock_wrlock(&fmgr.np1_flows_lock);

        cep_id = frct_i_create(address, &buf, qos);
        if (cep_id == INVALID_CEP_ID) {
                free(buf.data);
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                return -1;
        }

        free(buf.data);

        if (add_np1_fd(fd, cep_id, qos)) {
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                return -1;
        }

        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

        return 0;
}

/* Call under np1_flows lock */
static int np1_flow_dealloc(int fd)
{
        struct np1_flow * flow;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        buffer_t buf;
        int ret;

        flow_set_del(fmgr.np1_set, fd);

        flow = fmgr.np1_flows[fd];
        if (flow == NULL)
                return -1;

        msg.code = FLOW_ALLOC_CODE__FLOW_DEALLOC;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0)
                return -1;

        buf.data = malloc(buf.len);
        if (buf.data == NULL)
                return -1;

        flow_alloc_msg__pack(&msg, buf.data);

        ret = frct_i_destroy(flow->cep_id, &buf);

        fmgr.np1_flows[fd] = NULL;
        fmgr.np1_flows_cep[flow->cep_id] = NULL;

        free(flow);
        free(buf.data);

        return ret;
}

int fmgr_np1_alloc_resp(int fd, int response)
{
        struct np1_flow * flow;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        buffer_t buf;

        pthread_rwlock_wrlock(&fmgr.np1_flows_lock);

        flow = fmgr.np1_flows[fd];
        if (flow == NULL) {
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                return -1;
        }

        msg.code = FLOW_ALLOC_CODE__FLOW_REPLY;
        msg.response = response;
        msg.has_response = true;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0) {
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                return -1;
        }

        buf.data = malloc(buf.len);
        if (buf.data == NULL) {
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                return -1;
        }

        flow_alloc_msg__pack(&msg, buf.data);

        if (response < 0) {
                frct_i_destroy(flow->cep_id, &buf);
                free(buf.data);
                fmgr.np1_flows[fd] = NULL;
                fmgr.np1_flows_cep[flow->cep_id] = NULL;
                free(flow);
        } else {
                if (frct_i_accept(flow->cep_id, &buf, flow->qos)) {
                        pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                        return -1;
                }
                flow_set_add(fmgr.np1_set, fd);
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
        struct np1_flow * flow;
        int ret = 0;
        int fd;
        flow_alloc_msg_t * msg;

        pthread_rwlock_wrlock(&fmgr.np1_flows_lock);

        /* Depending on the message call the function in ipcp-dev.h */

        msg = flow_alloc_msg__unpack(NULL, buf->len, buf->data);
        if (msg == NULL) {
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                LOG_ERR("Failed to unpack flow alloc message");
                return -1;
        }

        switch (msg->code) {
        case FLOW_ALLOC_CODE__FLOW_REQ:
                fd = ipcp_flow_req_arr(getpid(),
                                       msg->dst_name,
                                       msg->src_ae_name);
                if (fd < 0) {
                        pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("Failed to get fd for flow.");
                        return -1;
                }

                if (add_np1_fd(fd, cep_id, msg->qos_cube)) {
                        pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("Failed to add np1 flow.");
                        return -1;
                }

                break;
        case FLOW_ALLOC_CODE__FLOW_REPLY:
                flow = fmgr.np1_flows_cep[cep_id];
                if (flow == NULL) {
                        pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("No such flow in flow manager.");
                        return -1;
                }

                ret = ipcp_flow_alloc_reply(flow->fd, msg->response);
                if (msg->response < 0) {
                        fmgr.np1_flows[flow->fd] = NULL;
                        fmgr.np1_flows_cep[cep_id] = NULL;
                        free(flow);
                } else {
                        flow_set_add(fmgr.np1_set, flow->fd);
                }

                break;
        case FLOW_ALLOC_CODE__FLOW_DEALLOC:
                flow = fmgr.np1_flows_cep[cep_id];
                if (flow == NULL) {
                        pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("No such flow in flow manager.");
                        return -1;
                }

                flow_set_del(fmgr.np1_set, flow->fd);

                ret = flow_dealloc(flow->fd);
                break;
        default:
                LOG_ERR("Got an unknown flow allocation message.");
                ret = -1;
                break;
        }

        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

        flow_alloc_msg__free_unpacked(msg, NULL);

        return ret;
}

int fmgr_np1_post_sdu(cep_id_t             cep_id,
                      struct shm_du_buff * sdb)
{
        struct np1_flow * flow;

        pthread_rwlock_rdlock(&fmgr.np1_flows_lock);

        flow = fmgr.np1_flows_cep[cep_id];
        if (flow == NULL) {
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                LOG_ERR("Failed to find N flow.");
                return -1;
        }

        if (ipcp_flow_write(flow->fd, sdb)) {
                pthread_rwlock_unlock(&fmgr.np1_flows_lock);
                LOG_ERR("Failed to hand SDU to N flow.");
                return -1;
        }

        pthread_rwlock_unlock(&fmgr.np1_flows_lock);

        return 0;
}

int fmgr_nm1_mgmt_flow(char * dst_name)
{
        int fd;
        int result;
        char * ae_name;

        ae_name = strdup(MGMT_AE);
        if (ae_name == NULL)
                return -1;

        /* FIXME: Request retransmission. */
        fd = flow_alloc(dst_name, MGMT_AE, NULL);
        if (fd < 0) {
                LOG_ERR("Failed to allocate flow to %s", dst_name);
                free(ae_name);
                return -1;
        }

        result = flow_alloc_res(fd);
        if (result < 0) {
                LOG_ERR("Result of flow allocation to %s is %d",
                        dst_name, result);
                free(ae_name);
                return -1;
        }

        if (ribmgr_add_flow(fd)) {
                LOG_ERR("Failed to hand file descriptor to RIB manager");
                flow_dealloc(fd);
                free(ae_name);
                return -1;
        }

        /* FIXME: Pass correct QoS cube */
        if (add_nm1_fd(fd, ae_name, QOS_CUBE_BE)) {
                LOG_ERR("Failed to add file descriptor to list.");
                flow_dealloc(fd);
                return -1;
        }

        return 0;
}

int fmgr_nm1_dt_flow(char * dst_name,
                     enum qos_cube qos)
{
        int fd;
        int result;
        char * ae_name;

        ae_name = strdup(DT_AE);
        if (ae_name == NULL)
                return -1;

        /* FIXME: Map qos cube on correct QoS. */
        fd = flow_alloc(dst_name, DT_AE, NULL);
        if (fd < 0) {
                LOG_ERR("Failed to allocate flow to %s", dst_name);
                free(ae_name);
                return -1;
        }

        result = flow_alloc_res(fd);
        if (result < 0) {
                LOG_ERR("Result of flow allocation to %s is %d",
                        dst_name, result);
                free(ae_name);
                return -1;
        }

        if (add_nm1_fd(fd, ae_name, qos)) {
                LOG_ERR("Failed to add file descriptor to list.");
                flow_dealloc(fd);
                free(ae_name);
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
                LOG_ERR("Failed to serialize PDU.");
                ipcp_flow_del(sdb);
                return -1;
        }

        if (ipcp_flow_write(fmgr.fd, sdb)) {
                LOG_ERR("Failed to write SDU to fd %d.", fmgr.fd);
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
                LOG_ERR("Failed to serialize buffer.");
                free(buf->data);
                return -1;
        }

        if (flow_write(fmgr.fd, buffer->data, buffer->len) == -1) {
                LOG_ERR("Failed to write buffer to fd.");
                free(buffer);
                return -1;
        }

        free(buffer);
        return 0;
}
