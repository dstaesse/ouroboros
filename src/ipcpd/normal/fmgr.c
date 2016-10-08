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
#include <ouroboros/select.h>
#include <ouroboros/errno.h>

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>

#include "fmgr.h"
#include "ribmgr.h"
#include "frct.h"
#include "ipcp.h"
#include "rmt.h"
#include "shm_pci.h"
#include "config.h"

#include "flow_alloc.pb-c.h"
typedef FlowAllocMsg flow_alloc_msg_t;

struct n_flow {
        int           fd;
        cep_id_t      cep_id;
        enum qos_cube qos;

        struct list_head next;
};

struct n_1_flow {
        int              fd;
        char *           ae_name;
        struct list_head next;
};

struct {
        pthread_t n_1_flow_acceptor;

        /* FIXME: Make this a table */
        struct list_head n_1_flows;
        pthread_mutex_t n_1_flows_lock;

        /* FIXME: Make this a table */
        struct list_head n_flows;
        /* FIXME: Make this a read/write lock */
        pthread_mutex_t n_flows_lock;

        struct flow_set * set;
        pthread_t n_reader;
} fmgr;

static int add_n_1_fd(int fd, char * ae_name)
{
        struct n_1_flow * tmp;

        if (ae_name == NULL)
                return -1;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return -1;

        tmp->fd = fd;
        tmp->ae_name = ae_name;

        INIT_LIST_HEAD(&tmp->next);

        pthread_mutex_lock(&fmgr.n_1_flows_lock);
        list_add(&tmp->next, &fmgr.n_1_flows);
        pthread_mutex_unlock(&fmgr.n_1_flows_lock);

        return 0;
}

/* Call under n_flows lock */
static struct n_flow * get_n_flow_by_fd(int fd)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &fmgr.n_flows) {
                struct n_flow * e = list_entry(pos, struct n_flow, next);
                if (e->fd == fd)
                        return e;
        }

        return NULL;
}

/* Call under n_flows lock */
static struct n_flow * get_n_flow_by_cep_id(cep_id_t cep_id)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &fmgr.n_flows) {
                struct n_flow * e = list_entry(pos, struct n_flow, next);
                if (e->cep_id == cep_id)
                        return e;
        }

        return NULL;
}

static void * fmgr_n_1_acceptor(void * o)
{
        int    fd;
        char * ae_name;

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

                if (strcmp(ae_name, DT_AE) == 0) {
                        /* FIXME: Pass correct QoS cube */
                        if (rmt_dt_flow(fd, 0)) {
                                LOG_ERR("Failed to hand fd to FRCT.");
                                flow_dealloc(fd);
                                continue;
                        }
                }

                if (add_n_1_fd(fd, ae_name)) {
                        LOG_ERR("Failed to add file descriptor to list.");
                        flow_dealloc(fd);
                        continue;
                }
        }

        return (void *) 0;
}

static void * fmgr_n_reader(void * o)
{
        struct shm_du_buff * sdb;
        struct timespec timeout = {0, FD_UPDATE_TIMEOUT};
        struct n_flow * flow;

        while (true) {
                int fd = flow_select(fmgr.set, &timeout);
                if (fd == -ETIMEDOUT)
                        continue;

                if (fd < 0) {
                        LOG_ERR("Failed to get active fd.");
                        continue;
                }

                if (ipcp_flow_read(fd, &sdb)) {
                        LOG_ERR("Failed to read SDU from fd %d.", fd);
                        continue;
                }

                pthread_mutex_lock(&fmgr.n_flows_lock);
                flow = get_n_flow_by_fd(fd);
                if (flow == NULL) {
                        pthread_mutex_unlock(&fmgr.n_flows_lock);
                        ipcp_flow_del(sdb);
                        LOG_ERR("Failed to retrieve flow.");
                        continue;
                }

                if (frct_i_write_sdu(flow->cep_id, sdb)) {
                        pthread_mutex_unlock(&fmgr.n_flows_lock);
                        ipcp_flow_del(sdb);
                        LOG_ERR("Failed to hand SDU to FRCT.");
                        continue;
                }

                pthread_mutex_unlock(&fmgr.n_flows_lock);
        }

        return (void *) 0;
}

int fmgr_init()
{
        INIT_LIST_HEAD(&fmgr.n_1_flows);
        INIT_LIST_HEAD(&fmgr.n_flows);

        pthread_mutex_init(&fmgr.n_1_flows_lock, NULL);
        pthread_mutex_init(&fmgr.n_flows_lock, NULL);

        fmgr.set = flow_set_create();
        if (fmgr.set == NULL)
                return -1;

        pthread_create(&fmgr.n_1_flow_acceptor, NULL, fmgr_n_1_acceptor, NULL);
        pthread_create(&fmgr.n_reader, NULL, fmgr_n_reader, NULL);

        return 0;
}

int fmgr_fini()
{
        struct list_head * pos = NULL;

        pthread_cancel(fmgr.n_1_flow_acceptor);
        pthread_cancel(fmgr.n_reader);

        pthread_join(fmgr.n_1_flow_acceptor, NULL);
        pthread_join(fmgr.n_reader, NULL);

        list_for_each(pos, &fmgr.n_1_flows) {
                struct n_1_flow * e = list_entry(pos, struct n_1_flow, next);
                if (e->ae_name != NULL)
                        free(e->ae_name);
                if (ribmgr_remove_flow(e->fd))
                    LOG_ERR("Failed to remove management flow.");
        }

        pthread_mutex_destroy(&fmgr.n_1_flows_lock);
        pthread_mutex_destroy(&fmgr.n_flows_lock);

        flow_set_destroy(fmgr.set);

        return 0;
}

int fmgr_mgmt_flow(char * dst_name)
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

        if (add_n_1_fd(fd, ae_name)) {
                LOG_ERR("Failed to add file descriptor to list.");
                flow_dealloc(fd);
                return -1;
        }

        return 0;
}

int fmgr_dt_flow(char * dst_name, enum qos_cube qos)
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

        if (rmt_dt_flow(fd, qos)) {
                LOG_ERR("Failed to hand file descriptor to FRCT");
                flow_dealloc(fd);
                free(ae_name);
                return -1;
        }

        if (add_n_1_fd(fd, ae_name)) {
                LOG_ERR("Failed to add file descriptor to list.");
                flow_dealloc(fd);
                free(ae_name);
                return -1;
        }

        return 0;
}

int fmgr_flow_alloc(int           fd,
                    char *        dst_ap_name,
                    char *        src_ae_name,
                    enum qos_cube qos)
{
        struct n_flow * flow;
        cep_id_t cep_id;
        uint32_t address = 0;
        buffer_t buf;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;

        flow = malloc(sizeof(*flow));
        if (flow == NULL)
                return -1;

        /* FIXME: Obtain correct address here from DIF NSM */

        msg.code = FLOW_ALLOC_CODE__FLOW_REQ;
        msg.dst_name = dst_ap_name;
        msg.src_ae_name = src_ae_name;
        msg.qos_cube = qos;
        msg.has_qos_cube = true;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0) {
                free(flow);
                return -1;
        }

        buf.data = malloc(buf.len);
        if (buf.data == NULL) {
                free(flow);
                return -1;
        }

        flow_alloc_msg__pack(&msg, buf.data);

        pthread_mutex_lock(&fmgr.n_flows_lock);

        cep_id = frct_i_create(address, &buf, qos);
        if (cep_id == INVALID_CEP_ID) {
                free(buf.data);
                free(flow);
                pthread_mutex_unlock(&fmgr.n_flows_lock);
                return -1;
        }

        free(buf.data);

        flow->fd     = fd;
        flow->cep_id = cep_id;
        flow->qos    = qos;

        INIT_LIST_HEAD(&flow->next);

        list_add(&flow->next, &fmgr.n_flows);

        pthread_mutex_unlock(&fmgr.n_flows_lock);

        return 0;
}

/* Call under n_flows lock */
static int n_flow_dealloc(int fd)
{
        struct n_flow * flow;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        buffer_t buf;
        int ret;

        flow_set_del(fmgr.set, fd);

        flow = get_n_flow_by_fd(fd);
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
        list_del(&flow->next);

        free(flow);
        free(buf.data);

        return ret;
}

int fmgr_flow_alloc_resp(int fd, int response)
{
        struct n_flow * flow;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        buffer_t buf;

        pthread_mutex_lock(&fmgr.n_flows_lock);

        flow = get_n_flow_by_fd(fd);
        if (flow == NULL) {
                pthread_mutex_unlock(&fmgr.n_flows_lock);
                return -1;
        }

        msg.code = FLOW_ALLOC_CODE__FLOW_REPLY;
        msg.response = response;
        msg.has_response = true;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0) {
                pthread_mutex_unlock(&fmgr.n_flows_lock);
                return -1;
        }

        buf.data = malloc(buf.len);
        if (buf.data == NULL) {
                pthread_mutex_unlock(&fmgr.n_flows_lock);
                return -1;
        }

        flow_alloc_msg__pack(&msg, buf.data);

        if (response < 0) {
                frct_i_destroy(flow->cep_id, &buf);
                free(buf.data);
                list_del(&flow->next);
                free(flow);
        } else {
                if (frct_i_accept(flow->cep_id, &buf, flow->qos)) {
                        pthread_mutex_unlock(&fmgr.n_flows_lock);
                        return -1;
                }
                flow_set_add(fmgr.set, fd);
        }

        pthread_mutex_unlock(&fmgr.n_flows_lock);

        return 0;
}

int fmgr_flow_dealloc(int fd)
{
        int ret;

        pthread_mutex_lock(&fmgr.n_flows_lock);
        ret = n_flow_dealloc(fd);
        pthread_mutex_unlock(&fmgr.n_flows_lock);

        return ret;
}

int fmgr_frct_post_buf(cep_id_t   cep_id,
                       buffer_t * buf)
{
        struct n_flow * flow;
        int ret = 0;
        int fd;
        flow_alloc_msg_t * msg;

        pthread_mutex_lock(&fmgr.n_flows_lock);

        /* Depending on the message call the function in ipcp-dev.h */

        msg = flow_alloc_msg__unpack(NULL, buf->len, buf->data);
        if (msg == NULL) {
                pthread_mutex_unlock(&fmgr.n_flows_lock);
                LOG_ERR("Failed to unpack flow alloc message");
                return -1;
        }

        switch (msg->code) {
        case FLOW_ALLOC_CODE__FLOW_REQ:
                flow = malloc(sizeof(*flow));
                if (flow == NULL) {
                        pthread_mutex_unlock(&fmgr.n_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        return -1;
                }

                flow->cep_id = cep_id;
                flow->qos = msg->qos_cube;

                fd = ipcp_flow_req_arr(getpid(),
                                       msg->dst_name,
                                       msg->src_ae_name);
                if (fd < 0) {
                        pthread_mutex_unlock(&fmgr.n_flows_lock);
                        free(flow);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("Failed to get fd for flow.");
                        return -1;
                }

                flow->fd = fd;

                INIT_LIST_HEAD(&flow->next);

                list_add(&flow->next, &fmgr.n_flows);
                break;
        case FLOW_ALLOC_CODE__FLOW_REPLY:
                flow = get_n_flow_by_cep_id(cep_id);
                if (flow == NULL) {
                        pthread_mutex_unlock(&fmgr.n_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("No such flow in flow manager.");
                        return -1;
                }

                ret = ipcp_flow_alloc_reply(flow->fd, msg->response);
                if (msg->response < 0) {
                        list_del(&flow->next);
                        free(flow);
                } else {
                        flow_set_add(fmgr.set, flow->fd);
                }

                break;
        case FLOW_ALLOC_CODE__FLOW_DEALLOC:
                flow = get_n_flow_by_cep_id(cep_id);
                if (flow == NULL) {
                        pthread_mutex_unlock(&fmgr.n_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("No such flow in flow manager.");
                        return -1;
                }

                flow_set_del(fmgr.set, flow->fd);

                ret = flow_dealloc(flow->fd);
                break;
        default:
                LOG_ERR("Got an unknown flow allocation message.");
                ret = -1;
                break;
        }

        pthread_mutex_unlock(&fmgr.n_flows_lock);

        flow_alloc_msg__free_unpacked(msg, NULL);

        return ret;
}

int fmgr_frct_post_sdu(cep_id_t             cep_id,
                       struct shm_du_buff * sdb)
{
        struct n_flow * flow;

        pthread_mutex_lock(&fmgr.n_flows_lock);

        flow = get_n_flow_by_cep_id(cep_id);
        if (flow == NULL) {
                pthread_mutex_unlock(&fmgr.n_flows_lock);
                LOG_ERR("Failed to find N flow.");
                return -1;
        }

        if (ipcp_flow_write(flow->fd, sdb)) {
                pthread_mutex_unlock(&fmgr.n_flows_lock);
                LOG_ERR("Failed to hand SDU to N flow.");
                return -1;
        }

        pthread_mutex_unlock(&fmgr.n_flows_lock);

        return 0;
}
