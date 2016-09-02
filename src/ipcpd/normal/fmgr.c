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
#include <ouroboros/ipcp.h>

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>

#include "fmgr.h"
#include "ribmgr.h"
#include "frct.h"
#include "ipcp.h"

#include "flow_alloc.pb-c.h"
typedef FlowAllocMsg flow_alloc_msg_t;

extern struct ipcp * _ipcp;

struct n_flow {
        struct flow flow;
        struct frct_i * frct_i;
        enum qos_cube qos;

        struct list_head next;
};

struct n_1_flow {
        int fd;
        char * ae_name;
        struct list_head next;
};

struct fmgr {
        pthread_t listen_thread;

        struct list_head n_1_flows;
        pthread_mutex_t n_1_flows_lock;

        struct list_head n_flows;
        /* FIXME: Make this a read/write lock */
        pthread_mutex_t n_flows_lock;
} * fmgr = NULL;

static int add_n_1_fd(int fd,
                      char * ae_name)
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

        pthread_mutex_lock(&fmgr->n_1_flows_lock);
        list_add(&tmp->next, &fmgr->n_1_flows);
        pthread_mutex_unlock(&fmgr->n_1_flows_lock);

        return 0;
}

static void * fmgr_listen(void * o)
{
        int fd;
        char * ae_name;

        while (true) {
                ipcp_wait_state(_ipcp, IPCP_ENROLLED, NULL);

                pthread_rwlock_rdlock(&_ipcp->state_lock);

                if (ipcp_get_state(_ipcp) == IPCP_SHUTDOWN) {
                        pthread_rwlock_unlock(&_ipcp->state_lock);
                        return 0;
                }

                pthread_rwlock_unlock(&_ipcp->state_lock);

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
                        if (frct_dt_flow(fd, 0)) {
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

int fmgr_init()
{
        fmgr = malloc(sizeof(*fmgr));
        if (fmgr == NULL)
                return -1;

        INIT_LIST_HEAD(&fmgr->n_1_flows);
        INIT_LIST_HEAD(&fmgr->n_flows);

        pthread_mutex_init(&fmgr->n_1_flows_lock, NULL);
        pthread_mutex_init(&fmgr->n_flows_lock, NULL);

        pthread_create(&fmgr->listen_thread, NULL, fmgr_listen, NULL);

        return 0;
}

int fmgr_fini()
{
        struct list_head * pos = NULL;

        pthread_cancel(fmgr->listen_thread);

        pthread_join(fmgr->listen_thread, NULL);

        list_for_each(pos, &fmgr->n_1_flows) {
                struct n_1_flow * e =
                        list_entry(pos, struct n_1_flow, next);
                if (e->ae_name != NULL)
                        free(e->ae_name);
                if (ribmgr_remove_flow(e->fd))
                    LOG_ERR("Failed to remove management flow.");
        }

        pthread_mutex_destroy(&fmgr->n_1_flows_lock);
        pthread_mutex_destroy(&fmgr->n_flows_lock);

        free(fmgr);

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

int fmgr_dt_flow(char * dst_name,
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

        if (frct_dt_flow(fd, qos)) {
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

/* Call under n_flows lock */
static struct n_flow * get_n_flow_by_port_id(int port_id)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &fmgr->n_flows) {
                struct n_flow * e =
                        list_entry(pos, struct n_flow, next);
                if (e->flow.port_id == port_id)
                        return e;
        }

        return NULL;
}

/* Call under n_flows lock */
static struct n_flow * get_n_flow_by_frct_i(struct frct_i * frct_i)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &fmgr->n_flows) {
                struct n_flow * e =
                        list_entry(pos, struct n_flow, next);
                if (e->frct_i == frct_i)
                        return e;
        }

        return NULL;
}

int fmgr_flow_alloc(pid_t         n_api,
                    int           port_id,
                    char *        dst_ap_name,
                    char *        src_ae_name,
                    enum qos_cube qos)
{
        struct n_flow * flow;
        struct frct_i * frct_i;
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

        pthread_mutex_lock(&fmgr->n_flows_lock);

        frct_i = frct_i_create(address, &buf, qos);
        if (frct_i == NULL) {
                free(buf.data);
                free(flow);
                pthread_mutex_unlock(&fmgr->n_flows_lock);
                return -1;
        }

        free(buf.data);

        flow->flow.rb = shm_ap_rbuff_open_s(n_api);
        if (flow->flow.rb == NULL) {
                pthread_mutex_unlock(&fmgr->n_flows_lock);
                free(flow);
                return -1;
        }

        flow->flow.api = n_api;
        flow->flow.port_id = port_id;
        flow->flow.state = FLOW_PENDING;
        flow->frct_i = frct_i;
        flow->qos = qos;

        INIT_LIST_HEAD(&flow->next);

        list_add(&flow->next, &fmgr->n_flows);

        pthread_mutex_unlock(&fmgr->n_flows_lock);

        return 0;
}

/* Call under n_flows lock */
static int n_flow_dealloc(int port_id)
{
        struct n_flow * flow;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        buffer_t buf;
        int ret;

        flow = get_n_flow_by_port_id(port_id);
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

        ret = frct_i_destroy(flow->frct_i, &buf);
        if (flow->flow.rb != NULL)
                shm_ap_rbuff_close(flow->flow.rb);
        list_del(&flow->next);

        free(flow);
        free(buf.data);

        return ret;
}

int fmgr_flow_alloc_resp(pid_t n_api,
                         int   port_id,
                         int   response)
{
        struct n_flow * flow;
        flow_alloc_msg_t msg = FLOW_ALLOC_MSG__INIT;
        buffer_t buf;

        pthread_mutex_lock(&fmgr->n_flows_lock);

        flow = get_n_flow_by_port_id(port_id);
        if (flow == NULL) {
                pthread_mutex_unlock(&fmgr->n_flows_lock);
                return -1;
        }

        if (flow->flow.state != FLOW_PENDING) {
                pthread_mutex_unlock(&fmgr->n_flows_lock);
                LOG_ERR("Flow is not pending.");
                return -1;
        }

        msg.code = FLOW_ALLOC_CODE__FLOW_REPLY;
        msg.response = response;
        msg.has_response = true;

        buf.len = flow_alloc_msg__get_packed_size(&msg);
        if (buf.len == 0) {
                pthread_mutex_unlock(&fmgr->n_flows_lock);
                return -1;
        }

        buf.data = malloc(buf.len);
        if (buf.data == NULL) {
                pthread_mutex_unlock(&fmgr->n_flows_lock);
                return -1;
        }

        flow_alloc_msg__pack(&msg, buf.data);

        if (response < 0) {
                frct_i_destroy(flow->frct_i, &buf);
                free(buf.data);
                list_del(&flow->next);
                free(flow);
        } else {
                if (frct_i_accept(flow->frct_i, &buf)) {
                        pthread_mutex_unlock(&fmgr->n_flows_lock);
                        return -1;
                }

                flow->flow.state = FLOW_ALLOCATED;
                flow->flow.api = n_api;

                flow->flow.rb = shm_ap_rbuff_open_s(n_api);
                if (flow->flow.rb == NULL) {
                        n_flow_dealloc(port_id);
                        pthread_mutex_unlock(&fmgr->n_flows_lock);
                        return -1;
                }
        }

        pthread_mutex_unlock(&fmgr->n_flows_lock);

        return 0;
}

int fmgr_flow_dealloc(int port_id)
{
        int ret;

        pthread_mutex_lock(&fmgr->n_flows_lock);
        ret = n_flow_dealloc(port_id);
        pthread_mutex_unlock(&fmgr->n_flows_lock);

        return ret;
}

int fmgr_flow_alloc_msg(struct frct_i * frct_i,
                        buffer_t *      buf)
{
        struct n_flow * flow;
        int ret = 0;
        int port_id;
        flow_alloc_msg_t * msg;

        pthread_mutex_lock(&fmgr->n_flows_lock);

        /* Depending on what is in the message call the function in ipcp.h */

        msg = flow_alloc_msg__unpack(NULL, buf->len, buf->data);
        if (msg == NULL) {
                pthread_mutex_unlock(&fmgr->n_flows_lock);
                LOG_ERR("Failed to unpack flow alloc message");
                return -1;
        }

        switch (msg->code) {
        case FLOW_ALLOC_CODE__FLOW_REQ:

                flow = malloc(sizeof(*flow));
                if (flow == NULL) {
                        pthread_mutex_unlock(&fmgr->n_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        return -1;
                }

                flow->flow.state = FLOW_PENDING;
                flow->frct_i = frct_i;
                flow->qos = msg->qos_cube;
                flow->flow.rb = NULL;
                flow->flow.api = 0;

                port_id = ipcp_flow_req_arr(getpid(),
                                            msg->dst_name,
                                            msg->src_ae_name);
                if (port_id < 0) {
                        pthread_mutex_unlock(&fmgr->n_flows_lock);
                        free(flow);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("Failed to get port-id from IRMd.");
                        return -1;
                }

                flow->flow.port_id = port_id;

                INIT_LIST_HEAD(&flow->next);

                list_add(&flow->next, &fmgr->n_flows);
                break;
        case FLOW_ALLOC_CODE__FLOW_REPLY:
                flow = get_n_flow_by_frct_i(frct_i);
                if (flow == NULL) {
                        pthread_mutex_unlock(&fmgr->n_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("No such flow in flow manager.");
                        return -1;
                }

                ret = ipcp_flow_alloc_reply(getpid(),
                                            flow->flow.port_id,
                                            msg->response);

                if (msg->response < 0) {
                        shm_ap_rbuff_close(flow->flow.rb);
                        list_del(&flow->next);
                        free(flow);
                }

                break;
        case FLOW_ALLOC_CODE__FLOW_DEALLOC:
                flow = get_n_flow_by_frct_i(frct_i);
                if (flow == NULL) {
                        pthread_mutex_unlock(&fmgr->n_flows_lock);
                        flow_alloc_msg__free_unpacked(msg, NULL);
                        LOG_ERR("No such flow in flow manager.");
                        return -1;
                }

                ret = irm_flow_dealloc(flow->flow.port_id);
                break;
        default:
                LOG_ERR("Got an unknown flow allocation message.");
                ret = -1;
                break;
        }

        pthread_mutex_unlock(&fmgr->n_flows_lock);

        flow_alloc_msg__free_unpacked(msg, NULL);

        return ret;
}
