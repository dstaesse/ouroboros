/*
 * Ouroboros - Copyright (C) 2016
 *
 * RIB manager of the IPC Process
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

#define OUROBOROS_PREFIX "rib-manager"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/cdap.h>
#include <ouroboros/list.h>

#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "ribmgr.h"
#include "dt_const.h"
#include "frct.h"
#include "ipcp.h"

#define ENROLLMENT "enrollment"

extern struct ipcp * _ipcp;

enum cdap_opcode {
        READ = 0,
        WRITE,
        START,
        STOP,
        CREATE,
        DELETE
};

struct cdap_request {
        enum cdap_opcode code;
        char *           name;
        int              invoke_id;
        struct cdap *    instance;

        struct list_head next;
};

struct mgmt_flow {
        struct cdap *    instance;
        int              fd;
        struct list_head next;
};

struct rib {
        struct dt_const  dtc;

        struct list_head flows;
        pthread_rwlock_t flows_lock;

        struct list_head cdap_reqs;
        pthread_mutex_t  cdap_reqs_lock;
} * rib = NULL;

/* Call while holding cdap_reqs_lock */
int cdap_request_add(struct cdap * instance,
                     enum cdap_opcode code,
                     char * name,
                     int invoke_id)
{
        struct cdap_request * req;

        req = malloc(sizeof(*req));
        if (req == NULL)
                return -1;

        req->code = code;
        req->invoke_id = invoke_id;
        req->instance = instance;

        req->name = strdup(name);
        if (req->name == NULL) {
                free(req);
                return -1;
        }

        INIT_LIST_HEAD(&req->next);

        list_add(&req->next, &rib->cdap_reqs);

        return 0;
}

int ribmgr_init()
{
        rib = malloc(sizeof(*rib));
        if (rib == NULL)
                return -1;

        INIT_LIST_HEAD(&rib->flows);
        INIT_LIST_HEAD(&rib->cdap_reqs);

        if (pthread_rwlock_init(&rib->flows_lock, NULL)) {
                LOG_ERR("Failed to initialize rwlock.");
                free(rib);
                return -1;
        }

        if (pthread_mutex_init(&rib->cdap_reqs_lock, NULL)) {
                LOG_ERR("Failed to initialize mutex.");
                free(rib);
                return -1;
        }

        return 0;
}

int ribmgr_fini()
{
        struct list_head * pos = NULL;
        struct list_head * n = NULL;

        pthread_mutex_lock(&rib->cdap_reqs_lock);
        list_for_each_safe(pos, n, &rib->cdap_reqs) {
                struct cdap_request * req =
                        list_entry(pos, struct cdap_request, next);

                free(req->name);
                list_del(&req->next);
                free(req);
        }
        pthread_mutex_unlock(&rib->cdap_reqs_lock);

        pthread_rwlock_wrlock(&rib->flows_lock);
        list_for_each_safe(pos, n, &rib->flows) {
                struct mgmt_flow * flow =
                        list_entry(pos, struct mgmt_flow, next);
                if (cdap_destroy(flow->instance))
                        LOG_ERR("Failed to destroy CDAP instance.");
                list_del(&flow->next);
                free(flow);
        }
        pthread_rwlock_unlock(&rib->flows_lock);

        free(rib);

        return 0;
}

int ribmgr_cdap_reply(struct cdap * instance,
                      int           invoke_id,
                      int           result,
                      buffer_t *    val,
                      size_t        len)
{
        LOG_MISSING;

        /* FIXME: Check all cdap_reqs here to see if we expect a reply */

        return -1;
}

int ribmgr_cdap_read(struct cdap * instance,
                     char *        name)
{
        LOG_MISSING;

        return -1;
}

int ribmgr_cdap_write(struct cdap * instance,
                      char *        name,
                      buffer_t *    val,
                      size_t        len,
                      uint32_t      flags)
{
        LOG_MISSING;

        return -1;
}

int ribmgr_cdap_create(struct cdap * instance,
                       char *        name,
                       buffer_t      val)
{
        LOG_MISSING;

        return -1;
}

int ribmgr_cdap_delete(struct cdap * instance,
                       char *        name,
                       buffer_t      val)
{
        LOG_MISSING;

        return -1;
}

int ribmgr_cdap_start(struct cdap * instance,
                      char *        name)
{
        LOG_MISSING;

        /* FIXME: Handle enrollment request here */

        return -1;
}

int ribmgr_cdap_stop(struct cdap * instance,
                     char *        name)
{
        LOG_MISSING;

        return -1;
}

static struct cdap_ops ribmgr_ops = {
        .cdap_reply  = ribmgr_cdap_reply,
        .cdap_read   = ribmgr_cdap_read,
        .cdap_write  = ribmgr_cdap_write,
        .cdap_create = ribmgr_cdap_create,
        .cdap_delete = ribmgr_cdap_delete,
        .cdap_start  = ribmgr_cdap_start,
        .cdap_stop   = ribmgr_cdap_stop
};

int ribmgr_add_flow(int fd)
{
        struct cdap * instance = NULL;
        struct mgmt_flow * flow;
        int iid = 0;

        flow = malloc(sizeof(*flow));
        if (flow == NULL)
                return -1;

        instance = cdap_create(&ribmgr_ops, fd);
        if (instance == NULL) {
                LOG_ERR("Failed to create CDAP instance");
                free(flow);
                return -1;
        }

        INIT_LIST_HEAD(&flow->next);
        flow->instance = instance;
        flow->fd = fd;

        pthread_rwlock_rdlock(&_ipcp->state_lock);
        pthread_rwlock_wrlock(&rib->flows_lock);
        if (list_empty(&rib->flows) &&
            (_ipcp->state == IPCP_INIT ||
             _ipcp->state == IPCP_DISCONNECTED)) {
                _ipcp->state = IPCP_PENDING_ENROLL;
                pthread_rwlock_unlock(&_ipcp->state_lock);

                pthread_mutex_lock(&rib->cdap_reqs_lock);
                iid = cdap_send_start(instance,
                                      ENROLLMENT);
                if (iid < 0) {
                        pthread_mutex_unlock(&rib->cdap_reqs_lock);
                        pthread_rwlock_unlock(&rib->flows_lock);
                        LOG_ERR("Failed to start enrollment.");
                        cdap_destroy(instance);
                        free(flow);
                        return -1;
                }

                if (cdap_request_add(instance, START, ENROLLMENT, iid)) {
                        pthread_mutex_unlock(&rib->cdap_reqs_lock);
                        pthread_rwlock_unlock(&rib->flows_lock);
                        LOG_ERR("Failed to add CDAP request to list.");
                        cdap_destroy(instance);
                        free(flow);
                        return -1;
                }
                pthread_mutex_unlock(&rib->cdap_reqs_lock);
        }
        pthread_rwlock_unlock(&_ipcp->state_lock);

        list_add(&flow->next, &rib->flows);
        pthread_rwlock_unlock(&rib->flows_lock);

        return 0;
}

int ribmgr_remove_flow(int fd)
{
        struct list_head * pos, * n = NULL;

        pthread_rwlock_wrlock(&rib->flows_lock);
        list_for_each_safe(pos, n, &rib->flows) {
                struct mgmt_flow * flow =
                        list_entry(pos, struct mgmt_flow, next);
                if (flow->fd == fd) {
                        if (cdap_destroy(flow->instance))
                                LOG_ERR("Failed to destroy CDAP instance.");
                        list_del(&flow->next);
                        free(flow);
                        return 0;
                }
        }
        pthread_rwlock_unlock(&rib->flows_lock);

        return -1;
}

int ribmgr_bootstrap(struct dif_config * conf)
{
        if (conf == NULL ||
            conf->type != IPCP_NORMAL) {
                LOG_ERR("Bad DIF configuration.");
                return -1;
        }

        rib->dtc.addr_size = conf->addr_size;
        rib->dtc.cep_id_size  = conf->cep_id_size;
        rib->dtc.pdu_length_size = conf->pdu_length_size;
        rib->dtc.seqno_size = conf->seqno_size;
        rib->dtc.ttl_size = conf->ttl_size;
        rib->dtc.chk_size = conf->chk_size;
        rib->dtc.min_pdu_size = conf->min_pdu_size;
        rib->dtc.max_pdu_size = conf->max_pdu_size;

        if (frct_init(&rib->dtc)) {
                LOG_ERR("Failed to initialize FRCT.");
                return -1;
        }

        LOG_DBG("Bootstrapped RIB Manager.");

        return 0;
}
