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
#include <ouroboros/time_utils.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/errno.h>

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include "addr_auth.h"
#include "ribmgr.h"
#include "dt_const.h"
#include "frct.h"
#include "ipcp.h"
#include "cdap_request.h"
#include "ro.h"

#include "static_info.pb-c.h"
typedef StaticInfoMsg static_info_msg_t;

#define SUBS_SIZE 25

#define ENROLLMENT     "enrollment"
#define STATIC_INFO    "static DIF information"
#define PATH_DELIMITER "/"

/* RIB objects */
struct rnode {
        char *            name;

        /*
         * NOTE: Naive implementation for now, could be replaced by
         * for instance taking a hash of the pathname and using that
         * as an index in a B-tree
         */

        /* If there are no children, this is a leaf */
        struct rnode *    child;
        struct rnode *    sibling;

        struct ro_props * props;
        uint8_t *         data;
        size_t            len;
};

struct mgmt_flow {
        struct cdap *    instance;
        int              fd;
        struct list_head next;
};

struct ro_sub {
        int                 sid;
        char *              name;
        struct ro_sub_ops * ops;
        struct list_head    next;
};

struct {
        struct rnode *     root;
        pthread_mutex_t    ro_lock;

        struct list_head   subs;
        struct bmp *       sids;
        pthread_mutex_t    subs_lock;

        struct dt_const    dtc;

        uint64_t           address;

        struct list_head   flows;
        pthread_rwlock_t   flows_lock;

        struct list_head   cdap_reqs;
        pthread_mutex_t    cdap_reqs_lock;

        struct addr_auth * addr_auth;
} rib;

/* Call while holding cdap_reqs_lock */
/* FIXME: better not to call blocking functions under any lock */
int cdap_result_wait(struct cdap * instance,
                     enum cdap_opcode code,
                     char * name,
                     int invoke_id)
{
        struct cdap_request * req;
        int ret;
        char * name_dup = strdup(name);
        if (name_dup == NULL)
                return -1;

        req = cdap_request_create(code, name_dup, invoke_id, instance);
        if (req == NULL) {
                free(name_dup);
                return -1;
        }

        list_add(&req->next, &rib.cdap_reqs);

        pthread_mutex_unlock(&rib.cdap_reqs_lock);

        ret = cdap_request_wait(req);

        pthread_mutex_lock(&rib.cdap_reqs_lock);

        if (ret == -1)  /* should only be on ipcp shutdown */
                LOG_DBG("Waiting CDAP request destroyed.");

        if (ret == -ETIMEDOUT)
                LOG_ERR("CDAP Request timed out.");

        if (ret)
                LOG_DBG("Unknown error code: %d.", ret);

        if (!ret)
                ret = req->result;

        list_del(&req->next);
        cdap_request_destroy(req);

        return ret;
}

int ribmgr_init()
{
        INIT_LIST_HEAD(&rib.flows);
        INIT_LIST_HEAD(&rib.cdap_reqs);
        INIT_LIST_HEAD(&rib.subs);

        rib.root = malloc(sizeof(*(rib.root)));
        if (rib.root == NULL)
                return -1;

        rib.root->name = "root";
        rib.root->child = NULL;
        rib.root->sibling = NULL;

        if (pthread_rwlock_init(&rib.flows_lock, NULL)) {
                LOG_ERR("Failed to initialize rwlock.");
                free(rib.root);
                return -1;
        }

        if (pthread_mutex_init(&rib.cdap_reqs_lock, NULL)) {
                LOG_ERR("Failed to initialize mutex.");
                pthread_rwlock_destroy(&rib.flows_lock);
                free(rib.root);
                return -1;
        }

        if (pthread_mutex_init(&rib.ro_lock, NULL)) {
                LOG_ERR("Failed to initialize mutex.");
                pthread_rwlock_destroy(&rib.flows_lock);
                pthread_mutex_destroy(&rib.cdap_reqs_lock);
                free(rib.root);
                return -1;
        }

        if (pthread_mutex_init(&rib.subs_lock, NULL)) {
                LOG_ERR("Failed to initialize mutex.");
                pthread_rwlock_destroy(&rib.flows_lock);
                pthread_mutex_destroy(&rib.cdap_reqs_lock);
                pthread_mutex_destroy(&rib.ro_lock);
                free(rib.root);
                return -1;
        }

        rib.sids = bmp_create(SUBS_SIZE, 0);
        if (rib.sids == NULL) {
                LOG_ERR("Failed to create bitmap.");
                pthread_rwlock_destroy(&rib.flows_lock);
                pthread_mutex_destroy(&rib.cdap_reqs_lock);
                pthread_mutex_destroy(&rib.ro_lock);
                pthread_mutex_destroy(&rib.subs_lock);
                free(rib.root);
                return -1;
        }

        return 0;
}

static void rtree_destroy(struct rnode * node)
{
        if (node != NULL) {
                rtree_destroy(node->child);
                rtree_destroy(node->sibling);
                free(node->name);
                if (node->data != NULL)
                        free(node->data);
                free(node);
        }
}

int ribmgr_fini()
{
        struct list_head * pos = NULL;
        struct list_head * n = NULL;

        pthread_mutex_lock(&rib.cdap_reqs_lock);
        list_for_each_safe(pos, n, &rib.cdap_reqs) {
                struct cdap_request * req =
                        list_entry(pos, struct cdap_request, next);
                free(req->name);
                list_del(&req->next);
                free(req);
        }
        pthread_mutex_unlock(&rib.cdap_reqs_lock);

        pthread_rwlock_wrlock(&rib.flows_lock);
        list_for_each_safe(pos, n, &rib.flows) {
                struct mgmt_flow * flow =
                        list_entry(pos, struct mgmt_flow, next);
                if (cdap_destroy(flow->instance))
                        LOG_ERR("Failed to destroy CDAP instance.");
                list_del(&flow->next);
                free(flow);
        }
        pthread_rwlock_unlock(&rib.flows_lock);

        if (rib.addr_auth != NULL)
                addr_auth_destroy(rib.addr_auth);

        pthread_mutex_lock(&rib.ro_lock);
        rtree_destroy(rib.root->child);
        free(rib.root);
        pthread_mutex_unlock(&rib.ro_lock);

        bmp_destroy(rib.sids);

        pthread_mutex_destroy(&rib.subs_lock);
        pthread_mutex_destroy(&rib.cdap_reqs_lock);
        pthread_mutex_destroy(&rib.ro_lock);
        pthread_rwlock_destroy(&rib.flows_lock);

        return 0;
}

static int ribmgr_cdap_reply(struct cdap * instance,
                             int           invoke_id,
                             int           result,
                             uint8_t *     data,
                             size_t        len)
{
        struct list_head * pos, * n = NULL;

        (void) data;
        (void) len;

        pthread_mutex_lock(&rib.cdap_reqs_lock);

        list_for_each_safe(pos, n, &rib.cdap_reqs) {
                struct cdap_request * req =
                        list_entry(pos, struct cdap_request, next);
                if (req->instance == instance &&
                    req->invoke_id == invoke_id &&
                    req->state == REQ_PENDING) {
                        if (result != 0)
                                LOG_ERR("CDAP command with code %d and name %s "
                                        "failed with error %d",
                                        req->code, req->name, result);
                        else
                                LOG_DBG("CDAP command with code %d and name %s "
                                        "executed succesfully",
                                        req->code, req->name);

                        pthread_mutex_unlock(&rib.cdap_reqs_lock);

                        /* FIXME: In case of a read, update values here */
                        cdap_request_respond(req, result);

                        pthread_mutex_lock(&rib.cdap_reqs_lock);
                }
        }
        pthread_mutex_unlock(&rib.cdap_reqs_lock);

        return 0;
}

static int ribmgr_cdap_write(struct cdap * instance,
                             int           invoke_id,
                             char *        name,
                             uint8_t *     data,
                             size_t        len,
                             uint32_t      flags)
{
        static_info_msg_t * msg;
        int ret = 0;

        (void) flags;

        pthread_rwlock_wrlock(&ipcpi.state_lock);
        if (ipcp_get_state() == IPCP_PENDING_ENROLL &&
            strcmp(name, STATIC_INFO) == 0) {
                LOG_DBG("Received static DIF information.");

                msg = static_info_msg__unpack(NULL, len, data);
                if (msg == NULL) {
                        ipcp_set_state(IPCP_INIT);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        cdap_send_reply(instance, invoke_id, -1, NULL, 0);
                        LOG_ERR("Failed to unpack static info message.");
                        return -1;
                }

                rib.dtc.addr_size = msg->addr_size;
                rib.dtc.cep_id_size = msg->cep_id_size;
                rib.dtc.pdu_length_size = msg->pdu_length_size;
                rib.dtc.seqno_size = msg->seqno_size;
                rib.dtc.has_ttl = msg->has_ttl;
                rib.dtc.has_chk = msg->has_chk;
                rib.dtc.min_pdu_size = msg->min_pdu_size;
                rib.dtc.max_pdu_size = msg->max_pdu_size;

                rib.addr_auth = addr_auth_create(msg->addr_auth_type);
                if (rib.addr_auth == NULL) {
                        ipcp_set_state(IPCP_INIT);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        cdap_send_reply(instance, invoke_id, -1, NULL, 0);
                        static_info_msg__free_unpacked(msg, NULL);
                        LOG_ERR("Failed to create address authority");
                        return -1;
                }

                rib.address = rib.addr_auth->address();
                LOG_DBG("IPCP has address %lu", rib.address);

                if (frct_init()) {
                        ipcp_set_state(IPCP_INIT);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        cdap_send_reply(instance, invoke_id, -1, NULL, 0);
                        static_info_msg__free_unpacked(msg, NULL);
                        LOG_ERR("Failed to init FRCT");
                        return -1;
                }

                static_info_msg__free_unpacked(msg, NULL);
        } else {
                ret = -1;
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        if (cdap_send_reply(instance, invoke_id, ret, NULL, 0)) {
                LOG_ERR("Failed to send reply to write request.");
                return -1;
        }

        return 0;
}

static int ribmgr_cdap_start(struct cdap * instance,
                             int           invoke_id,
                             char *        name)
{
        static_info_msg_t stat_info = STATIC_INFO_MSG__INIT;
        uint8_t * data = NULL;
        size_t len = 0;
        int iid = 0;

        pthread_rwlock_wrlock(&ipcpi.state_lock);
        if (ipcp_get_state() == IPCP_ENROLLED &&
            strcmp(name, ENROLLMENT) == 0) {
                LOG_DBG("New enrollment request.");

                if (cdap_send_reply(instance, invoke_id, 0, NULL, 0)) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        LOG_ERR("Failed to send reply to enrollment request.");
                        return -1;
                }

                stat_info.addr_size = rib.dtc.addr_size;
                stat_info.cep_id_size = rib.dtc.cep_id_size;
                stat_info.pdu_length_size = rib.dtc.pdu_length_size;
                stat_info.seqno_size = rib.dtc.seqno_size;
                stat_info.has_ttl = rib.dtc.has_ttl;
                stat_info.has_chk = rib.dtc.has_chk;
                stat_info.min_pdu_size  = rib.dtc.min_pdu_size;
                stat_info.max_pdu_size = rib.dtc.max_pdu_size;
                stat_info.addr_auth_type = rib.addr_auth->type;

                len = static_info_msg__get_packed_size(&stat_info);
                if (len == 0) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        LOG_ERR("Failed to get size of static information.");
                        return -1;
                }

                data = malloc(len);
                if (data == NULL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        LOG_ERR("Failed to allocate memory.");
                        return -1;
                }

                static_info_msg__pack(&stat_info, data);

                LOG_DBGF("Sending static info...");

                pthread_mutex_lock(&rib.cdap_reqs_lock);

                iid = cdap_send_request(instance, CDAP_WRITE,
                                        STATIC_INFO, data, len, 0);
                if (iid < 0) {
                        pthread_mutex_unlock(&rib.cdap_reqs_lock);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        free(data);
                        LOG_ERR("Failed to send static information.");
                        return -1;
                }

                if (cdap_result_wait(instance, CDAP_WRITE,
                                     STATIC_INFO, iid)) {
                        pthread_mutex_unlock(&rib.cdap_reqs_lock);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        free(data);
                        LOG_ERR("Remote did not receive static information.");
                        return -1;
                }
                pthread_mutex_unlock(&rib.cdap_reqs_lock);

                /* FIXME: Send neighbors here. */

                LOG_DBGF("Sending stop enrollment...");

                pthread_mutex_lock(&rib.cdap_reqs_lock);

                iid = cdap_send_request(instance, CDAP_STOP, ENROLLMENT,
                                        NULL, 0, 0);
                if (iid < 0) {
                        pthread_mutex_unlock(&rib.cdap_reqs_lock);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        free(data);
                        LOG_ERR("Failed to send stop of enrollment.");
                        return -1;
                }

                if (cdap_result_wait(instance, CDAP_STOP,
                                     ENROLLMENT, iid)) {
                        pthread_mutex_unlock(&rib.cdap_reqs_lock);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        free(data);
                        LOG_ERR("Remote failed to complete enrollment.");
                        return -1;
                }
                pthread_mutex_unlock(&rib.cdap_reqs_lock);

                free(data);
        } else {
                if (cdap_send_reply(instance, invoke_id, -1, NULL, 0)) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        LOG_ERR("Failed to send reply to start request.");
                        return -1;
                }
        }
        pthread_rwlock_unlock(&ipcpi.state_lock);

        return 0;
}

static int ribmgr_cdap_stop(struct cdap * instance,
                            int           invoke_id,
                            char *        name)
{
        int ret = 0;

        pthread_rwlock_wrlock(&ipcpi.state_lock);
        if (ipcp_get_state() == IPCP_PENDING_ENROLL &&
            strcmp(name, ENROLLMENT) == 0) {
                LOG_DBG("Stop enrollment received.");

                ipcp_set_state(IPCP_ENROLLED);
        } else
                ret = -1;

        if (cdap_send_reply(instance, invoke_id, ret, NULL, 0)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to send reply to stop request.");
                return -1;
        }
        pthread_rwlock_unlock(&ipcpi.state_lock);

        return 0;
}

static int ribmgr_cdap_request(struct cdap *    instance,
                               int              invoke_id,
                               enum cdap_opcode opcode,
                               char *           name,
                               uint8_t *        data,
                               size_t           len,
                               uint32_t         flags)
{
        switch (opcode) {
        case CDAP_WRITE:
                return ribmgr_cdap_write(instance,
                                         invoke_id,
                                         name, data,
                                         len, flags);
        case CDAP_START:
                return ribmgr_cdap_start(instance,
                                         invoke_id,
                                         name);
        case CDAP_STOP:
                return ribmgr_cdap_stop(instance,
                                        invoke_id,
                                        name);
        default:
                LOG_INFO("Unsupported CDAP opcode received.");
                return -1;
        }
}

static struct cdap_ops ribmgr_ops = {
        .cdap_reply   = ribmgr_cdap_reply,
        .cdap_request = ribmgr_cdap_request
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

        pthread_rwlock_wrlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&rib.flows_lock);
        if (list_empty(&rib.flows) && ipcp_get_state() == IPCP_INIT) {
                ipcp_set_state(IPCP_PENDING_ENROLL);

                pthread_mutex_lock(&rib.cdap_reqs_lock);
                iid = cdap_send_request(instance,
                                        CDAP_START,
                                        ENROLLMENT,
                                        NULL, 0, 0);
                if (iid < 0) {
                        pthread_mutex_unlock(&rib.cdap_reqs_lock);
                        pthread_rwlock_unlock(&rib.flows_lock);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        LOG_ERR("Failed to start enrollment.");
                        cdap_destroy(instance);
                        free(flow);
                        return -1;
                }

                if (cdap_result_wait(instance, CDAP_START,
                                     ENROLLMENT, iid)) {
                        pthread_mutex_unlock(&rib.cdap_reqs_lock);
                        pthread_rwlock_unlock(&rib.flows_lock);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        LOG_ERR("Failed to start enrollment.");
                        cdap_destroy(instance);
                        free(flow);
                        return -1;
                }
                pthread_mutex_unlock(&rib.cdap_reqs_lock);
        }

        list_add(&flow->next, &rib.flows);
        pthread_rwlock_unlock(&rib.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        return 0;
}

int ribmgr_remove_flow(int fd)
{
        struct list_head * pos, * n = NULL;

        pthread_rwlock_wrlock(&rib.flows_lock);
        list_for_each_safe(pos, n, &rib.flows) {
                struct mgmt_flow * flow =
                        list_entry(pos, struct mgmt_flow, next);
                if (flow->fd == fd) {
                        if (cdap_destroy(flow->instance))
                                LOG_ERR("Failed to destroy CDAP instance.");
                        list_del(&flow->next);
                        pthread_rwlock_unlock(&rib.flows_lock);
                        free(flow);
                        return 0;
                }
        }
        pthread_rwlock_unlock(&rib.flows_lock);

        return -1;
}

int ribmgr_bootstrap(struct dif_config * conf)
{
        if (conf == NULL ||
            conf->type != IPCP_NORMAL) {
                LOG_ERR("Bad DIF configuration.");
                return -1;
        }

        rib.dtc.addr_size = conf->addr_size;
        rib.dtc.cep_id_size  = conf->cep_id_size;
        rib.dtc.pdu_length_size = conf->pdu_length_size;
        rib.dtc.seqno_size = conf->seqno_size;
        rib.dtc.has_ttl = conf->has_ttl;
        rib.dtc.has_chk = conf->has_chk;
        rib.dtc.min_pdu_size = conf->min_pdu_size;
        rib.dtc.max_pdu_size = conf->max_pdu_size;

        rib.addr_auth = addr_auth_create(conf->addr_auth_type);
        if (rib.addr_auth == NULL) {
                LOG_ERR("Failed to create address authority.");
                return -1;
        }

        rib.address = rib.addr_auth->address();
        LOG_DBG("IPCP has address %lu", rib.address);

        if (frct_init()) {
                LOG_ERR("Failed to initialize FRCT.");
                addr_auth_destroy(rib.addr_auth);
                return -1;
        }

        LOG_DBG("Bootstrapped RIB Manager.");

        return 0;
}

struct dt_const * ribmgr_dt_const()
{
        return &(rib.dtc);
}

uint64_t ribmgr_address()
{
        return rib.address;
}

int ro_create(const char * name,
              uint8_t *    data,
              size_t       len)
{
        char * str, * str1, * saveptr, * token;
        struct rnode * node, * new, * prev;
        bool sibling;
        struct list_head * p = NULL;
        size_t len_s, len_n;
        uint8_t * ro_data;

        str = strdup(name);
        if (str == NULL)
                return -1;

        pthread_mutex_lock(&rib.ro_lock);
        node = rib.root;

        for (str1 = str; ; str1 = NULL) {
                token = strtok_r(str1, PATH_DELIMITER, &saveptr);
                if (token == NULL) {
                        pthread_mutex_unlock(&rib.ro_lock);
                        LOG_ERR("RO already exists.");
                        free(str);
                        return -1;
                }

                prev = node;
                node = node->child;
                sibling = false;

                /* Search horizontally */
                while (node != NULL) {
                        if (strcmp(node->name, token) == 0) {
                                break;
                        } else {
                                prev = node;
                                node = node->sibling;
                                sibling = true;
                        }
                }

                if (node == NULL)
                        break;
        }

        token = strtok_r(str1, PATH_DELIMITER, &saveptr);
        if (token != NULL) {
                pthread_mutex_unlock(&rib.ro_lock);
                LOG_ERR("Part of the pathname does not exist.");
                free(str);
                return -1;
        }

        free(str);

        new = malloc(sizeof(*new));
        if (new == NULL) {
                pthread_mutex_unlock(&rib.ro_lock);
                return -1;
        }

        new->name = strdup(token);
        if (new->name == NULL) {
                pthread_mutex_unlock(&rib.ro_lock);
                free(new);
                return -1;
        }

        if (sibling)
                prev->sibling = new;
        else
                prev->child = new;

        new->data = data;
        new->len = len;
        new->child = NULL;
        new->sibling = NULL;

        pthread_mutex_lock(&rib.subs_lock);

        list_for_each(p, &rib.subs) {
                struct ro_sub * e = list_entry(p, struct ro_sub, next);
                len_s = strlen(e->name);
                len_n = strlen(name);

                if (len_n < len_s)
                        continue;

                if (strncmp(name, e->name, len_s) == 0) {
                        if (e->ops->ro_created == NULL)
                                continue;

                        ro_data = malloc(len);
                        if (ro_data == NULL)
                                continue;

                        memcpy(ro_data, data, len);
                        e->ops->ro_created(name, ro_data, len);
                }
        }

        pthread_mutex_unlock(&rib.subs_lock);
        pthread_mutex_unlock(&rib.ro_lock);

        return 0;
}

int ro_delete(const char * name)
{
        char * str, * str1, * saveptr, * token;
        struct rnode * node, * prev;
        bool sibling = false;
        struct list_head * p = NULL;
        size_t len_s, len_n;

        str = strdup(name);
        if (str == NULL)
                return -1;

        pthread_mutex_lock(&rib.ro_lock);

        node = rib.root;
        prev = NULL;

        for (str1 = str; ; str1 = NULL) {
                token = strtok_r(str1, PATH_DELIMITER, &saveptr);
                if (token == NULL)
                        break;

                prev = node;
                node = node->child;
                sibling = false;

                while (node != NULL) {
                        if (strcmp(node->name, token) == 0) {
                                break;
                        } else {
                                prev = node;
                                node = node->sibling;
                                sibling = true;
                        }
                }

                if (node == NULL) {
                        pthread_mutex_unlock(&rib.ro_lock);
                        free(str);
                        return -1;
                }
        }

        if (node == rib.root) {
                LOG_ERR("Won't remove root.");
                free(str);
                return -1;
        }

        free(node->name);
        if (node->data != NULL)
                free(node->data);

        if (sibling)
                prev->sibling = node->sibling;
        else
                prev->child = node->sibling;

        free(node);

        pthread_mutex_lock(&rib.subs_lock);

        list_for_each(p, &rib.subs) {
                struct ro_sub * e = list_entry(p, struct ro_sub, next);
                len_s = strlen(e->name);
                len_n = strlen(name);

                if (len_n < len_s)
                        continue;

                if (strncmp(name, e->name, len_s) == 0) {
                        if (e->ops->ro_deleted == NULL)
                                continue;

                        e->ops->ro_deleted(name);
                }
        }

        pthread_mutex_unlock(&rib.subs_lock);
        pthread_mutex_unlock(&rib.ro_lock);

        free(str);
        return 0;
}

static struct rnode * find_rnode_by_name(const char * name)
{
        char * str, * str1, * saveptr, * token;
        struct rnode * node;

        str = strdup(name);
        if (str == NULL)
                return NULL;

        node = rib.root;

        for (str1 = str; ; str1 = NULL) {
                token = strtok_r(str1, PATH_DELIMITER, &saveptr);
                if (token == NULL)
                        break;

                node = node->child;

                while (node != NULL)
                        if (strcmp(node->name, token) == 0)
                                break;
                        else
                                node = node->sibling;

                if (node == NULL) {
                        free(str);
                        return NULL;
                }
        }

        free(str);
        return node;
}

ssize_t ro_read(const char * name,
                uint8_t **   data)
{
        struct rnode * node;
        ssize_t        len;

        pthread_mutex_lock(&rib.ro_lock);

        node = find_rnode_by_name(name);
        if (node == NULL) {
                pthread_mutex_unlock(&rib.ro_lock);
                return -1;
        }

        *data = malloc(node->len);
        if (*data == NULL) {
                pthread_mutex_unlock(&rib.ro_lock);
                return -1;
        }

        memcpy(*data, node->data, node->len);
        len = node->len;

        pthread_mutex_unlock(&rib.ro_lock);

        return len;
}

int ro_write(const char * name,
             uint8_t *    data,
             size_t       len)
{
        struct rnode * node;
        struct list_head * p = NULL;
        size_t len_s, len_n;
        uint8_t * ro_data;

        pthread_mutex_lock(&rib.ro_lock);

        node = find_rnode_by_name(name);
        if (node == NULL) {
                pthread_mutex_unlock(&rib.ro_lock);
                return -1;
        }

        free(node->data);

        node->data = data;
        node->len = len;

        pthread_mutex_lock(&rib.subs_lock);

        list_for_each(p, &rib.subs) {
                struct ro_sub * e =
                        list_entry(p, struct ro_sub, next);
                len_s = strlen(e->name);
                len_n = strlen(name);

                if (len_n < len_s)
                        continue;

                if (strncmp(name, e->name, len_s) == 0) {
                        if (e->ops->ro_updated == NULL)
                                continue;

                        ro_data = malloc(len);
                        if (ro_data == NULL)
                                continue;

                        memcpy(ro_data, data, len);
                        e->ops->ro_updated(name, ro_data, len);
                }
        }

        pthread_mutex_unlock(&rib.subs_lock);
        pthread_mutex_unlock(&rib.ro_lock);

        return 0;
}

int ro_props(const char *      name,
             struct ro_props * props)
{
        struct rnode * node;

        pthread_mutex_lock(&rib.ro_lock);

        node = find_rnode_by_name(name);
        if (node == NULL) {
                pthread_mutex_unlock(&rib.ro_lock);
                return -1;
        }

        if (node->props != NULL) {
                if (node->props->expiry != NULL)
                        free(node->props->expiry);
                free(node->props);
        }

        node->props = props;

        pthread_mutex_unlock(&rib.ro_lock);

        return 0;
}

int ro_sync(const char * name)
{
        (void) name;

        LOG_MISSING;
        /* FIXME: We need whatevercast sets first */

        return -1;
}

int ro_subscribe(const char *        name,
                 struct ro_sub_ops * ops)
{
        struct ro_sub * sub;

        if (name == NULL || ops == NULL)
                return -EINVAL;

        sub = malloc(sizeof(*sub));
        if (sub == NULL)
                return -ENOMEM;

        INIT_LIST_HEAD(&sub->next);

        sub->name = strdup(name);
        if (sub->name == NULL) {
                free(sub);
                return -1;
        }

        sub->ops = ops;

        pthread_mutex_lock(&rib.subs_lock);

        sub->sid = bmp_allocate(rib.sids);
        if (sub->sid < 0) {
                pthread_mutex_unlock(&rib.subs_lock);
                free(sub->name);
                free(sub);
                LOG_ERR("Failed to get sub id.");
        }

        list_add(&sub->next, &rib.subs);

        pthread_mutex_unlock(&rib.subs_lock);

        return 0;
}

int ro_unsubscribe(int sid)
{
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        pthread_mutex_lock(&rib.subs_lock);

        list_for_each_safe(pos, n, &(rib.subs)) {
                struct ro_sub * e = list_entry(pos, struct ro_sub, next);
                if (sid == e->sid) {
                        bmp_release(rib.sids, sid);
                        list_del(&e->next);
                        free(e->name);
                        free(e);
                        pthread_mutex_unlock(&rib.subs_lock);
                        return 0;
                }
        }

        pthread_mutex_unlock(&rib.subs_lock);

        LOG_ERR("No such subscription found.");

        return -1;
}
