/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager
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

#define OUROBOROS_PREFIX "irmd"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/sockets.h>
#include <ouroboros/irm.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/da.h>
#include <ouroboros/list.h>
#include <ouroboros/instance_name.h>
#include <ouroboros/utils.h>
#include <ouroboros/dif_config.h>
#include <ouroboros/shm_du_map.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/flow.h>
#include <ouroboros/qos.h>
#include <ouroboros/rw_lock.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>

/* FIXME: this smells like part of namespace management */
#define ALL_DIFS "*"

#ifndef IRMD_MAX_FLOWS
  #define IRMD_MAX_FLOWS 4096
#endif

#ifndef IRMD_THREADPOOL_SIZE
  #define IRMD_THREADPOOL_SIZE 3
#endif

struct ipcp_entry {
        struct list_head  next;
        instance_name_t * api;
        char *            dif_name;
};

/* currently supports only registering whatevercast groups of a single AP-I */
struct reg_name_entry {
        struct list_head next;

        /* generic whatevercast name */
        char *             name;

        /* FIXME: make a list resolve to AP-I instead */
        instance_name_t  * api;

        bool   accept;
        char * req_ap_name;
        char * req_ae_name;
        int    response;
        int    flow_arrived;

        pthread_cond_t  acc_signal;
        pthread_mutex_t acc_lock;
};

/* keeps track of port_id's between N and N - 1 */
struct port_map_entry {
        struct list_head next;

        int port_id;

        pid_t n_pid;
        pid_t n_1_pid;

        pthread_cond_t  res_signal;
        pthread_mutex_t res_lock;

        enum flow_state state;
};

struct irm {
        /* FIXME: list of ipcps could be merged with registered names */
        struct list_head ipcps;
        struct list_head reg_names;
        rw_lock_t  reg_lock;

        /* keep track of all flows in this processing system */
        struct bmp * port_ids;
        /* maps port_ids to pid pair */
        struct list_head port_map;
        rw_lock_t  flows_lock;

        struct shm_du_map * dum;
        pthread_t *         threadpool;
        int                 sockfd;
        rw_lock_t           state_lock;
} * instance = NULL;

static struct port_map_entry * port_map_entry_create()
{
        struct port_map_entry * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->n_pid   = 0;
        e->n_1_pid = 0;
        e->port_id = 0;
        e->state   = FLOW_NULL;

        if (pthread_cond_init(&e->res_signal, NULL)) {
                free(e);
                return NULL;
        }

        if (pthread_mutex_init(&e->res_lock, NULL)) {
                free(e);
                return NULL;
        }

        return e;
}

static struct port_map_entry * get_port_map_entry(int port_id)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->port_map) {
                struct port_map_entry * e =
                        list_entry(pos, struct port_map_entry, next);

                if (e->port_id == port_id)
                        return e;
        }

        return NULL;
}

static struct port_map_entry * get_port_map_entry_n(pid_t n_pid)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->port_map) {
                struct port_map_entry * e =
                        list_entry(pos, struct port_map_entry, next);

                if (e->n_pid == n_pid)
                        return e;
        }

        return NULL;
}

static struct ipcp_entry * ipcp_entry_create()
{
        struct ipcp_entry * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->api = NULL;
        e->dif_name = NULL;

        INIT_LIST_HEAD(&e->next);

        return e;
}

static void ipcp_entry_destroy(struct ipcp_entry * e)
{
        if (e == NULL)
                return;

        if (e->api != NULL)
                instance_name_destroy(e->api);

        if (e->dif_name != NULL)
                free(e->dif_name);

        free(e);
}

static struct ipcp_entry * get_ipcp_entry_by_name(instance_name_t * api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                if (instance_name_cmp(api, tmp->api) == 0)
                        return tmp;
        }

        return NULL;
}

static instance_name_t * get_ipcp_by_name(char * ap_name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);

                if (strcmp(e->api->name, ap_name) == 0)
                        return e->api;
        }

        return NULL;
}

static instance_name_t * get_ipcp_by_dif_name(char * dif_name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);

                if (e->dif_name == NULL)
                        continue;

                if (strcmp(dif_name, e->dif_name) == 0)
                        return e->api;
        }

        return NULL;
}

/* FIXME: this just returns the first IPCP for now */
static instance_name_t * get_ipcp_by_dst_name(char * dst_name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);
                return e->api;
        }

        return NULL;
}

static struct reg_name_entry * reg_name_entry_create()
{
        struct reg_name_entry * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->name         = NULL;
        e->api          = NULL;
        e->accept       = false;
        e->req_ap_name  = NULL;
        e->req_ae_name  = NULL;
        e->flow_arrived = -1;

        if (pthread_cond_init(&e->acc_signal, NULL)) {
                free(e);
                return NULL;
        }

        if (pthread_mutex_init(&e->acc_lock, NULL)) {
                free(e);
                return NULL;
        }

        INIT_LIST_HEAD(&e->next);

        return e;
}

static struct reg_name_entry * reg_name_entry_init(struct reg_name_entry * e,
                                                   char *                  name,
                                                   instance_name_t *       api)
{
        if (e == NULL || name == NULL || api == NULL)
                return NULL;

        e->name = name;
        e->api  = api;

        return e;
}

static int reg_name_entry_destroy(struct reg_name_entry * e)
{
        if (e == NULL)
                return 0;

        if (e->accept) {
                pthread_mutex_lock(&e->acc_lock);
                e->flow_arrived = -2;
                pthread_mutex_unlock(&e->acc_lock);
                pthread_cond_broadcast(&e->acc_signal);
                sched_yield();
        }

        free(e->name);
        instance_name_destroy(e->api);

        if (e->req_ap_name != NULL)
                free(e->req_ap_name);
        if (e->req_ae_name != NULL)
                free(e->req_ae_name);

        free(e);

        e = NULL;

        return 0;
}

static struct reg_name_entry * get_reg_name_entry_by_name(char * name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->reg_names) {
                struct reg_name_entry * e =
                        list_entry(pos, struct reg_name_entry, next);

                if (strcmp(name, e->name) == 0)
                        return e;
        }

        return NULL;
}

static struct reg_name_entry * get_reg_name_entry_by_id(pid_t pid)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->reg_names) {
                struct reg_name_entry * e =
                        list_entry(pos, struct reg_name_entry, next);

                if (e->api->id == pid)
                        return e;
        }

        return NULL;
}

/* FIXME: add only name when we have NSM solved */
static int reg_name_entry_add_name_instance(char * name, instance_name_t * api)
{
        struct reg_name_entry * e = get_reg_name_entry_by_name(name);
        if (e == NULL) {
                e = reg_name_entry_create();
                if (e == NULL)
                        return -1;

                if (reg_name_entry_init(e, name, api) == NULL) {
                        reg_name_entry_destroy(e);
                        return -1;
                }

                list_add(&e->next, &instance->reg_names);
                return 0;
        }

        /* already exists, we don't have NSM yet */
        return -1;
}

static int reg_name_entry_del_name(char * name)
{
        struct reg_name_entry * e = get_reg_name_entry_by_name(name);
        if (e == NULL)
                return 0;

        list_del(&e->next);

        reg_name_entry_destroy(e);

        return 0;
}

static pid_t create_ipcp(char *         ap_name,
                         enum ipcp_type ipcp_type)
{
        pid_t pid;
        struct ipcp_entry * tmp = NULL;

        rw_lock_rdlock(&instance->state_lock);

        pid = ipcp_create(ap_name, ipcp_type);
        if (pid == -1) {
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Failed to create IPCP.");
                return -1;
        }

        tmp = ipcp_entry_create();
        if (tmp == NULL) {
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        INIT_LIST_HEAD(&tmp->next);

        tmp->api = instance_name_create();
        if (tmp->api == NULL) {
                ipcp_entry_destroy(tmp);
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        if(instance_name_init_from(tmp->api, ap_name, pid) == NULL) {
                instance_name_destroy(tmp->api);
                ipcp_entry_destroy(tmp);
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        tmp->dif_name = NULL;

        rw_lock_wrlock(&instance->reg_lock);

        list_add(&tmp->next, &instance->ipcps);

        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        LOG_INFO("Created IPCP %s-%d.", ap_name, pid);

        return pid;
}

static int destroy_ipcp(instance_name_t * api)
{
        struct list_head * pos = NULL;
        struct list_head * n = NULL;
        pid_t pid = 0;

        if (api == NULL)
                return 0;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_wrlock(&instance->reg_lock);

        if (api->id == 0)
                api = get_ipcp_by_name(api->name);

        if (api == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("No such IPCP in the system.");
                return 0;
        }

        pid = api->id;
        if (ipcp_destroy(api->id))
                LOG_ERR("Could not destroy IPCP.");

        list_for_each_safe(pos, n, &(instance->ipcps)) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                if (instance_name_cmp(api, tmp->api) == 0)
                        list_del(&tmp->next);

                ipcp_entry_destroy(tmp);
        }

        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        LOG_INFO("Destroyed IPCP %d.", pid);

        return 0;
}

static int bootstrap_ipcp(instance_name_t *  api,
                          dif_config_msg_t * conf)
{
        struct ipcp_entry * entry = NULL;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_wrlock(&instance->reg_lock);

        if (api->id == 0)
                api = get_ipcp_by_name(api->name);

        if (api == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("No such IPCP in the system.");
                return -1;
        }

        entry = get_ipcp_entry_by_name(api);
        if (entry == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("No such IPCP.");
                return -1;
        }

        entry->dif_name = strdup(conf->dif_name);
        if (entry->dif_name == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Failed to strdup.");
                return -1;
        }

        if (ipcp_bootstrap(entry->api->id, conf)) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Could not bootstrap IPCP.");
                free(entry->dif_name);
                entry->dif_name = NULL;
                return -1;
        }

        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        LOG_INFO("Bootstrapped IPCP %s-%d in DIF %s.",
                 api->name, api->id, conf->dif_name);

        return 0;
}

static int enroll_ipcp(instance_name_t  * api,
                       char *             dif_name)
{
        char *  member = NULL;
        char ** n_1_difs = NULL;
        ssize_t n_1_difs_size = 0;
        struct ipcp_entry * entry = NULL;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->reg_lock);

        entry = get_ipcp_entry_by_name(api);
        if (entry == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("No such IPCP.");
                return -1;
        }

        entry->dif_name = strdup(dif_name);
        if (entry->dif_name == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Failed to strdup.");
                return -1;
        }

        member = da_resolve_daf(dif_name);
        if (member == NULL) {
                free(entry->dif_name);
                entry->dif_name = NULL;
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        n_1_difs_size = da_resolve_dap(member, n_1_difs);
        if (n_1_difs_size < 1) {
                free(entry->dif_name);
                entry->dif_name = NULL;
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Could not find N-1 DIFs.");
                return -1;
        }

        if (ipcp_enroll(api->id, member, n_1_difs[0])) {
                free(entry->dif_name);
                entry->dif_name = NULL;
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Could not enroll IPCP.");
                return -1;
        }

        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        LOG_INFO("Enrolled IPCP %s-%d in DIF %s.",
                 api->name, api->id, dif_name);

        return 0;
}

static int reg_ipcp(instance_name_t * api,
                    char **           difs,
                    size_t            difs_size)
{
        rw_lock_rdlock(&instance->state_lock);
        rw_lock_wrlock(&instance->reg_lock);

        if (ipcp_reg(api->id, difs, difs_size)) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Could not register IPCP to N-1 DIF(s).");
                return -1;
        }

        rw_lock_wrlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        return 0;
}

static int unreg_ipcp(instance_name_t  * api,
                      char **            difs,
                      size_t             difs_size)
{
        rw_lock_rdlock(&instance->state_lock);
        rw_lock_wrlock(&instance->reg_lock);
        if (ipcp_unreg(api->id, difs, difs_size)) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Could not unregister IPCP from N-1 DIF(s).");
                return -1;
        }
        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        return 0;
}

static int ap_reg(char *  ap_name,
                  pid_t   ap_id,
                  char ** difs,
                  size_t  len)
{
        int i;
        int ret = 0;
        struct list_head * pos = NULL;
        struct reg_name_entry * rne = NULL;

        instance_name_t * api   = NULL;
        instance_name_t * ipcpi = NULL;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_wrlock(&instance->reg_lock);

        if (instance->ipcps.next == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        api = instance_name_create();
        if (api == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        if (instance_name_init_from(api, ap_name, ap_id) == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                instance_name_destroy(api);
                return -1;
        }

        /* check if this ap_name is already registered */

        rne = get_reg_name_entry_by_name(ap_name);
        if (rne != NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                instance_name_destroy(api);
                return -1; /* can only register one instance for now */
        }

        /*
         * for now, the whatevercast name is the same as the ap_name and
         * contains a single instance only
         */

        if (strcmp(difs[0], ALL_DIFS) == 0) {
                list_for_each(pos, &instance->ipcps) {
                        struct ipcp_entry * e =
                                list_entry(pos, struct ipcp_entry, next);

                        if (ipcp_name_reg(e->api->id, ap_name)) {
                                LOG_ERR("Could not register %s in DIF %s.",
                                        api->name, e->dif_name);
                        } else {
                                ++ret;
                        }
                }
        } else {
                for (i = 0; i < len; ++i) {
                        ipcpi = get_ipcp_by_dif_name(difs[i]);
                        if (ipcpi == NULL) {
                                LOG_ERR("%s: No such DIF.", difs[i]);
                                continue;
                        }

                        if (ipcp_name_reg(ipcpi->id, api->name)) {
                                LOG_ERR("Could not register %s in DIF %s.",
                                        api->name, difs[i]);
                        } else {
                                ++ret;
                        }
                }
        }

        if (ret ==  0) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                instance_name_destroy(api);
                return -1;
        }
        /* for now, we register single instances */
        ret = reg_name_entry_add_name_instance(strdup(ap_name),
                                               api);

        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        return ret;
}

static int ap_unreg(char *  ap_name,
                    pid_t   ap_id,
                    char ** difs,
                    size_t  len)
{
        int i;
        int ret = 0;
        struct reg_name_entry * rne = NULL;
        struct list_head      * pos = NULL;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_wrlock(&instance->reg_lock);

        /* check if ap_name is registered */
        rne = get_reg_name_entry_by_id(ap_id);
        if (rne == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                return 0; /* no such id */
        }

        if (strcmp(ap_name, rne->api->name)) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                return 0;
        }

        if (instance->ipcps.next == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("No IPCPs in this system.");
                return 0;
        }

        if (strcmp(difs[0], ALL_DIFS) == 0) {
                  list_for_each(pos, &instance->ipcps) {
                        struct ipcp_entry * e =
                                list_entry(pos, struct ipcp_entry, next);

                        if (ipcp_name_unreg(e->api->id, rne->name)) {
                                LOG_ERR("Could not unregister %s in DIF %s.",
                                        rne->name, e->dif_name);
                                --ret;
                        }
                }
        } else {
                for (i = 0; i < len; ++i) {
                        if (ipcp_name_unreg(ap_id, rne->name)) {
                                LOG_ERR("Could not unregister %s in DIF %s.",
                                        rne->name, difs[i]);
                                --ret;
                        }
                }
        }

        /* FIXME: check if name is not registered in any DIF before removing */
        reg_name_entry_del_name(rne->name);

        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        return ret;
}

static struct port_map_entry * flow_accept(pid_t    pid,
                                           char **  ap_name,
                                           char **  ae_name)
{
        struct port_map_entry * pme;
        struct reg_name_entry * rne = NULL;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->reg_lock);

        rne = get_reg_name_entry_by_id(pid);
        if (rne == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_DBGF("Unregistered AP calling accept().");
                return NULL;
        }
        if (rne->accept) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_DBGF("This AP still has a pending accept().");
                return NULL;
        }

        rne->accept       = true;
        rne->flow_arrived = -1;

        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        pthread_mutex_lock(&rne->acc_lock);
        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void*) &rne->acc_lock);

        while (rne->flow_arrived == -1)
                pthread_cond_wait(&rne->acc_signal, &rne->acc_lock);

        pthread_mutex_unlock(&rne->acc_lock);
        pthread_cleanup_pop(0);

        pthread_mutex_lock(&rne->acc_lock);

        /* ap with pending accept being unregistered */
        if (rne->flow_arrived == -2 ) {
                pthread_mutex_unlock(&rne->acc_lock);
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                return NULL;
        }

        pthread_mutex_unlock(&rne->acc_lock);

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->flows_lock);

        pme = get_port_map_entry_n(pid);
        if (pme == NULL) {
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("Port_id was not created yet.");
                return NULL;
        }

        *ap_name = rne->req_ap_name;
        if (ae_name != NULL)
                *ae_name = rne->req_ae_name;

        rw_lock_unlock(&instance->flows_lock);
        rw_lock_unlock(&instance->state_lock);

        return pme;
}

static int flow_alloc_resp(pid_t n_pid,
                           int   port_id,
                           int   response)
{
        struct port_map_entry * pme = NULL;
        struct reg_name_entry * rne = NULL;
        int ret = -1;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->reg_lock);

        rne = get_reg_name_entry_by_id(n_pid);
        if (rne == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        /* FIXME: check all instances associated with the name */
        if (!rne->accept) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_ERR("No process listening for this name.");
                return -1;
        }

        /*
         * consider the flow as handled
         * once we can handle a list of AP-I's, remove it from the list
         */

        pthread_mutex_lock(&rne->acc_lock);

        rne->accept       = false;
        rne->flow_arrived = -1;

        pthread_mutex_unlock(&rne->acc_lock);

        rw_lock_unlock(&instance->reg_lock);

        if (!response) {
                rw_lock_wrlock(&instance->flows_lock);

                pme = get_port_map_entry(port_id);
                if (pme == NULL) {
                        rw_lock_unlock(&instance->flows_lock);
                        rw_lock_unlock(&instance->state_lock);
                        return -1;
                }

                pme->state = FLOW_ALLOCATED;
                ret = ipcp_flow_alloc_resp(pme->n_1_pid,
                                           port_id,
                                           pme->n_pid,
                                           response);

                rw_lock_unlock(&instance->flows_lock);
        }

        rw_lock_unlock(&instance->state_lock);

        return ret;
}

static struct port_map_entry * flow_alloc(pid_t  pid,
                                          char * dst_name,
                                          char * src_ap_name,
                                          char * src_ae_name,
                                          struct qos_spec * qos)
{
        struct port_map_entry * pme;
        instance_name_t * ipcp;

        /* FIXME: Map qos_spec to qos_cube */

        pme = port_map_entry_create();
        if (pme == NULL) {
                LOG_ERR("Failed malloc of port_map_entry.");
                return NULL;
        }

        pme->n_pid   = pid;
        pme->state   = FLOW_PENDING;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->reg_lock);

        ipcp = get_ipcp_by_dst_name(dst_name);

        if (ipcp == NULL) {
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_DBG("unknown ipcp");
                return NULL;
        }

        rw_lock_unlock(&instance->reg_lock);
        rw_lock_wrlock(&instance->flows_lock);

        pme->port_id = bmp_allocate(instance->port_ids);
        pme->n_1_pid = get_ipcp_by_dst_name(dst_name)->id;

        list_add(&pme->next, &instance->port_map);

        rw_lock_unlock(&instance->flows_lock);
        rw_lock_unlock(&instance->state_lock);

        if (ipcp_flow_alloc(ipcp->id,
                            pme->port_id,
                            pme->n_pid,
                            dst_name,
                            src_ap_name,
                            src_ae_name,
                            QOS_CUBE_BE) < 0) {
                rw_lock_rdlock(&instance->state_lock);
                rw_lock_wrlock(&instance->flows_lock);
                list_del(&pme->next);
                bmp_release(instance->port_ids, pme->port_id);
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_rdlock(&instance->state_lock);
                free(pme);
                return NULL;
        }

        return pme;
}

static int flow_alloc_res(int port_id)
{
        struct port_map_entry * e;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->flows_lock);

        e = get_port_map_entry(port_id);
        if (e == NULL) {
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        if (e->state == FLOW_ALLOCATED) {
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_unlock(&instance->state_lock);
                return 0;
        }

        rw_lock_unlock(&instance->flows_lock);
        rw_lock_unlock(&instance->state_lock);

        while (true) {
                pthread_mutex_lock(&e->res_lock);
                pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                                     (void*) &e->res_lock);

                pthread_cond_wait(&e->res_signal, &e->res_lock);

                pthread_mutex_unlock(&e->res_lock);
                pthread_cleanup_pop(0);

                rw_lock_rdlock(&instance->state_lock);
                rw_lock_wrlock(&instance->flows_lock);

                e = get_port_map_entry(port_id);
                if (e == NULL) {
                        rw_lock_unlock(&instance->flows_lock);
                        rw_lock_unlock(&instance->state_lock);
                        return -1;
                }
                if (e->state == FLOW_ALLOCATED) {
                        rw_lock_unlock(&instance->flows_lock);
                        rw_lock_unlock(&instance->state_lock);
                        LOG_DBGF("Returning 0.");
                        return 0;
                }
                if (e->state == FLOW_NULL) {
                        list_del(&e->next);
                        rw_lock_unlock(&instance->flows_lock);
                        rw_lock_unlock(&instance->state_lock);
                        free(e);
                        return -1;

                }
                /* still pending, spurious wake */
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_unlock(&instance->state_lock);
        }

        return 0;
}

static int flow_dealloc(int port_id)
{
        pid_t n_1_pid;
        int   ret = 0;

        struct port_map_entry * e = NULL;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_wrlock(&instance->flows_lock);

        e = get_port_map_entry(port_id);
        if (e == NULL) {
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_unlock(&instance->state_lock);
                return 0;
        }

        n_1_pid = e->n_1_pid;

        list_del(&e->next);

        bmp_release(instance->port_ids, port_id);

        ret = ipcp_flow_dealloc(n_1_pid, port_id);

        rw_lock_unlock(&instance->flows_lock);
        rw_lock_unlock(&instance->state_lock);

        free(e);

        return ret;
}

static struct port_map_entry * flow_req_arr(pid_t  pid,
                                            char * dst_name,
                                            char * ap_name,
                                            char * ae_name)
{
        struct reg_name_entry * rne;
        struct port_map_entry * pme;

        pme = malloc(sizeof(*pme));
        if (pme == NULL) {
                LOG_ERR("Failed malloc of port_map_entry.");
                return NULL;
        }

        pme->state   = FLOW_PENDING;
        pme->n_1_pid = pid;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->reg_lock);
        rw_lock_wrlock(&instance->flows_lock);

        pme->port_id = bmp_allocate(instance->port_ids);

        rne = get_reg_name_entry_by_name(dst_name);
        if (rne == NULL) {
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_unlock(&instance->reg_lock);
                rw_lock_unlock(&instance->state_lock);
                LOG_DBGF("Destination name %s unknown.", dst_name);
                free(pme);
                return NULL;
        }

        pme->n_pid = rne->api->id;

        rne->req_ap_name = strdup(ap_name);
        rne->req_ae_name = strdup(ae_name);

        list_add(&pme->next, &instance->port_map);

        pthread_mutex_lock(&rne->acc_lock);

        rne->flow_arrived = 0;

        pthread_mutex_unlock(&rne->acc_lock);

        if (pthread_cond_signal(&rne->acc_signal))
                LOG_ERR("Failed to send signal.");

        rw_lock_unlock(&instance->flows_lock);
        rw_lock_unlock(&instance->reg_lock);
        rw_lock_unlock(&instance->state_lock);

        return pme;
}

static int flow_alloc_reply(int port_id,
                            int response)
{
        struct port_map_entry * e;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->flows_lock);

        e = get_port_map_entry(port_id);
        if (e == NULL) {
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_unlock(&instance->state_lock);
                return -1;
        }

        pthread_mutex_lock(&e->res_lock);

        if (!response)
                e->state = FLOW_ALLOCATED;

        else
                e->state = FLOW_NULL;

        if (pthread_cond_signal(&e->res_signal))
                LOG_ERR("Failed to send signal.");

        pthread_mutex_unlock(&e->res_lock);

        rw_lock_unlock(&instance->flows_lock);
        rw_lock_unlock(&instance->state_lock);

        return 0;
}

static int flow_dealloc_ipcp(int port_id)
{
        struct port_map_entry * e = NULL;

        rw_lock_rdlock(&instance->state_lock);
        rw_lock_rdlock(&instance->flows_lock);

        e = get_port_map_entry(port_id);
        if (e == NULL) {
                rw_lock_unlock(&instance->flows_lock);
                rw_lock_unlock(&instance->state_lock);
                return 0;
        }

        list_del(&e->next);

        rw_lock_unlock(&instance->flows_lock);
        rw_lock_unlock(&instance->state_lock);

        free(e);

        return 0;
}

static void irm_destroy(struct irm *  irm)
{
        struct list_head * h;
        struct list_head * t;

        if (irm == NULL)
                return;

        rw_lock_wrlock(&irm->state_lock);

        if (irm->threadpool != NULL)
                free(irm->threadpool);

        if (irm->port_ids != NULL)
                bmp_destroy(irm->port_ids);
        /* clear the lists */
        list_for_each_safe(h, t, &irm->ipcps) {
                struct ipcp_entry * e = list_entry(h, struct ipcp_entry, next);
                destroy_ipcp(e->api);
        }

        list_for_each_safe(h, t, &irm->reg_names) {
                struct reg_name_entry * e = list_entry(h,
                                                       struct reg_name_entry,
                                                       next);
                list_del(&e->next);
                reg_name_entry_destroy(e);
        }

        list_for_each_safe(h, t, &irm->port_map) {
                struct port_map_entry * e = list_entry(h,
                                                       struct port_map_entry,
                                                       next);
                list_del(&e->next);
                free(e);
        }

        if (irm->dum != NULL)
                shm_du_map_destroy(irm->dum);

        close(irm->sockfd);

        rw_lock_unlock(&irm->state_lock);

        free(irm);

}

void irmd_sig_handler(int sig, siginfo_t * info, void * c)
{
        int i;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                rw_lock_wrlock(&instance->state_lock);

                if (instance->threadpool != NULL) {
                        for (i = 0; i < IRMD_THREADPOOL_SIZE; i++)
                                pthread_cancel(instance->threadpool[i]);

                }

                rw_lock_unlock(&instance->state_lock);

        case SIGPIPE:
                LOG_DBG("Ignoring SIGPIPE.");
        default:
                return;
        }
}

void * mainloop()
{
        uint8_t buf[IRM_MSG_BUF_SIZE];

        while (true) {
                int cli_sockfd;
                irm_msg_t * msg;
                ssize_t count;
                instance_name_t api;
                buffer_t buffer;
                irm_msg_t ret_msg = IRM_MSG__INIT;
                struct port_map_entry * e = NULL;

                ret_msg.code = IRM_MSG_CODE__IRM_REPLY;

                cli_sockfd = accept(instance->sockfd, 0, 0);
                if (cli_sockfd < 0) {
                        LOG_ERR("Cannot accept new connection.");
                        continue;
                }

                count = read(cli_sockfd, buf, IRM_MSG_BUF_SIZE);
                if (count <= 0) {
                        LOG_ERR("Failed to read from socket.");
                        close(cli_sockfd);
                        continue;
                }

                msg = irm_msg__unpack(NULL, count, buf);
                if (msg == NULL) {
                        close(cli_sockfd);
                        continue;
                }

                api.name = msg->ap_name;
                if (msg->has_api_id == true)
                        api.id = msg->api_id;

                switch (msg->code) {
                case IRM_MSG_CODE__IRM_CREATE_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = create_ipcp(msg->ap_name,
                                                     msg->ipcp_type);
                        break;
                case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = destroy_ipcp(&api);
                        break;
                case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = bootstrap_ipcp(&api, msg->conf);
                        break;
                case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = enroll_ipcp(&api,
                                                     msg->dif_name[0]);
                        break;
                case IRM_MSG_CODE__IRM_REG_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = reg_ipcp(&api,
                                                  msg->dif_name,
                                                  msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_UNREG_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = unreg_ipcp(&api,
                                                    msg->dif_name,
                                                    msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_AP_REG:
                        ret_msg.has_result = true;
                        ret_msg.result = ap_reg(msg->ap_name,
                                                msg->pid,
                                                msg->dif_name,
                                                msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_AP_UNREG:
                        ret_msg.has_result = true;
                        ret_msg.result = ap_unreg(msg->ap_name,
                                                  msg->pid,
                                                  msg->dif_name,
                                                  msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ACCEPT:
                        e = flow_accept(msg->pid,
                                        &ret_msg.ap_name,
                                        &ret_msg.ae_name);

                        if (e == NULL)
                                break;

                        ret_msg.has_port_id = true;
                        ret_msg.port_id     = e->port_id;
                        ret_msg.has_pid     = true;
                        ret_msg.pid         = e->n_1_pid;
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC_RESP:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc_resp(msg->pid,
                                                         msg->port_id,
                                                         msg->response);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC:
                        e = flow_alloc(msg->pid,
                                       msg->dst_name,
                                       msg->ap_name,
                                       msg->ae_name,
                                       NULL);
                        if (e == NULL)
                                break;

                        ret_msg.has_port_id = true;
                        ret_msg.port_id     = e->port_id;
                        ret_msg.has_pid     = true;
                        ret_msg.pid         = e->n_1_pid;
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC_RES:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc_res(msg->port_id);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_DEALLOC:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_dealloc(msg->port_id);
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_REQ_ARR:
                        e = flow_req_arr(msg->pid,
                                         msg->dst_name,
                                         msg->ap_name,
                                         msg->ae_name);
                        if (e == NULL)
                                break;

                        ret_msg.has_port_id = true;
                        ret_msg.port_id     = e->port_id;
                        ret_msg.has_pid     = true;
                        ret_msg.pid         = e->n_pid;
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc_reply(msg->port_id,
                                                          msg->response);
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_DEALLOC:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_dealloc_ipcp(msg->port_id);
                        break;
                default:
                        LOG_ERR("Don't know that message code.");
                        break;
                }

                irm_msg__free_unpacked(msg, NULL);

                buffer.size = irm_msg__get_packed_size(&ret_msg);
                if (buffer.size == 0) {
                        LOG_ERR("Failed to send reply message.");
                        close(cli_sockfd);
                        continue;
                }

                buffer.data = malloc(buffer.size);
                if (buffer.data == NULL) {
                        close(cli_sockfd);
                        continue;
                }

                irm_msg__pack(&ret_msg, buffer.data);

                if (write(cli_sockfd, buffer.data, buffer.size) == -1) {
                        free(buffer.data);
                        close(cli_sockfd);
                        continue;
                }

                free(buffer.data);
                close(cli_sockfd);
        }
}

static struct irm * irm_create()
{
        struct irm * i = malloc(sizeof(*i));
        if (i == NULL)
                return NULL;

        if (access("/dev/shm/" SHM_DU_MAP_FILENAME, F_OK) != -1)
                unlink("/dev/shm/" SHM_DU_MAP_FILENAME);

        i->threadpool = malloc(sizeof(pthread_t) * IRMD_THREADPOOL_SIZE);
        if (i->threadpool == NULL) {
                irm_destroy(i);
                return NULL;
        }

        if ((i->dum = shm_du_map_create()) == NULL) {
                irm_destroy(i);
                return NULL;
        }

        INIT_LIST_HEAD(&i->ipcps);
        INIT_LIST_HEAD(&i->reg_names);
        INIT_LIST_HEAD(&i->port_map);

        i->port_ids = bmp_create(IRMD_MAX_FLOWS, 0);
        if (i->port_ids == NULL) {
                irm_destroy(i);
                return NULL;
        }

        i->sockfd = server_socket_open(IRM_SOCK_PATH);
        if (i->sockfd < 0) {
                irm_destroy(i);
                return NULL;
        }

        if (rw_lock_init(&i->state_lock)) {
                irm_destroy(i);
                return NULL;
        }

        if (rw_lock_init(&i->reg_lock)) {
                irm_destroy(i);
                return NULL;
        }

        if (rw_lock_init(&i->flows_lock)) {
                irm_destroy(i);
                return NULL;
        }

        return i;
}

int main()
{
        struct sigaction sig_act;

        int t = 0;

        /* init sig_act */
        memset(&sig_act, 0, sizeof sig_act);

        /* install signal traps */
        sig_act.sa_sigaction = &irmd_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        if (sigaction(SIGINT,  &sig_act, NULL) < 0)
                exit(1);
        if (sigaction(SIGTERM, &sig_act, NULL) < 0)
                exit(1);
        if (sigaction(SIGHUP,  &sig_act, NULL) < 0)
                exit(1);
        if (sigaction(SIGPIPE, &sig_act, NULL) < 0)
                exit(1);

        instance = irm_create();
        if (instance == NULL)
                return 1;

        /*
         * FIXME: we need a main loop that delegates messages to subthreads in a
         * way that avoids all possible deadlocks for local apps
         */

        for (t = 0; t < IRMD_THREADPOOL_SIZE; ++t)
                pthread_create(&instance->threadpool[t], NULL, mainloop, NULL);

        /* wait for (all of them) to return */
        for (t = 0; t < IRMD_THREADPOOL_SIZE; ++t)
                pthread_join(instance->threadpool[t], NULL);

        irm_destroy(instance);

        return 0;
}
