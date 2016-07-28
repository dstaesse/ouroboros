/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/sockets.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/nsm.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/irm_config.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/shm_du_map.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/flow.h>
#include <ouroboros/qos.h>
#include <ouroboros/time_utils.h>

#include "utils.h"
#include "registry.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/wait.h>

#define IRMD_CLEANUP_TIMER ((IRMD_FLOW_TIMEOUT / 20) * MILLION) /* ns */

struct ipcp_entry {
        struct list_head  next;
        char *            name;
        pid_t             api;
        enum ipcp_type    type;
        char *            dif_name;
};

enum irm_state {
        IRMD_NULL = 0,
        IRMD_RUNNING,
        IRMD_SHUTDOWN
};

struct spawned_api {
        struct list_head next;
        pid_t            api;
};

/* keeps track of port_id's between N and N - 1 */
struct irm_flow {
        struct list_head next;

        int              port_id;

        pid_t            n_api;
        pid_t            n_1_api;

        struct timespec  t0;

        enum flow_state  state;
        pthread_cond_t   state_cond;
        pthread_mutex_t  state_lock;
};

struct irm {
        /* FIXME: list of ipcps could be merged into the registry */
        struct list_head    ipcps;

        struct list_head    registry;
        pthread_rwlock_t    reg_lock;

        struct list_head    spawned_apis;

        /* keep track of all flows in this processing system */
        struct bmp *        port_ids;
        /* maps port_ids to api pair */
        struct list_head    irm_flows;
        pthread_rwlock_t    flows_lock;

        struct lockfile *   lf;
        struct shm_du_map * dum;
        pthread_t *         threadpool;
        int                 sockfd;

        enum irm_state      state;
        pthread_rwlock_t    state_lock;

        pthread_t           cleanup_flows;
        pthread_t           shm_sanitize;
} * irmd = NULL;

static struct irm_flow * irm_flow_create()
{
        struct irm_flow * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->n_api   = -1;
        e->n_1_api = -1;
        e->port_id = -1;
        e->state   = FLOW_NULL;

        if (pthread_cond_init(&e->state_cond, NULL)) {
                free(e);
                return NULL;
        }

        if (pthread_mutex_init(&e->state_lock, NULL)) {
                free(e);
                return NULL;
        }

        e->t0.tv_sec  = 0;
        e->t0.tv_nsec = 0;

        return e;
}

static void irm_flow_destroy(struct irm_flow * e)
{
        pthread_mutex_lock(&e->state_lock);

        if (e->state == FLOW_PENDING)
                e->state = FLOW_DESTROY;

        pthread_cond_signal(&e->state_cond);
        pthread_mutex_unlock(&e->state_lock);

        pthread_cleanup_push((void(*)(void *)) pthread_mutex_unlock,
                             (void *) &e->state_lock);

        while (e->state != FLOW_NULL)
                pthread_cond_wait(&e->state_cond, &e->state_lock);

        pthread_cleanup_pop(true);

        pthread_cond_destroy(&e->state_cond);
        pthread_mutex_destroy(&e->state_lock);

        free(e);
}

static struct irm_flow * get_irm_flow(int port_id)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &irmd->irm_flows) {
                struct irm_flow * e = list_entry(pos, struct irm_flow, next);

                if (e->port_id == port_id)
                        return e;
        }

        return NULL;
}

static struct irm_flow * get_irm_flow_n(pid_t n_api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &irmd->irm_flows) {
                struct irm_flow * e = list_entry(pos, struct irm_flow, next);

                if (e->n_api == n_api)
                        return e;
        }

        return NULL;
}

static struct ipcp_entry * ipcp_entry_create()
{
        struct ipcp_entry * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->name = NULL;
        e->dif_name = NULL;

        INIT_LIST_HEAD(&e->next);

        return e;
}

static void ipcp_entry_destroy(struct ipcp_entry * e)
{
        if (e == NULL)
                return;

        if (e->name != NULL)
                free(e->name);

        if (e->dif_name != NULL)
                free(e->dif_name);

        free(e);
}

static struct ipcp_entry * get_ipcp_entry_by_api(pid_t api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);
                if (api == tmp->api)
                        return tmp;
        }

        return NULL;
}


/* FIXME: Check if the name exists anywhere in a DIF. */
static pid_t get_ipcp_by_dst_name(char * dst_name)
{
        struct list_head * pos = NULL;
        char * dif_name =
                registry_get_dif_for_dst(&irmd->registry, dst_name);
        if (dif_name == NULL) {
                list_for_each(pos, &irmd->ipcps) {
                        struct ipcp_entry * e =
                                list_entry(pos, struct ipcp_entry, next);
                        if (e->type == IPCP_NORMAL) {
                                dif_name = e->dif_name;
                                break;
                        }
                }

                list_for_each(pos, &irmd->ipcps) {
                        struct ipcp_entry * e =
                                list_entry(pos, struct ipcp_entry, next);
                        if (e->type == IPCP_SHIM_ETH_LLC) {
                                dif_name = e->dif_name;
                                break;
                        }
                }


                list_for_each(pos, &irmd->ipcps) {
                        struct ipcp_entry * e =
                                list_entry(pos, struct ipcp_entry, next);
                        if (e->type == IPCP_SHIM_UDP) {
                                dif_name = e->dif_name;
                                break;
                        }
                }
        }

        if (dif_name == NULL)
                return -1;

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);
                if (strcmp(e->dif_name, dif_name) == 0)
                        return e->api;
        }

        return -1;
}

static pid_t create_ipcp(char *         name,
                         enum ipcp_type ipcp_type)
{
        struct spawned_api * api;
        struct ipcp_entry * tmp = NULL;

        struct list_head * pos;

        api = malloc(sizeof(*api));
        if (api == NULL)
                return -ENOMEM;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        api->api = ipcp_create(ipcp_type);
        if (api->api == -1) {
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Failed to create IPCP.");
                return -1;
        }

        tmp = ipcp_entry_create();
        if (tmp == NULL) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        INIT_LIST_HEAD(&tmp->next);

        tmp->api = api->api;
        tmp->name = strdup(name);
        if (tmp->name  == NULL) {
                ipcp_entry_destroy(tmp);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        tmp->dif_name = NULL;
        tmp->type = ipcp_type;

        pthread_rwlock_wrlock(&irmd->reg_lock);

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);
                if (e->type < ipcp_type)
                        break;
        }

        list_add(&tmp->next, &irmd->ipcps);

        list_add(&api->next, &irmd->spawned_apis);

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        LOG_INFO("Created IPCP %d.", api->api);

        return api->api;
}

static void clear_spawned_api(pid_t api)
{
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        list_for_each_safe(pos, n, &(irmd->spawned_apis)) {
                struct spawned_api * a =
                        list_entry(pos, struct spawned_api, next);

                if (api == a->api) {
                        list_del(&a->next);
                        free(a);
                }
        }
}

static int destroy_ipcp(pid_t api)
{
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_wrlock(&irmd->reg_lock);

        list_for_each_safe(pos, n, &(irmd->ipcps)) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                if (api == tmp->api) {
                        clear_spawned_api(api);
                        if (ipcp_destroy(api))
                                LOG_ERR("Could not destroy IPCP.");
                        list_del(&tmp->next);
                        ipcp_entry_destroy(tmp);

                        LOG_INFO("Destroyed IPCP %d.", api);
                }
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return 0;
}

static int bootstrap_ipcp(pid_t              api,
                          dif_config_msg_t * conf)
{
        struct ipcp_entry * entry = NULL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        entry = get_ipcp_entry_by_api(api);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("No such IPCP.");
                return -1;
        }

        entry->dif_name = strdup(conf->dif_name);
        if (entry->dif_name == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Failed to strdup.");
                return -1;
        }

        if (ipcp_bootstrap(entry->api, conf)) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Could not bootstrap IPCP.");
                free(entry->dif_name);
                entry->dif_name = NULL;
                return -1;
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        LOG_INFO("Bootstrapped IPCP %d in DIF %s.",
                 entry->api, conf->dif_name);

        return 0;
}

static int enroll_ipcp(pid_t  api,
                       char * dif_name)
{
        struct ipcp_entry * entry = NULL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_rdlock(&irmd->reg_lock);

        entry = get_ipcp_entry_by_api(api);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("No such IPCP.");
                return -1;
        }

        entry->dif_name = strdup(dif_name);
        if (entry->dif_name == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Failed to strdup.");
                return -1;
        }

        if (ipcp_enroll(api, dif_name)) {
                free(entry->dif_name);
                entry->dif_name = NULL;
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Could not enroll IPCP.");
                return -1;
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        LOG_INFO("Enrolled IPCP %d in DIF %s.",
                 entry->api, dif_name);

        return 0;
}

static int bind_name(char *   name,
                     char *   ap_name,
                     uint16_t opts,
                     int      argc,
                     char **  argv)
{
        char * apn       = path_strip(ap_name);
        char ** argv_dup = NULL;
        int i            = 0;

        if (name == NULL || ap_name == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        if (opts & BIND_AP_AUTO) {
                /* we need to duplicate argv */
                if (argc != 0) {
                        argv_dup = malloc((argc + 2) * sizeof(*argv_dup));
                        argv_dup[0] = strdup(ap_name);
                        for (i = 1; i <= argc; ++i)
                                argv_dup[i] = strdup(argv[i - 1]);
                        argv_dup[argc + 1] = NULL;
                }
        }

        if (registry_add_binding(&irmd->registry,
                                 strdup(name), strdup(apn),
                                 opts, argv_dup) < 0) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Failed to register %s.", name);
                return -1;
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        LOG_INFO("Bound %s to registered name %s.", ap_name, name);

        return 0;
}

static int unbind_name(char *   name,
                       char *   apn,
                       uint16_t opts)

{
        if (name == NULL)
                return -EINVAL;

        if (!(opts & UNBIND_AP_HARD) && apn == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        if ((opts & UNBIND_AP_HARD) && apn == NULL) {
                registry_deassign(&irmd->registry, name);
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_INFO("Removed all bindings of %s.", name);
        } else {
                registry_del_binding(&irmd->registry, name, apn);
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_INFO("Removed binding from %s to %s.", apn, name);
        }

        return 0;
}

static ssize_t list_ipcps(char * name,
                          pid_t ** apis)
{
        struct list_head * pos = NULL;
        ssize_t count = 0;
        int i = 0;

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                if (wildcard_match(name, tmp->name) == 0) {
                        count++;
                }
        }

        *apis = malloc(count * sizeof(pid_t));
        if (*apis == NULL) {
                return -1;
        }

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                if (wildcard_match(name, tmp->name) == 0) {
                        (*apis)[i++] = tmp->api;
                }
        }

        return count;
}

static int ap_reg(char *  name,
                  char ** difs,
                  size_t  len)
{
        int i;
        int ret = 0;
        struct list_head * pos = NULL;

        if (name == NULL || difs == NULL || len == 0 || difs[0] == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        if (list_empty(&irmd->ipcps)) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);

                if (e->dif_name == NULL)
                        continue;

                for (i = 0; i < len; ++i) {
                        if (wildcard_match(difs[i], e->dif_name))
                                continue;

                        if (ipcp_name_reg(e->api, name)) {
                                LOG_ERR("Could not register %s in DIF %s.",
                                        name, e->dif_name);
                        } else {
                                if(registry_add_name_to_dif(&irmd->registry,
                                                            name,
                                                            e->dif_name,
                                                            e->type) < 0)
                                        LOG_WARN("Registered unbound name %s. "
                                                 "Registry may be inconsistent",
                                                 name);
                                LOG_INFO("Registered %s in %s %d.",
                                         name, e->dif_name, e->type);
                                ++ret;
                        }
                }
        }

        if (ret == 0) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return ret;
}

static int ap_unreg(char *  name,
                    char ** difs,
                    size_t  len)
{
        int i;
        int ret = 0;
        struct list_head * pos = NULL;

        if (name == NULL || len == 0 || difs == NULL || difs[0] == NULL)
                return -1;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);

                if (e->dif_name == NULL)
                        continue;

                for (i = 0; i < len; ++i) {
                        if (wildcard_match(difs[i], e->dif_name))
                                continue;

                        if (ipcp_name_unreg(e->api, name)) {
                                LOG_ERR("Could not unregister %s in DIF %s.",
                                        name, e->dif_name);
                                --ret;
                        } else {
                                registry_del_name_from_dif(&irmd->registry,
                                                           name,
                                                           e->dif_name);
                                LOG_INFO("Unregistered %s from %s.",
                                         name, e->dif_name);
                        }
                }
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return ret;
}

static struct irm_flow * flow_accept(pid_t   api,
                                     char *  srv_ap_name,
                                     char ** dst_ae_name)
{
        struct irm_flow * pme = NULL;
        struct reg_entry *      rne = NULL;
        struct reg_api *        rgi = NULL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        rne = registry_get_entry_by_apn(&irmd->registry, srv_ap_name);
        if (rne == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("AP %s is unknown.", srv_ap_name);
                return NULL;
        }

        if (!reg_entry_get_reg_api(rne, api)) {
                rgi = registry_add_api_name(&irmd->registry,
                                            api,
                                            rne->name);
                if (rgi == NULL) {
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        LOG_ERR("Failed to register instance %d with %s.",
                                api,srv_ap_name);
                        return NULL;
                }
                LOG_INFO("New instance (%d) of %s added.", api, srv_ap_name);
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        reg_api_sleep(rgi);

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_rdlock(&irmd->reg_lock);
        pthread_mutex_lock(&rne->state_lock);

        if (rne->state != REG_NAME_FLOW_ARRIVED) {
                pthread_mutex_unlock(&rne->state_lock);
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }

        pthread_mutex_unlock(&rne->state_lock);
        pthread_rwlock_unlock(&irmd->reg_lock);

        pthread_rwlock_rdlock(&irmd->flows_lock);

        pme = get_irm_flow_n(api);
        if (pme == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Port_id was not created yet.");
                return NULL;
        }

        if (dst_ae_name != NULL)
                *dst_ae_name = rne->req_ae_name;

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return pme;
}

static int flow_alloc_resp(pid_t n_api,
                           int   port_id,
                           int   response)
{
        struct irm_flow * pme = NULL;
        struct reg_entry * rne      = NULL;
        int ret = -1;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        rne = registry_get_entry_by_api(&irmd->registry, n_api);
        if (rne == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        if (rne->state != REG_NAME_FLOW_ARRIVED) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Process not listening for this name.");
                return -1;
        }

        pthread_mutex_lock(&rne->state_lock);

        registry_del_api(&irmd->registry, n_api);

        pthread_mutex_unlock(&rne->state_lock);

        pthread_rwlock_unlock(&irmd->reg_lock);

        if (!response) {
                pthread_rwlock_wrlock(&irmd->flows_lock);

                pme = get_irm_flow(port_id);
                if (pme == NULL) {
                        pthread_rwlock_unlock(&irmd->flows_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        return -1;
                }

                pme->state = FLOW_ALLOCATED;
                pthread_cond_signal(&pme->state_cond);
                pthread_rwlock_unlock(&irmd->flows_lock);

                ret = ipcp_flow_alloc_resp(pme->n_1_api,
                                           port_id,
                                           pme->n_api,
                                           response);
        }

        pthread_rwlock_unlock(&irmd->state_lock);

        return ret;
}

static struct irm_flow * flow_alloc(pid_t  api,
                                    char * dst_name,
                                    char * src_ae_name,
                                    struct qos_spec * qos)
{
        struct irm_flow * pme;
        pid_t ipcp;

        /* FIXME: Map qos_spec to qos_cube */

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }

        pme = irm_flow_create();
        if (pme == NULL) {
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Failed to create irm_flow.");
                return NULL;
        }

        pme->n_api = api;
        pme->state = FLOW_PENDING;
        if (clock_gettime(CLOCK_MONOTONIC, &pme->t0) < 0)
                LOG_WARN("Failed to set timestamp.");

        pthread_rwlock_rdlock(&irmd->reg_lock);

        ipcp = get_ipcp_by_dst_name(dst_name);
        if (ipcp == -1) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_INFO("Destination unreachable.");
                return NULL;
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_wrlock(&irmd->flows_lock);

        pme->port_id = bmp_allocate(irmd->port_ids);
        pme->n_1_api = ipcp;

        list_add(&pme->next, &irmd->irm_flows);

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        if (ipcp_flow_alloc(ipcp,
                            pme->port_id,
                            pme->n_api,
                            dst_name,
                            src_ae_name,
                            QOS_CUBE_BE) < 0) {
                pthread_rwlock_rdlock(&irmd->state_lock);
                pthread_rwlock_wrlock(&irmd->flows_lock);
                list_del(&pme->next);
                bmp_release(irmd->port_ids, pme->port_id);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                free(pme);
                return NULL;
        }

        return pme;
}

static int flow_alloc_res(int port_id)
{
        struct irm_flow * e;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }
        pthread_rwlock_rdlock(&irmd->flows_lock);

        e = get_irm_flow(port_id);
        if (e == NULL) {
                LOG_ERR("Could not find port %d.", port_id);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        if (e->state == FLOW_NULL) {
                LOG_INFO("Port %d is deprecated.", port_id);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        if (e->state == FLOW_ALLOCATED) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return 0;
        }

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        pthread_mutex_lock(&e->state_lock);
        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void*) &e->state_lock);

        while (e->state == FLOW_PENDING)
                pthread_cond_wait(&e->state_cond, &e->state_lock);

        pthread_cleanup_pop(true);

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_wrlock(&irmd->flows_lock);
        pthread_mutex_lock(&e->state_lock);

        if (e->state == FLOW_ALLOCATED) {
                pthread_mutex_unlock(&e->state_lock);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return 0;
        }

        e->state = FLOW_NULL;
        pthread_cond_signal(&e->state_cond);
        pthread_mutex_unlock(&e->state_lock);
        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return -1;
}

static int flow_dealloc(int port_id)
{
        pid_t n_1_api;
        int   ret = 0;

        struct irm_flow * e = NULL;

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_wrlock(&irmd->flows_lock);
        bmp_release(irmd->port_ids, port_id);

        e = get_irm_flow(port_id);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return 0;
        }

        n_1_api = e->n_1_api;

        list_del(&e->next);

        pthread_rwlock_unlock(&irmd->flows_lock);

        ret = ipcp_flow_dealloc(n_1_api, port_id);

        pthread_rwlock_unlock(&irmd->state_lock);

        free(e);

        return ret;
}

static pid_t auto_execute(char ** argv)
{
        pid_t api;
        struct stat s;

        if (stat(argv[0], &s) != 0) {
                LOG_WARN("Application %s does not exist.", argv[0]);
                return -1;
        }

        if (!(s.st_mode & S_IXUSR)) {
                LOG_WARN("Application %s is not executable.", argv[0]);
                return -1;
        }

        LOG_INFO("Executing %s.", argv[0]);
        api = fork();
        if (api == -1) {
                LOG_ERR("Failed to fork");
                return api;
        }

        if (api != 0)
                return api;

        execv(argv[0], argv);

        LOG_ERR("Failed to execute %s.", argv[0]);

        exit(EXIT_FAILURE);
}

static struct irm_flow * flow_req_arr(pid_t  api,
                                      char * dst_name,
                                      char * ae_name)
{
        struct reg_entry *      rne = NULL;
        struct irm_flow * pme = NULL;

        enum reg_name_state state;

        struct spawned_api * c_api;

        pme = irm_flow_create();
        if (pme == NULL) {
                LOG_ERR("Failed to create irm_flow.");
                return NULL;
        }

        pme->state   = FLOW_PENDING;
        pme->n_1_api = api;
        if (clock_gettime(CLOCK_MONOTONIC, &pme->t0) < 0)
                LOG_WARN("Failed to set timestamp.");

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_rdlock(&irmd->reg_lock);

        rne = registry_get_entry_by_name(&irmd->registry, dst_name);
        if (rne == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Unknown name: %s.", dst_name);
                free(pme);
                return NULL;
        }

        pthread_mutex_lock(&rne->state_lock);
        state = rne->state;
        pthread_mutex_unlock(&rne->state_lock);

        switch (state) {
        case REG_NAME_IDLE:
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("No AP's for %s.", dst_name);
                free(pme);
                return NULL;
        case REG_NAME_AUTO_ACCEPT:
                c_api = malloc(sizeof(*c_api));
                if (c_api == NULL) {
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        free(pme);
                        return NULL;
                }

                pthread_mutex_lock(&rne->state_lock);
                rne->state = REG_NAME_AUTO_EXEC;
                pthread_mutex_unlock(&rne->state_lock);

                if ((c_api->api = auto_execute(reg_entry_get_auto_info(rne)))
                    < 0) {
                        pthread_mutex_lock(&rne->state_lock);
                        rne->state = REG_NAME_AUTO_ACCEPT;
                        pthread_mutex_unlock(&rne->state_lock);
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        free(pme);
                        free(c_api);
                        return NULL;
                }

                list_add(&c_api->next, &irmd->spawned_apis);

                pthread_rwlock_unlock(&irmd->reg_lock);

                pthread_mutex_lock(&rne->state_lock);
                pthread_cleanup_push((void(*)(void *)) pthread_mutex_unlock,
                                     (void *) &rne->state_lock);

                while (rne->state == REG_NAME_AUTO_EXEC)
                        pthread_cond_wait(&rne->state_cond, &rne->state_lock);

                pthread_cleanup_pop(true);

                pthread_rwlock_rdlock(&irmd->reg_lock);
                pthread_mutex_lock(&rne->state_lock);
                if (rne->state == REG_NAME_DESTROY) {
                        rne->state = REG_NAME_NULL;
                        pthread_mutex_unlock(&rne->state_lock);
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        return NULL;
                }
                pthread_mutex_unlock(&rne->state_lock);
        case REG_NAME_FLOW_ACCEPT:
                pme->n_api = reg_entry_resolve_api(rne);
                if (pme->n_api == -1) {
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        LOG_ERR("Invalid api returned.");
                        return NULL;
                }

                break;
        default:
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("IRMd in wrong state.");
                free(pme);
                return NULL;
        }

        pthread_rwlock_unlock(&irmd->reg_lock);

        pthread_rwlock_wrlock(&irmd->flows_lock);
        pme->port_id = bmp_allocate(irmd->port_ids);

        list_add(&pme->next, &irmd->irm_flows);

        pthread_rwlock_unlock(&irmd->flows_lock);

        pthread_mutex_lock(&rne->state_lock);

        rne->req_ae_name = ae_name;

        rne->state = REG_NAME_FLOW_ARRIVED;

        reg_api_wake(reg_entry_get_reg_api(rne, pme->n_api));

        pthread_mutex_unlock(&rne->state_lock);

        pthread_rwlock_unlock(&irmd->state_lock);

        pthread_cleanup_push((void(*)(void *)) pthread_mutex_unlock,
                             (void *) &rne->state_lock);

        while (rne->state == REG_NAME_FLOW_ARRIVED &&
               irmd->state == IRMD_RUNNING)
                pthread_cond_wait(&rne->state_cond, &rne->state_lock);

        pthread_cleanup_pop(true);

        return pme;
}

static int flow_alloc_reply(int port_id,
                            int response)
{
        struct irm_flow * e;

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_rdlock(&irmd->flows_lock);

        e = get_irm_flow(port_id);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_mutex_lock(&e->state_lock);

        if (!response)
                e->state = FLOW_ALLOCATED;

        else
                e->state = FLOW_NULL;

        if (pthread_cond_signal(&e->state_cond))
                LOG_ERR("Failed to send signal.");

        pthread_mutex_unlock(&e->state_lock);

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return 0;
}

static int flow_dealloc_ipcp(int port_id)
{
        struct irm_flow * e = NULL;

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_wrlock(&irmd->flows_lock);

        e = get_irm_flow(port_id);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return 0;
        }

        list_del(&e->next);

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        free(e);

        return 0;
}

static void irm_destroy()
{
        struct list_head * h;
        struct list_head * t;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_NULL)
                LOG_WARN("Unsafe destroy.");

        if (irmd->threadpool != NULL)
                free(irmd->threadpool);

        pthread_rwlock_wrlock(&irmd->reg_lock);
        /* clear the lists */
        list_for_each_safe(h, t, &irmd->ipcps) {
                struct ipcp_entry * e = list_entry(h, struct ipcp_entry, next);
                list_del(&e->next);
                ipcp_destroy(e->api);
                clear_spawned_api(e->api);
                ipcp_entry_destroy(e);
        }

        registry_destroy(&irmd->registry);

        list_for_each_safe(h, t, &irmd->spawned_apis) {
                struct spawned_api * api =
                        list_entry(h, struct spawned_api, next);
                int status;
                if (kill(api->api, SIGTERM))
                        LOG_DBG("Could not send kill signal to %d.", api->api);
                else if (waitpid(api->api, &status, 0) < 0)
                        LOG_DBG("Error waiting for %d to exit.", api->api);
                list_del(&api->next);
                free(api);
        }

        pthread_rwlock_unlock(&irmd->reg_lock);

        pthread_rwlock_wrlock(&irmd->flows_lock);

        list_for_each_safe(h, t, &irmd->irm_flows) {
                struct irm_flow * e = list_entry(h, struct irm_flow, next);
                list_del(&e->next);
                irm_flow_destroy(e);
        }

        if (irmd->port_ids != NULL)
                bmp_destroy(irmd->port_ids);

        pthread_rwlock_unlock(&irmd->flows_lock);

        if (irmd->dum != NULL)
                shm_du_map_destroy(irmd->dum);

        if (irmd->lf != NULL)
                lockfile_destroy(irmd->lf);

        close(irmd->sockfd);

        pthread_rwlock_unlock(&irmd->state_lock);

        pthread_rwlock_destroy(&irmd->reg_lock);
        pthread_rwlock_destroy(&irmd->state_lock);

        free(irmd);
}

void irmd_sig_handler(int sig, siginfo_t * info, void * c)
{
        int i;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                pthread_rwlock_wrlock(&irmd->state_lock);

                irmd->state = IRMD_NULL;

                pthread_rwlock_unlock(&irmd->state_lock);

                if (irmd->threadpool != NULL) {
                        for (i = 0; i < IRMD_THREADPOOL_SIZE; i++)
                                pthread_cancel(irmd->threadpool[i]);

                }

                pthread_cancel(irmd->shm_sanitize);
                pthread_cancel(irmd->cleanup_flows);
                break;
        case SIGPIPE:
                LOG_DBG("Ignored SIGPIPE.");
        default:
                return;
        }
}

void * irm_flow_cleaner()
{
        struct timespec now;
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        struct timespec timeout = {IRMD_CLEANUP_TIMER / BILLION,
                                   IRMD_CLEANUP_TIMER % BILLION};
        int status;

        while (true) {
                if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
                        LOG_WARN("Failed to get time.");
                /* cleanup stale PENDING flows */

                pthread_rwlock_rdlock(&irmd->state_lock);

                if (irmd->state == IRMD_NULL) {
                        pthread_rwlock_unlock(&irmd->state_lock);
                        return (void *) 0;
                }

                pthread_rwlock_wrlock(&irmd->flows_lock);

                list_for_each_safe(pos, n, &(irmd->irm_flows)) {
                        struct irm_flow * e =
                                list_entry(pos, struct irm_flow, next);

                        pthread_mutex_lock(&e->state_lock);

                        if (e->state == FLOW_PENDING &&
                            ts_diff_ms(&e->t0, &now) > IRMD_FLOW_TIMEOUT) {
                                LOG_INFO("Pending port_id %d timed out.",
                                         e->port_id);
                                e->state = FLOW_NULL;
                                pthread_cond_signal(&e->state_cond);
                                pthread_mutex_unlock(&e->state_lock);
                                continue;
                        }

                        pthread_mutex_unlock(&e->state_lock);

                        if (kill(e->n_api, 0) < 0) {
                                struct shm_ap_rbuff * n_rb =
                                        shm_ap_rbuff_open(e->n_api);
                                bmp_release(irmd->port_ids, e->port_id);

                                list_del(&e->next);
                                LOG_INFO("Process %d gone, %d deallocated.",
                                         e->n_api, e->port_id);
                                ipcp_flow_dealloc(e->n_1_api, e->port_id);
                                if (n_rb != NULL)
                                        shm_ap_rbuff_destroy(n_rb);
                                irm_flow_destroy(e);
                        }
                        if (kill(e->n_1_api, 0) < 0) {
                                struct shm_ap_rbuff * n_1_rb =
                                        shm_ap_rbuff_open(e->n_1_api);
                                list_del(&e->next);
                                LOG_ERR("IPCP %d gone, flow %d removed.",
                                        e->n_1_api, e->port_id);
                                if (n_1_rb != NULL)
                                        shm_ap_rbuff_destroy(n_1_rb);
                                irm_flow_destroy(e);
                        }
                }

                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_wrlock(&irmd->reg_lock);

                registry_sanitize_apis(&irmd->registry);

                list_for_each_safe(pos, n, &irmd->spawned_apis) {
                        struct spawned_api * api =
                                list_entry(pos, struct spawned_api, next);
                        waitpid(api->api, &status, WNOHANG);

                        if (kill(api->api, 0) < 0) {
                                LOG_INFO("Spawned process %d terminated "
                                         "with exit status %d.",
                                         api->api, status);
                                list_del(&api->next);
                                free(api);
                        }
                }

                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);

                nanosleep(&timeout, NULL);
        }
}

void clean_msg(void * msg)
{
        irm_msg__free_unpacked(msg, NULL);
}

void * mainloop()
{
        uint8_t buf[IRM_MSG_BUF_SIZE];

        while (true) {
                int cli_sockfd;
                irm_msg_t * msg;
                ssize_t count;
                buffer_t buffer;
                irm_msg_t ret_msg = IRM_MSG__INIT;
                struct irm_flow * e = NULL;
                pid_t * apis = NULL;

                ret_msg.code = IRM_MSG_CODE__IRM_REPLY;

                cli_sockfd = accept(irmd->sockfd, 0, 0);
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

                pthread_cleanup_push(clean_msg, (void *) msg);

                switch (msg->code) {
                case IRM_MSG_CODE__IRM_CREATE_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = create_ipcp(msg->dst_name,
                                                     msg->ipcp_type);
                        break;
                case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = destroy_ipcp(msg->api);
                        break;
                case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = bootstrap_ipcp(msg->api,
                                                        msg->conf);
                        break;
                case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = enroll_ipcp(msg->api,
                                                     msg->dif_name[0]);
                        break;
                case IRM_MSG_CODE__IRM_BIND:
                        ret_msg.has_result = true;
                        ret_msg.result = bind_name(msg->dst_name,
                                                   msg->ap_name,
                                                   msg->opts,
                                                   msg->n_args,
                                                   msg->args);
                        break;
                case IRM_MSG_CODE__IRM_UNBIND:
                        ret_msg.has_result = true;
                        ret_msg.result = unbind_name(msg->dst_name,
                                                     msg->ap_name,
                                                     msg->opts);
                        break;
                case IRM_MSG_CODE__IRM_LIST_IPCPS:
                        ret_msg.n_apis = list_ipcps(msg->dst_name,
                                                    &apis);
                        ret_msg.apis = apis;
                        ret_msg.has_result = true;
                        break;
                case IRM_MSG_CODE__IRM_REG:
                        ret_msg.has_result = true;
                        ret_msg.result = ap_reg(msg->dst_name,
                                                msg->dif_name,
                                                msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_UNREG:
                        ret_msg.has_result = true;
                        ret_msg.result = ap_unreg(msg->dst_name,
                                                  msg->dif_name,
                                                  msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ACCEPT:
                        e = flow_accept(msg->api,
                                        msg->ap_name,
                                        &ret_msg.ae_name);

                        if (e == NULL) {
                                ret_msg.has_result = true;
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.has_port_id = true;
                        ret_msg.port_id     = e->port_id;
                        ret_msg.has_api     = true;
                        ret_msg.api         = e->n_1_api;
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC_RESP:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc_resp(msg->api,
                                                         msg->port_id,
                                                         msg->response);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC:
                        e = flow_alloc(msg->api,
                                       msg->dst_name,
                                       msg->ae_name,
                                       NULL);
                        if (e == NULL) {
                                ret_msg.has_result = true;
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.has_port_id = true;
                        ret_msg.port_id     = e->port_id;
                        ret_msg.has_api     = true;
                        ret_msg.api         = e->n_1_api;
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
                        e = flow_req_arr(msg->api,
                                         msg->dst_name,
                                         msg->ae_name);
                        if (e == NULL) {
                                ret_msg.has_result = true;
                                ret_msg.result = -1;
                                break;
                        }

                        ret_msg.has_port_id = true;
                        ret_msg.port_id     = e->port_id;
                        ret_msg.has_api     = true;
                        ret_msg.api         = e->n_api;
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

                pthread_cleanup_pop(true);

                buffer.len = irm_msg__get_packed_size(&ret_msg);
                if (buffer.len == 0) {
                        LOG_ERR("Failed to send reply message.");
                        if (apis != NULL)
                                free(apis);
                        close(cli_sockfd);
                        continue;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        if (apis != NULL)
                                free(apis);
                        close(cli_sockfd);
                        continue;
                }

                irm_msg__pack(&ret_msg, buffer.data);

                if (write(cli_sockfd, buffer.data, buffer.len) == -1) {
                        free(buffer.data);
                        if (apis != NULL)
                                free(apis);
                        close(cli_sockfd);
                        continue;
                }

                if (apis != NULL)
                        free(apis);

                free(buffer.data);
                close(cli_sockfd);
        }
}

static struct irm * irm_create()
{
        struct stat st = {0};

        irmd = malloc(sizeof(*irmd));
        if (irmd == NULL)
                return NULL;

        irmd->state = IRMD_NULL;

        if (access("/dev/shm/" LOCKFILE_NAME, F_OK) != -1) {
                struct lockfile * lf = lockfile_open();
                if (lf == NULL) {
                        LOG_ERR("Failed to open existing lockfile.");
                        free(irmd);
                        return NULL;
                }

                if (kill(lockfile_owner(lf), 0) < 0) {
                        LOG_INFO("IRMd didn't properly shut down last time.");
                        shm_du_map_destroy(shm_du_map_open());
                        LOG_INFO("Stale resources cleaned");
                        lockfile_destroy(lf);
                } else {
                        LOG_INFO("IRMd already running (%d), exiting.",
                                 lockfile_owner(lf));
                        lockfile_close(lf);
                        free(irmd);
                        return NULL;
                }
        }

        if (pthread_rwlock_init(&irmd->state_lock, NULL)) {
                LOG_ERR("Failed to initialize rwlock.");
                free(irmd);
                return NULL;
        }

        if (pthread_rwlock_init(&irmd->reg_lock, NULL)) {
                LOG_ERR("Failed to initialize rwlock.");
                free(irmd);
                return NULL;
        }

        if (pthread_rwlock_init(&irmd->flows_lock, NULL)) {
                LOG_ERR("Failed to initialize rwlock.");
                free(irmd);
                return NULL;
        }

        INIT_LIST_HEAD(&irmd->ipcps);
        INIT_LIST_HEAD(&irmd->spawned_apis);
        INIT_LIST_HEAD(&irmd->registry);
        INIT_LIST_HEAD(&irmd->irm_flows);

        irmd->port_ids = bmp_create(IRMD_MAX_FLOWS, 0);
        if (irmd->port_ids == NULL) {
                irm_destroy();
                return NULL;
        }

        irmd->threadpool = malloc(sizeof(pthread_t) * IRMD_THREADPOOL_SIZE);
        if (irmd->threadpool == NULL) {
                irm_destroy();
                return NULL;
        }

        if (stat(SOCK_PATH, &st) == -1) {
                if (mkdir(SOCK_PATH, 0777)) {
                        LOG_ERR("Failed to create sockets directory.");
                        irm_destroy();
                        return NULL;
                }
        }

        irmd->sockfd = server_socket_open(IRM_SOCK_PATH);
        if (irmd->sockfd < 0) {
                irm_destroy();
                return NULL;
        }

        if (chmod(IRM_SOCK_PATH, 0666)) {
                LOG_ERR("Failed to chmod socket.");
                irm_destroy();
                return NULL;
        }

        if ((irmd->lf = lockfile_create()) == NULL) {
                irm_destroy();
                return NULL;
        }

        if ((irmd->dum = shm_du_map_create()) == NULL) {
                irm_destroy();
                return NULL;
        }

        irmd->state = IRMD_RUNNING;

        return irmd;
}

static void usage()
{
        LOG_ERR("Usage: irmd \n\n"
                 "         [--stdout (Print to stdout instead of logs)]\n");
}

int main(int argc, char ** argv)
{
        struct sigaction sig_act;

        int t = 0;

        char * log_file = INSTALL_PREFIX LOG_DIR "irmd.log";
        DIR * log_dir;
        struct dirent * ent;
        char * point;
        char * log_path;
        size_t len = 0;
        bool use_stdout = false;

        if (geteuid() != 0) {
                LOG_ERR("IPC Resource Manager must be run as root.");
                exit(EXIT_FAILURE);
        }

        argc--;
        argv++;
        while (argc > 0) {
                if (strcmp(*argv, "--stdout") == 0) {
                        use_stdout = true;
                        argc--;
                        argv++;
                } else {
                        usage();
                        exit(EXIT_FAILURE);
                }
        }


        if (!use_stdout &&
            (log_dir = opendir(INSTALL_PREFIX LOG_DIR)) != NULL) {
                while ((ent = readdir(log_dir)) != NULL) {
                        point = strrchr(ent->d_name,'.');
                        if (point == NULL ||
                            strcmp(point, ".log") != 0)
                                continue;

                        len += strlen(INSTALL_PREFIX);
                        len += strlen(LOG_DIR);
                        len += strlen(ent->d_name);

                        log_path = malloc(len + 1);
                        if (log_path == NULL) {
                                LOG_ERR("Failed to malloc");
                                exit(EXIT_FAILURE);
                        }

                        strcpy(log_path, INSTALL_PREFIX);
                        strcat(log_path, LOG_DIR);
                        strcat(log_path, ent->d_name);

                        unlink(log_path);

                        free(log_path);
                        len = 0;
                }
                closedir(log_dir);
        }

        if (!use_stdout)
                if (set_logfile(log_file))
                        LOG_ERR("Cannot open %s, falling back to "
                                "stdout for logs.",
                                log_file);

        /* init sig_act */
        memset(&sig_act, 0, sizeof sig_act);

        /* install signal traps */
        sig_act.sa_sigaction = &irmd_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        if (sigaction(SIGINT,  &sig_act, NULL) < 0)
                exit(EXIT_FAILURE);
        if (sigaction(SIGTERM, &sig_act, NULL) < 0)
                exit(EXIT_FAILURE);
        if (sigaction(SIGHUP,  &sig_act, NULL) < 0)
                exit(EXIT_FAILURE);
        if (sigaction(SIGPIPE, &sig_act, NULL) < 0)
                exit(EXIT_FAILURE);

        irmd = irm_create();
        if (irmd == NULL) {
                close_logfile();
                exit(EXIT_FAILURE);
        }

        for (t = 0; t < IRMD_THREADPOOL_SIZE; ++t)
                pthread_create(&irmd->threadpool[t], NULL, mainloop, NULL);

        pthread_create(&irmd->cleanup_flows, NULL, irm_flow_cleaner, NULL);
        pthread_create(&irmd->shm_sanitize, NULL,
                       shm_du_map_sanitize, irmd->dum);

        /* wait for (all of them) to return */
        for (t = 0; t < IRMD_THREADPOOL_SIZE; ++t)
                pthread_join(irmd->threadpool[t], NULL);

        pthread_join(irmd->shm_sanitize, NULL);
        pthread_join(irmd->cleanup_flows, NULL);

        irm_destroy();

        close_logfile();

        exit(EXIT_SUCCESS);
}
