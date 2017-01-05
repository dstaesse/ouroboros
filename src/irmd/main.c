/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "irmd"

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/sockets.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/irm_config.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/shm_flow_set.h>
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/qos.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/logs.h>

#include "utils.h"
#include "registry.h"
#include "irm_flow.h"
#include "api_table.h"
#include "ipcp.h"

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
#define SHM_SAN_HOLDOFF 1000 /* ms */

struct ipcp_entry {
        struct list_head next;

        char *           name;
        pid_t            api;
        enum ipcp_type   type;
        char *           dif_name;

        pthread_cond_t   init_cond;
        pthread_mutex_t  init_lock;
        bool             init;
};

enum irm_state {
        IRMD_NULL = 0,
        IRMD_RUNNING
};

struct irm {
        struct list_head     registry;

        struct list_head     ipcps;

        struct list_head     api_table;
        struct list_head     apn_table;
        struct list_head     spawned_apis;
        pthread_rwlock_t     reg_lock;

        /* keep track of all flows in this processing system */
        struct bmp *         port_ids;
        /* maps port_ids to api pair */
        struct list_head     irm_flows;
        pthread_rwlock_t     flows_lock;

        struct lockfile *    lf;
        struct shm_rdrbuff * rdrb;
        pthread_t *          threadpool;
        int                  sockfd;

        enum irm_state       state;
        pthread_rwlock_t     state_lock;

        pthread_t            irm_sanitize;
        pthread_t            shm_sanitize;
} * irmd;

static void clear_irm_flow(struct irm_flow * f) {
        ssize_t idx;

        assert(f);

        while ((idx = shm_rbuff_read(f->n_rb)) >= 0)
                shm_rdrbuff_remove(irmd->rdrb, idx);

        while ((idx = shm_rbuff_read(f->n_1_rb)) >= 0)
                shm_rdrbuff_remove(irmd->rdrb, idx);
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

static struct ipcp_entry * ipcp_entry_create(void)
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
        struct list_head * p = NULL;

        list_for_each(p, &irmd->ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (api == e->api)
                        return e;
        }

        return NULL;
}

/* Check if the name exists anywhere in a DIF. */
static pid_t get_ipcp_by_dst_name(char * dst_name)
{
        struct list_head * p = NULL;

        list_for_each(p, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(p, struct ipcp_entry, next);
                if (e->type == IPCP_LOCAL) {
                        if (ipcp_name_query(e->api, dst_name) == 0)
                                return e->api;
                }
        }

        list_for_each(p, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(p, struct ipcp_entry, next);
                if (e->type == IPCP_NORMAL) {
                        if (ipcp_name_query(e->api, dst_name) == 0)
                                return e->api;
                }
        }

        list_for_each(p, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(p, struct ipcp_entry, next);
                if (e->type == IPCP_SHIM_ETH_LLC) {
                        if (ipcp_name_query(e->api, dst_name) == 0)
                                return e->api;
                }
        }

        list_for_each(p, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(p, struct ipcp_entry, next);
                if (e->type == IPCP_SHIM_UDP) {
                        if (ipcp_name_query(e->api, dst_name) == 0)
                                return e->api;
                }
        }

        return -1;
}

static pid_t create_ipcp(char * name, enum ipcp_type ipcp_type)
{
        struct pid_el *      api = NULL;
        struct ipcp_entry *  tmp = NULL;
        struct list_head *   p   = NULL;

        api = malloc(sizeof(*api));
        if (api == NULL)
                return -ENOMEM;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        api->pid = ipcp_create(ipcp_type);
        if (api->pid == -1) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Failed to create IPCP.");
                return -1;
        }

        tmp = ipcp_entry_create();
        if (tmp == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        INIT_LIST_HEAD(&tmp->next);

        tmp->api = api->pid;
        tmp->name = strdup(name);
        if (tmp->name  == NULL) {
                ipcp_entry_destroy(tmp);
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_cond_init(&tmp->init_cond, NULL);
        pthread_mutex_init(&tmp->init_lock, NULL);

        tmp->dif_name = NULL;
        tmp->type = ipcp_type;
        tmp->init = false;

        list_for_each(p, &irmd->ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->type < ipcp_type)
                        break;
        }

        list_add(&tmp->next, &irmd->ipcps);

        list_add(&api->next, &irmd->spawned_apis);

        pthread_mutex_lock(&tmp->init_lock);

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        while (tmp->init == false)
                pthread_cond_wait(&tmp->init_cond, &tmp->init_lock);

        pthread_mutex_unlock(&tmp->init_lock);

        LOG_INFO("Created IPCP %d.", api->pid);

        return api->pid;
}

static int create_ipcp_r(pid_t api)
{
        struct list_head * pos = NULL;

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_rdlock(&irmd->reg_lock);

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);

                if (e->api == api) {
                        pthread_mutex_lock(&e->init_lock);
                        e->init = true;
                        pthread_cond_broadcast(&e->init_cond);
                        pthread_mutex_unlock(&e->init_lock);
                }
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return 0;
}

static void clear_spawned_api(pid_t api)
{
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        list_for_each_safe(pos, n, &(irmd->spawned_apis)) {
                struct pid_el * a = list_entry(pos, struct pid_el, next);
                if (api == a->pid) {
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

static int bootstrap_ipcp(pid_t api, dif_config_msg_t * conf)
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

static int enroll_ipcp(pid_t api, char * dif_name)
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

        if (entry->dif_name != NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("IPCP in wrong state");
                return -1;
        }

        entry->dif_name = strdup(dif_name);
        if (entry->dif_name == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Failed to strdup.");
                return -1;
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        if (ipcp_enroll(api, dif_name)) {
                pthread_rwlock_rdlock(&irmd->state_lock);
                pthread_rwlock_wrlock(&irmd->reg_lock);
                free(entry->dif_name);
                entry->dif_name = NULL;
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Could not enroll IPCP.");
                return -1;
        }

        LOG_INFO("Enrolled IPCP %d in DIF %s.",
                 api, dif_name);

        return 0;
}

static int bind_ap(char * ap, char * name, uint16_t flags,
                   int argc, char ** argv)
{
        char * aps;
        char * apn;
        char ** argv_dup = NULL;
        int i;
        char * name_dup = NULL;
        struct apn_entry * e = NULL;
        struct reg_entry * re = NULL;

        if (ap == NULL || name == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        e = apn_table_get(&irmd->apn_table, path_strip(ap));

        if (e == NULL) {
                aps = strdup(path_strip(ap));
                if (aps == NULL) {
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        return -ENOMEM;
                }

                apn = strdup(name);
                if (apn == NULL) {
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        free(aps);
                        return -ENOMEM;
                }

                if ((flags & BIND_AP_AUTO) && argc) {
                /* We need to duplicate argv and set argv[0] to ap. */
                        argv_dup = malloc((argc + 2) * sizeof(*argv_dup));
                        argv_dup[0] = strdup(ap);
                        for (i = 1; i <= argc; ++i) {
                                argv_dup[i] = strdup(argv[i - 1]);
                                if (argv_dup[i] == NULL) {
                                        pthread_rwlock_unlock(&irmd->reg_lock);
                                        pthread_rwlock_unlock(
                                                &irmd->state_lock);
                                        argvfree(argv_dup);
                                        LOG_ERR("Failed to bind ap %s to  %s.",
                                                ap, name);
                                        free(aps);
                                        free(apn);
                                        return -ENOMEM;
                                }
                        }
                        argv_dup[argc + 1] = NULL;
                }
                e = apn_entry_create(apn, aps, flags, argv_dup);
                if (e == NULL) {
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        free(aps);
                        free(apn);
                        argvfree(argv_dup);
                        return -ENOMEM;
                }

                apn_table_add(&irmd->apn_table, e);

        }

        name_dup = strdup(name);
        if (name_dup == NULL) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -ENOMEM;
        }

        if (apn_entry_add_name(e, name_dup)) {
                LOG_ERR("Failed adding name.");
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                free(name_dup);
                return -ENOMEM;
        }

        re = registry_get_entry(&irmd->registry, name);
        if (re != NULL && reg_entry_add_apn(re, e) < 0)
                LOG_ERR("Failed adding AP %s for name %s.", ap, name);

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        LOG_INFO("Bound AP %s to name %s.", ap, name);

        return 0;
}

static int bind_api(pid_t api, char * name)
{
        char * name_dup = NULL;
        struct api_entry * e = NULL;
        struct reg_entry * re = NULL;

        if (name == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        e = api_table_get(&irmd->api_table, api);
        if (e == NULL) {
                LOG_ERR("AP-I %d does not exist.", api);
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        name_dup = strdup(name);
        if (name_dup == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -ENOMEM;
        }

        if (api_entry_add_name(e, name_dup)) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Failed to add name %s to api %d.", name, api);
                free(name_dup);
                return -1;
        }

        re = registry_get_entry(&irmd->registry, name);
        if (re != NULL && reg_entry_add_api(re, api) < 0)
                LOG_ERR("Failed adding AP-I %d for name %s.", api, name);

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        LOG_INFO("Bound AP-I %d to name %s.", api, name);

        return 0;
}

static int unbind_ap(char * ap, char * name)
{
        if (ap == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        if (name == NULL)
                apn_table_del(&irmd->apn_table, ap);
        else {
                struct apn_entry * e = apn_table_get(&irmd->apn_table, ap);
                apn_entry_del_name(e, name);
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        if (name  == NULL)
                LOG_INFO("AP %s removed.", ap);
        else
                LOG_INFO("All names matching %s cleared for %s.", name, ap);

        return 0;
}

static int unbind_api(pid_t api, char * name)
{
        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        if (name == NULL)
                api_table_del(&irmd->api_table, api);
        else {
                struct api_entry * e = api_table_get(&irmd->api_table, api);
                api_entry_del_name(e, name);
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        if (name  == NULL)
                LOG_INFO("AP-I %d removed.", api);
        else
                LOG_INFO("All names matching %s cleared for %d.", name, api);

        return 0;
}

static ssize_t list_ipcps(char * name, pid_t ** apis)
{
        struct list_head * pos = NULL;
        size_t count = 0;
        int i = 0;

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_rdlock(&irmd->reg_lock);

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);
                if (wildcard_match(name, tmp->name) == 0)
                        count++;
        }

        *apis = malloc(count * sizeof(pid_t));
        if (*apis == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        list_for_each(pos, &irmd->ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);
                if (wildcard_match(name, tmp->name) == 0)
                        (*apis)[i++] = tmp->api;
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return count;
}

static int name_reg(char * name, char ** difs, size_t len)
{
        size_t i;
        int ret = 0;
        struct list_head * p = NULL;

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

        if (!registry_has_name(&irmd->registry, name)) {
                struct reg_entry * re =
                        registry_add_name(&irmd->registry, strdup(name));
                if (re == NULL) {
                        LOG_ERR("Failed creating registry entry for %s.", name);
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        return -1;
                }

                /* check the tables for client APs */
                list_for_each(p, &irmd->api_table) {
                        struct list_head * q;
                        struct api_entry * e =
                                list_entry(p, struct api_entry, next);
                        list_for_each(q, &e->names) {
                                struct str_el * s =
                                        list_entry(q, struct str_el, next);
                                if (!strcmp(s->str, name))
                                        reg_entry_add_api(re, e->api);
                        }
                }

                list_for_each(p, &irmd->apn_table) {
                        struct list_head * q;
                        struct apn_entry * e =
                                list_entry(p, struct apn_entry, next);
                        list_for_each(q, &e->names) {
                                struct str_el * s =
                                        list_entry(q, struct str_el, next);
                                if (!strcmp(s->str, name))
                                        reg_entry_add_apn(re, e);
                        }
                }
        }

        list_for_each(p, &irmd->ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->dif_name == NULL)
                        continue;

                for (i = 0; i < len; ++i) {
                        if (wildcard_match(difs[i], e->dif_name))
                                continue;

                        if (ipcp_name_reg(e->api, name)) {
                                LOG_ERR("Could not register %s in DIF %s.",
                                        name, e->dif_name);
                        } else {
                                if (registry_add_name_to_dif(&irmd->registry,
                                                             name,
                                                             e->dif_name,
                                                             e->type) < 0)
                                        LOG_WARN("Registered unbound name %s. "
                                                 "Registry may be corrupt.",
                                                 name);
                                LOG_INFO("Registered %s in %s as %s.",
                                         name, e->dif_name, name);
                                ++ret;
                        }
                }
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return (ret > 0 ? 0 : -1);
}

static int name_unreg(char * name, char ** difs, size_t len)
{
        size_t i;
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
                        } else {
                                registry_del_name_from_dif(&irmd->registry,
                                                           name,
                                                           e->dif_name);
                                LOG_INFO("Unregistered %s from %s.",
                                         name, e->dif_name);
                                ++ret;
                        }
                }
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return (ret > 0 ? 0 : -1);
}

static int api_announce(pid_t api, char * apn)
{
        struct api_entry * e = NULL;
        struct apn_entry * a = NULL;
        char * apn_dup;
        if (apn == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -EPERM;
        }

        apn_dup = strdup(apn);
        if (apn_dup == NULL) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -ENOMEM;
        }

        e = api_entry_create(api, apn_dup);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -ENOMEM;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        api_table_add(&irmd->api_table, e);

        /* Copy listen names from apn if it exists. */

        a = apn_table_get(&irmd->apn_table, e->apn);
        if (a != NULL) {
                struct list_head * p;
                list_for_each(p, &a->names) {
                        struct str_el * s = list_entry(p, struct str_el, next);
                        struct str_el * n = malloc(sizeof(*n));
                        if (n == NULL) {
                                pthread_rwlock_unlock(&irmd->reg_lock);
                                pthread_rwlock_unlock(&irmd->state_lock);
                                return -ENOMEM;
                        }
                        n->str = strdup(s->str);
                        if (n->str == NULL) {
                                pthread_rwlock_unlock(&irmd->reg_lock);
                                pthread_rwlock_unlock(&irmd->state_lock);
                                free(n);
                        }

                        list_add(&n->next, &e->names);
                        LOG_DBG("AP-I %d inherits listen name %s from AP %s.",
                                api, n->str, e->apn);
                }
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return 0;
}

static struct irm_flow * flow_accept(pid_t api, char ** dst_ae_name,
                                     qoscube_t * cube)
{
        struct irm_flow *  f  = NULL;
        struct api_entry * e  = NULL;
        struct reg_entry * re = NULL;
        struct list_head * p;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        e = api_table_get(&irmd->api_table, api);
        if (e == NULL) {
                /* Can only happen if server called ap_init(NULL); */
                LOG_ERR("Unknown instance %d calling accept.", api);
                return NULL;
        }

        LOG_DBG("New instance (%d) of %s added.", api, e->apn);
        LOG_DBG("This instance accepts flows for:");
        list_for_each(p, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                LOG_DBG("        %s", s->str);
                re = registry_get_entry(&irmd->registry, s->str);
                if (re != NULL)
                        reg_entry_add_api(re, api);
        }

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        while (api_entry_sleep(e) == -ETIMEDOUT) {
                pthread_rwlock_rdlock(&irmd->state_lock);
                if (irmd->state != IRMD_RUNNING) {
                        pthread_rwlock_unlock(&irmd->state_lock);
                        return NULL;
                }
                pthread_rwlock_unlock(&irmd->state_lock);
        }

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }

        pthread_rwlock_rdlock(&irmd->reg_lock);

        e = api_table_get(&irmd->api_table, api);
        if (e == NULL) {
                LOG_DBG("Process gone while accepting flow.");
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }

        pthread_mutex_lock(&e->state_lock);

        re = e->re;

        pthread_mutex_unlock(&e->state_lock);

        if (reg_entry_get_state(re) != REG_NAME_FLOW_ARRIVED) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }
        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_rdlock(&irmd->flows_lock);

        f = get_irm_flow_n(api);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Port_id was not created yet.");
                return NULL;
        }

        *cube = re->qos;

        if (dst_ae_name != NULL)
                *dst_ae_name = re->req_ae_name;

        LOG_INFO("Flow on port_id %d allocated.", f->port_id);

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return f;
}

static int flow_alloc_resp(pid_t n_api, int port_id, int response)
{
        struct irm_flow *  f  = NULL;
        struct reg_entry * re = NULL;
        struct api_entry * e  = NULL;
        int ret = -1;

        pid_t api_n1;
        pid_t api_n;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd->reg_lock);

        e = api_table_get(&irmd->api_table, n_api);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Unknown AP-I %d responding for port_id %d.",
                        n_api, port_id);
                return -1;
        }

        re = e->re;
        if (re == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("AP-I %d is not handling a flow request.", n_api);
                return -1;
        }

        if (reg_entry_get_state(re) != REG_NAME_FLOW_ARRIVED) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Name %s has no pending flow request.", re->name);
                return -1;
        }

        registry_del_api(&irmd->registry, n_api);

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_wrlock(&irmd->flows_lock);

        f = get_irm_flow(port_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        api_n  = f->n_api;
        api_n1 = f->n_1_api;

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        ret = ipcp_flow_alloc_resp(api_n1, port_id, api_n, response);

        if (!(response || ret))
                irm_flow_set_state(f, FLOW_ALLOCATED);

        return ret;
}

static struct irm_flow * flow_alloc(pid_t api, char * dst_name,
                                    char * src_ae_name, qoscube_t cube)
{
        struct irm_flow * f;
        pid_t ipcp;
        int port_id;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }

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
        port_id = bmp_allocate(irmd->port_ids);
        if (!bmp_is_id_valid(irmd->port_ids, port_id)) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Could not allocate port_id.");
                return NULL;
        }

        f = irm_flow_create(api, ipcp, port_id);
        if (f == NULL) {
                bmp_release(irmd->port_ids, port_id);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Could not allocate port_id.");
                return NULL;
        }

        list_add(&f->next, &irmd->irm_flows);

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        if (ipcp_flow_alloc(ipcp, port_id, api,
                            dst_name, src_ae_name, cube) < 0) {
                pthread_rwlock_rdlock(&irmd->state_lock);
                pthread_rwlock_wrlock(&irmd->flows_lock);
                list_del(&f->next);
                clear_irm_flow(f);
                bmp_release(irmd->port_ids, f->port_id);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                irm_flow_destroy(f);
                return NULL;
        }

        return f;
}

static int flow_alloc_res(int port_id)
{
        struct irm_flow * f;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_RUNNING) {
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }
        pthread_rwlock_rdlock(&irmd->flows_lock);

        f = get_irm_flow(port_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Could not find port %d.", port_id);
                return -1;
        }

        if (irm_flow_get_state(f) == FLOW_NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_INFO("Port %d is deprecated.", port_id);
                return -1;
        }

        if (irm_flow_get_state(f) == FLOW_ALLOCATED) {
                LOG_INFO("Flow on port_id %d allocated.", port_id);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return 0;
        }

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        if (irm_flow_wait_state(f, FLOW_ALLOCATED) == FLOW_ALLOCATED) {
                LOG_INFO("Flow on port_id %d allocated.", port_id);
                return 0;
        }

        LOG_INFO("Pending flow on port_id %d torn down.", port_id);

        return -1;
}

static int flow_dealloc(pid_t api, int port_id)
{
        pid_t n_1_api = -1;
        int   ret = 0;

        struct irm_flow * f = NULL;

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_wrlock(&irmd->flows_lock);

        f = get_irm_flow(port_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_DBG("Deallocate unknown port %d by %d.", port_id, api);
                return 0;
        }

        if (api == f->n_api) {
                f->n_api = -1;
                n_1_api = f->n_1_api;
        } else if (api == f->n_1_api) {
                f->n_1_api = -1;
        } else {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_DBG("Dealloc called by wrong AP-I.");
                return -EPERM;
        }

        if (irm_flow_get_state(f) == FLOW_DEALLOC_PENDING) {
                list_del(&f->next);
                clear_irm_flow(f);
                irm_flow_destroy(f);
                bmp_release(irmd->port_ids, port_id);
                LOG_INFO("Completed deallocation of port_id %d by AP-I %d.",
                         port_id, api);
        } else {
                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                LOG_DBG("Partial deallocation of port_id %d by AP-I %d.",
                        port_id, api);
        }

        pthread_rwlock_unlock(&irmd->flows_lock);

        if (n_1_api != -1)
                ret = ipcp_flow_dealloc(n_1_api, port_id);

        pthread_rwlock_unlock(&irmd->state_lock);

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

        api = fork();
        if (api == -1) {
                LOG_ERR("Failed to fork");
                return api;
        }

        if (api != 0) {
                LOG_INFO("Instantiated %s as AP-I %d.", argv[0], api);
                return api;
        }

        execv(argv[0], argv);

        LOG_ERR("Failed to execute %s.", argv[0]);

        exit(EXIT_FAILURE);
}

static struct irm_flow * flow_req_arr(pid_t api, char * dst_name,
                                      char * ae_name, qoscube_t cube)
{
        struct reg_entry * re = NULL;
        struct apn_entry * a  = NULL;
        struct api_entry * e  = NULL;
        struct irm_flow *  f  = NULL;

        struct pid_el * c_api;
        pid_t h_api = -1;
        int port_id = -1;

        LOG_DBGF("Flow req arrived from IPCP %d for %s on AE %s.",
                 api, dst_name, ae_name);

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_wrlock(&irmd->reg_lock);

        re = registry_get_entry(&irmd->registry, dst_name);
        if (re == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Unknown name: %s.", dst_name);
                return NULL;
        }

        switch (reg_entry_get_state(re)) {
        case REG_NAME_IDLE:
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("No APs for %s.", dst_name);
                return NULL;
        case REG_NAME_AUTO_ACCEPT:
                c_api = malloc(sizeof(*c_api));
                if (c_api == NULL) {
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        return NULL;
                }

                reg_entry_set_state(re, REG_NAME_AUTO_EXEC);
                a = apn_table_get_by_apn(&irmd->apn_table,
                                         reg_entry_get_apn(re));

                if (a == NULL || (c_api->pid = auto_execute(a->argv)) < 0) {
                        reg_entry_set_state(re, REG_NAME_AUTO_ACCEPT);
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        LOG_ERR("Could not get start apn for reg_entry %s.",
                                re->name);
                        free(c_api);
                        return NULL;
                }

                list_add(&c_api->next, &irmd->spawned_apis);

                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_unlock(&irmd->state_lock);

                reg_entry_leave_state(re, REG_NAME_AUTO_EXEC);

                pthread_rwlock_rdlock(&irmd->state_lock);
                pthread_rwlock_rdlock(&irmd->reg_lock);

                if (reg_entry_get_state(re) == REG_NAME_DESTROY) {
                        reg_entry_set_state(re, REG_NAME_NULL);
                        pthread_rwlock_unlock(&irmd->reg_lock);
                        pthread_rwlock_unlock(&irmd->state_lock);
                        return NULL;
                }
        case REG_NAME_FLOW_ACCEPT:
                h_api = reg_entry_get_api(re);
                if (h_api == -1) {
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
                return NULL;
        }


        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_wrlock(&irmd->flows_lock);
        port_id = bmp_allocate(irmd->port_ids);
        if (!bmp_is_id_valid(irmd->port_ids, port_id)) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return NULL;
        }

        f = irm_flow_create(h_api, api, port_id);
        if (f == NULL) {
                bmp_release(irmd->port_ids, port_id);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Could not allocate port_id.");
                return NULL;
        }

        list_add(&f->next, &irmd->irm_flows);

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_rdlock(&irmd->reg_lock);

        re->req_ae_name = ae_name;
        re->qos = cube;
        reg_entry_set_state(re, REG_NAME_FLOW_ARRIVED);

        e = api_table_get(&irmd->api_table, h_api);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_wrlock(&irmd->flows_lock);
                clear_irm_flow(f);
                bmp_release(irmd->port_ids, f->port_id);
                list_del(&f->next);
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                LOG_ERR("Could not get api table entry for %d.", h_api);
                irm_flow_destroy(f);
                return NULL;
        }

        api_entry_wake(e, re);

        pthread_rwlock_unlock(&irmd->reg_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        reg_entry_leave_state(re, REG_NAME_FLOW_ARRIVED);

        return f;
}

static int flow_alloc_reply(int port_id, int response)
{
        struct irm_flow * f;

        pthread_rwlock_rdlock(&irmd->state_lock);
        pthread_rwlock_wrlock(&irmd->flows_lock);

        f = get_irm_flow(port_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);
                return -1;
        }

        if (!response)
                irm_flow_set_state(f, FLOW_ALLOCATED);
        else
                irm_flow_set_state(f, FLOW_NULL);

        pthread_rwlock_unlock(&irmd->flows_lock);
        pthread_rwlock_unlock(&irmd->state_lock);

        return 0;
}

static void irm_destroy(void)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_rdlock(&irmd->state_lock);

        if (irmd->state != IRMD_NULL)
                LOG_WARN("Unsafe destroy.");

        if (irmd->threadpool != NULL)
                free(irmd->threadpool);

        pthread_rwlock_wrlock(&irmd->flows_lock);

        list_for_each_safe(p, h, &irmd->irm_flows) {
                struct irm_flow * f = list_entry(p, struct irm_flow, next);
                list_del(&f->next);
                clear_irm_flow(f);
                irm_flow_destroy(f);
        }

        close(irmd->sockfd);

        if (unlink(IRM_SOCK_PATH))
                LOG_DBG("Failed to unlink %s.", IRM_SOCK_PATH);

        pthread_rwlock_wrlock(&irmd->reg_lock);
        /* Clear the lists. */
        list_for_each_safe(p, h, &irmd->ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                list_del(&e->next);
                ipcp_destroy(e->api);
                clear_spawned_api(e->api);
                ipcp_entry_destroy(e);
        }

        registry_destroy(&irmd->registry);

        list_for_each_safe(p, h, &irmd->spawned_apis) {
                struct pid_el * e = list_entry(p, struct pid_el, next);
                int status;
                if (kill(e->pid, SIGTERM))
                        LOG_DBG("Could not send kill signal to %d.", e->pid);
                else if (waitpid(e->pid, &status, 0) < 0)
                        LOG_DBG("Error waiting for %d to exit.", e->pid);
                list_del(&e->next);
                free(e);
        }

        list_for_each_safe(p, h, &irmd->apn_table) {
                struct apn_entry * e = list_entry(p, struct apn_entry, next);
                list_del(&e->next);
                apn_entry_destroy(e);
        }

        list_for_each_safe(p, h, &irmd->api_table) {
                struct api_entry * e = list_entry(p, struct api_entry, next);
                list_del(&e->next);
                api_entry_destroy(e);
        }

        pthread_rwlock_unlock(&irmd->reg_lock);

        if (irmd->port_ids != NULL)
                bmp_destroy(irmd->port_ids);

        pthread_rwlock_unlock(&irmd->flows_lock);

        if (irmd->rdrb != NULL)
                shm_rdrbuff_destroy(irmd->rdrb);

        if (irmd->lf != NULL)
                lockfile_destroy(irmd->lf);

        pthread_rwlock_unlock(&irmd->state_lock);

        pthread_rwlock_destroy(&irmd->reg_lock);
        pthread_rwlock_destroy(&irmd->state_lock);

        free(irmd);
}

void irmd_sig_handler(int sig, siginfo_t * info, void * c)
{
        (void) info;
        (void) c;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                LOG_INFO("IRMd shutting down...");

                pthread_rwlock_wrlock(&irmd->state_lock);

                irmd->state = IRMD_NULL;

                pthread_rwlock_unlock(&irmd->state_lock);
                break;
        case SIGPIPE:
                LOG_DBG("Ignored SIGPIPE.");
        default:
                return;
        }
}

void * shm_sanitize(void * o)
{
        struct list_head * p = NULL;
        struct timespec ts = {SHM_SAN_HOLDOFF / 1000,
                              (SHM_SAN_HOLDOFF % 1000) * MILLION};
        ssize_t idx;

        (void) o;

        while (true) {
                shm_rdrbuff_wait_full(irmd->rdrb);

                pthread_rwlock_rdlock(&irmd->state_lock);
                pthread_rwlock_wrlock(&irmd->flows_lock);

                list_for_each(p, &irmd->irm_flows) {
                        struct irm_flow * f =
                                list_entry(p, struct irm_flow, next);
                        if (kill(f->n_api, 0) < 0) {
                                while ((idx = shm_rbuff_read(f->n_rb)) >= 0)
                                        shm_rdrbuff_remove(irmd->rdrb, idx);
                                continue;
                        }

                        if (kill(f->n_1_api, 0) < 0) {
                                while ((idx = shm_rbuff_read(f->n_1_rb)) >= 0)
                                        shm_rdrbuff_remove(irmd->rdrb, idx);
                                continue;
                        }
                }

                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);

                nanosleep(&ts, NULL);
        }

        return (void *) 0;
}

void * irm_sanitize(void * o)
{
        struct timespec now;
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        struct timespec timeout = {IRMD_CLEANUP_TIMER / BILLION,
                                   IRMD_CLEANUP_TIMER % BILLION};
        int s;

        (void) o;

        while (true) {
                if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
                        LOG_WARN("Failed to get time.");
                /* Cleanup stale PENDING flows. */

                pthread_rwlock_rdlock(&irmd->state_lock);

                if (irmd->state != IRMD_RUNNING) {
                        pthread_rwlock_unlock(&irmd->state_lock);
                        return (void *) 0;
                }

                pthread_rwlock_wrlock(&irmd->reg_lock);

                list_for_each_safe(p, h, &irmd->spawned_apis) {
                        struct pid_el * e = list_entry(p, struct pid_el, next);
                        waitpid(e->pid, &s, WNOHANG);
                        if (kill(e->pid, 0) >= 0)
                                continue;
                        LOG_DBG("Child process %d died, error %d.", e->pid, s);
                        list_del(&e->next);
                        free(e);
                }

                list_for_each_safe(p, h, &irmd->api_table) {
                        struct api_entry * e =
                                list_entry(p, struct api_entry, next);
                        if (kill(e->api, 0) >= 0)
                                continue;
                        LOG_DBG("Dead AP-I removed: %d.", e->api);
                        list_del(&e->next);
                        api_entry_destroy(e);
                }

                list_for_each_safe(p, h, &irmd->ipcps) {
                        struct ipcp_entry * e =
                                list_entry(p, struct ipcp_entry, next);
                        if (kill(e->api, 0) >= 0)
                                continue;
                        LOG_DBG("Dead IPCP removed: %d.", e->api);
                        list_del(&e->next);
                        ipcp_entry_destroy(e);
                }

                list_for_each_safe(p, h, &irmd->registry) {
                        struct list_head * p2;
                        struct list_head * h2;
                        struct reg_entry * e =
                                list_entry(p, struct reg_entry, next);
                        list_for_each_safe(p2, h2, &e->reg_apis) {
                                struct pid_el * a =
                                        list_entry(p2, struct pid_el, next);
                                if (kill(a->pid, 0) >= 0)
                                        continue;
                                LOG_DBG("Dead AP-I removed from: %d %s.",
                                        a->pid, e->name);
                                reg_entry_del_api(e, a->pid);
                        }
                }

                pthread_rwlock_unlock(&irmd->reg_lock);
                pthread_rwlock_wrlock(&irmd->flows_lock);

                list_for_each_safe(p, h, &irmd->irm_flows) {
                        struct irm_flow * f =
                                list_entry(p, struct irm_flow, next);

                        if (irm_flow_get_state(f) == FLOW_ALLOC_PENDING
                            && ts_diff_ms(&f->t0, &now) > IRMD_FLOW_TIMEOUT) {
                                list_del(&f->next);
                                LOG_DBG("Pending port_id %d timed out.",
                                         f->port_id);
                                clear_irm_flow(f);
                                ipcp_flow_dealloc(f->n_1_api, f->port_id);
                                bmp_release(irmd->port_ids, f->port_id);
                                irm_flow_destroy(f);
                                continue;
                        }

                        if (kill(f->n_api, 0) < 0) {
                                struct shm_flow_set * set;
                                LOG_DBG("AP-I %d gone, flow %d deallocated.",
                                         f->n_api, f->port_id);
                                set = shm_flow_set_open(f->n_api);
                                if (set != NULL)
                                        shm_flow_set_destroy(set);
                                f->n_api = -1;
                                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                                ipcp_flow_dealloc(f->n_1_api, f->port_id);
                                clear_irm_flow(f);
                                continue;
                        }

                        if (kill(f->n_1_api, 0) < 0) {
                                struct shm_flow_set * set;
                                list_del(&f->next);
                                LOG_ERR("IPCP %d gone, flow %d removed.",
                                        f->n_1_api, f->port_id);
                                set = shm_flow_set_open(f->n_api);
                                if (set != NULL)
                                        shm_flow_set_destroy(set);

                                clear_irm_flow(f);
                                bmp_release(irmd->port_ids, f->port_id);
                                irm_flow_destroy(f);
                        }
                }

                pthread_rwlock_unlock(&irmd->flows_lock);
                pthread_rwlock_unlock(&irmd->state_lock);

                nanosleep(&timeout, NULL);
        }
}

void * mainloop(void * o)
{
        uint8_t buf[IRM_MSG_BUF_SIZE];

        (void) o;

        while (true) {
#ifdef __FreeBSD__
                fd_set fds;
                struct timeval timeout = {(IRMD_ACCEPT_TIMEOUT / 1000),
                                          (IRMD_ACCEPT_TIMEOUT % 1000) * 1000};
#endif
                int cli_sockfd;
                irm_msg_t * msg;
                ssize_t count;
                buffer_t buffer;
                irm_msg_t ret_msg = IRM_MSG__INIT;
                struct irm_flow * e = NULL;
                pid_t * apis = NULL;
                struct timeval tv = {(SOCKET_TIMEOUT / 1000),
                                     (SOCKET_TIMEOUT % 1000) * 1000};

                pthread_rwlock_rdlock(&irmd->state_lock);
                if (irmd->state != IRMD_RUNNING) {
                        pthread_rwlock_unlock(&irmd->state_lock);
                        break;
                }
                pthread_rwlock_unlock(&irmd->state_lock);

                ret_msg.code = IRM_MSG_CODE__IRM_REPLY;
#ifdef __FreeBSD__
                FD_ZERO(&fds);
                FD_SET(irmd->sockfd, &fds);
                if (select(irmd->sockfd, &fds, NULL, NULL, &timeout) <= 0)
                        continue;
#endif
                cli_sockfd = accept(irmd->sockfd, 0, 0);
                if (cli_sockfd < 0)
                        continue;

                if (setsockopt(cli_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                               (void *) &tv, sizeof(tv)))
                        LOG_WARN("Failed to set timeout on socket.");

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

                switch (msg->code) {
                case IRM_MSG_CODE__IRM_CREATE_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = create_ipcp(msg->dst_name,
                                                     msg->ipcp_type);
                        break;
                case IRM_MSG_CODE__IPCP_CREATE_R:
                        ret_msg.has_result = true;
                        ret_msg.result = create_ipcp_r(msg->api);
                        break;
                case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = destroy_ipcp(msg->api);
                        break;
                case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = bootstrap_ipcp(msg->api, msg->conf);
                        break;
                case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = enroll_ipcp(msg->api,
                                                     msg->dif_name[0]);
                        break;
                case IRM_MSG_CODE__IRM_BIND_AP:
                        ret_msg.has_result = true;
                        ret_msg.result = bind_ap(msg->ap_name,
                                                 msg->dst_name,
                                                 msg->opts,
                                                 msg->n_args,
                                                 msg->args);
                        break;
                case IRM_MSG_CODE__IRM_UNBIND_AP:
                        ret_msg.has_result = true;
                        ret_msg.result = unbind_ap(msg->ap_name, msg->dst_name);
                        break;
                case IRM_MSG_CODE__IRM_API_ANNOUNCE:
                        ret_msg.has_result = true;
                        ret_msg.result = api_announce(msg->api, msg->ap_name);
                        break;
                case IRM_MSG_CODE__IRM_BIND_API:
                        ret_msg.has_result = true;
                        ret_msg.result = bind_api(msg->api, msg->dst_name);
                        break;
                case IRM_MSG_CODE__IRM_UNBIND_API:
                        ret_msg.has_result = true;
                        ret_msg.result = unbind_api(msg->api, msg->dst_name);
                        break;
                case IRM_MSG_CODE__IRM_LIST_IPCPS:
                        ret_msg.n_apis = list_ipcps(msg->dst_name, &apis);
                        ret_msg.apis = apis;
                        ret_msg.has_result = true;
                        break;
                case IRM_MSG_CODE__IRM_REG:
                        ret_msg.has_result = true;
                        ret_msg.result = name_reg(msg->dst_name,
                                                  msg->dif_name,
                                                  msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_UNREG:
                        ret_msg.has_result = true;
                        ret_msg.result = name_unreg(msg->dst_name,
                                                    msg->dif_name,
                                                    msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ACCEPT:
                        ret_msg.has_qoscube = true;
                        e = flow_accept(msg->api,
                                        &ret_msg.ae_name,
                                        (qoscube_t *) &ret_msg.qoscube);
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
                                       msg->qoscube);
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
                        ret_msg.result = flow_dealloc(msg->api, msg->port_id);
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_REQ_ARR:
                        e = flow_req_arr(msg->api,
                                         msg->dst_name,
                                         msg->ae_name,
                                         msg->qoscube);
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
                default:
                        LOG_ERR("Don't know that message code.");
                        break;
                }

                irm_msg__free_unpacked(msg, NULL);

                buffer.len = irm_msg__get_packed_size(&ret_msg);
                if (buffer.len == 0) {
                        LOG_ERR("Failed to calculate length of reply message.");
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

                if (apis != NULL)
                        free(apis);

                if (write(cli_sockfd, buffer.data, buffer.len) == -1)
                        LOG_WARN("Failed to send reply message.");

                free(buffer.data);
                close(cli_sockfd);
        }

        return (void *) 0;
}

static int irm_create(void)
{
        struct stat st;
        struct timeval timeout = {(IRMD_ACCEPT_TIMEOUT / 1000),
                                  (IRMD_ACCEPT_TIMEOUT % 1000) * 1000};

        irmd = malloc(sizeof(*irmd));
        if (irmd == NULL)
                return -ENOMEM;

        memset(&st, 0, sizeof(st));

        irmd->state = IRMD_NULL;

        if (pthread_rwlock_init(&irmd->state_lock, NULL)) {
                LOG_ERR("Failed to initialize rwlock.");
                free(irmd);
                return -1;
        }

        if (pthread_rwlock_init(&irmd->reg_lock, NULL)) {
                LOG_ERR("Failed to initialize rwlock.");
                free(irmd);
                return -1;
        }

        if (pthread_rwlock_init(&irmd->flows_lock, NULL)) {
                LOG_ERR("Failed to initialize rwlock.");
                free(irmd);
                return -1;
        }

        INIT_LIST_HEAD(&irmd->ipcps);
        INIT_LIST_HEAD(&irmd->api_table);
        INIT_LIST_HEAD(&irmd->apn_table);
        INIT_LIST_HEAD(&irmd->spawned_apis);
        INIT_LIST_HEAD(&irmd->registry);
        INIT_LIST_HEAD(&irmd->irm_flows);

        irmd->port_ids = bmp_create(IRMD_MAX_FLOWS, 0);
        if (irmd->port_ids == NULL) {
                irm_destroy();
                return -ENOMEM;
        }

        irmd->threadpool = malloc(sizeof(pthread_t) * IRMD_THREADPOOL_SIZE);
        if (irmd->threadpool == NULL) {
                irm_destroy();
                return -ENOMEM;
        }

        if (stat(SOCK_PATH, &st) == -1) {
                if (mkdir(SOCK_PATH, 0777)) {
                        LOG_ERR("Failed to create sockets directory.");
                        irm_destroy();
                        return -1;
                }
        }

        irmd->sockfd = server_socket_open(IRM_SOCK_PATH);
        if (irmd->sockfd < 0) {
                irm_destroy();
                return -1;
        }

        if (setsockopt(irmd->sockfd, SOL_SOCKET, SO_RCVTIMEO,
                       (char *) &timeout, sizeof(timeout)) < 0) {
                LOG_ERR("Failed setting socket option.");
                irm_destroy();
                return -1;
        }

        if (chmod(IRM_SOCK_PATH, 0666)) {
                LOG_ERR("Failed to chmod socket.");
                irm_destroy();
                return -1;
        }

        if ((irmd->lf = lockfile_create()) == NULL) {
                if ((irmd->lf = lockfile_open()) == NULL) {
                        LOG_ERR("Lockfile error.");
                        irm_destroy();
                        return -1;
                }

                if (kill(lockfile_owner(irmd->lf), 0) < 0) {
                        LOG_INFO("IRMd didn't properly shut down last time.");
                        shm_rdrbuff_destroy(shm_rdrbuff_open());
                        LOG_INFO("Stale resources cleaned.");
                        lockfile_destroy(irmd->lf);
                        irmd->lf = lockfile_create();
                } else {
                        LOG_INFO("IRMd already running (%d), exiting.",
                                 lockfile_owner(irmd->lf));
                        lockfile_close(irmd->lf);
                        free(irmd);
                        return -1;
                }
        }

        if (irmd->lf == NULL) {
                irm_destroy();
                return -1;
        }

        if ((irmd->rdrb = shm_rdrbuff_create()) == NULL) {
                irm_destroy();
                return -1;
        }

        irmd->state = IRMD_RUNNING;

        LOG_INFO("Ouroboros IPC Resource Manager daemon started...");

        return 0;
}

static void usage(void)
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
                                LOG_ERR("Failed to malloc.");
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

        if (!use_stdout && (set_logfile(log_file) < 0))
                LOG_ERR("Cannot open %s, falling back to stdout for logs.",
                        log_file);

        /* Init sig_act. */
        memset(&sig_act, 0, sizeof sig_act);

        /* Install signal traps. */
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

        if (irm_create() < 0) {
                close_logfile();
                exit(EXIT_FAILURE);
        }

        for (t = 0; t < IRMD_THREADPOOL_SIZE; ++t)
                pthread_create(&irmd->threadpool[t], NULL, mainloop, NULL);

        pthread_create(&irmd->irm_sanitize, NULL, irm_sanitize, NULL);
        pthread_create(&irmd->shm_sanitize, NULL,
                       shm_sanitize, irmd->rdrb);

        /* Wait for (all of them) to return. */
        for (t = 0; t < IRMD_THREADPOOL_SIZE; ++t)
                pthread_join(irmd->threadpool[t], NULL);

        pthread_join(irmd->irm_sanitize, NULL);

        pthread_cancel(irmd->shm_sanitize);
        pthread_join(irmd->shm_sanitize, NULL);

        irm_destroy();

        close_logfile();

        LOG_INFO("Bye.");

        exit(EXIT_SUCCESS);
}
