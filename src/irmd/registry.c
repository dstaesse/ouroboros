/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager - Registry
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#include "registry.h"

#include <ouroboros/config.h>

#define OUROBOROS_PREFIX "registry"

#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/irm_config.h>

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define reg_entry_has_auto_binding(e)  (reg_entry_get_auto_info(e) != NULL)
#define reg_entry_has_api(e, api)      (reg_entry_get_reg_api(e, api) != NULL)
#define reg_entry_has_binding(e, name) (reg_entry_get_binding(e, name) != NULL)


struct reg_binding {
        struct list_head next;
        char *           apn;
        uint32_t         flags;
        char **          argv;
};

struct reg_dif {
        struct list_head next;
        char *           dif_name;
        enum ipcp_type   type;
};

struct reg_api * reg_api_create(pid_t api)
{
        struct reg_api * i;
        i = malloc(sizeof(*i));
        if (i == NULL)
                return NULL;

        i->api   = api;
        i->state = REG_I_WAKE;

        pthread_mutex_init(&i->mutex, NULL);
        pthread_cond_init(&i->cond_state, NULL);

        INIT_LIST_HEAD(&i->next);

        return i;
}

void reg_api_destroy(struct reg_api * i)
{
        pthread_mutex_lock(&i->mutex);

        if (i->state != REG_I_SLEEP)
                i->state = REG_I_WAKE;
        else
                i->state = REG_I_NULL;

        pthread_cond_broadcast(&i->cond_state);
        pthread_mutex_unlock(&i->mutex);

        while (i->state != REG_I_WAKE)
                ;

        pthread_mutex_destroy(&i->mutex);

        free(i);
}

void reg_api_sleep(struct reg_api * i)
{
        pthread_mutex_lock(&i->mutex);
        if (i->state != REG_I_WAKE) {
                pthread_mutex_unlock(&i->mutex);
                return;
        }

        i->state = REG_I_SLEEP;

        pthread_cleanup_push((void(*)(void *)) pthread_mutex_unlock,
                             (void *) &i->mutex);

        while (i->state == REG_I_SLEEP)
                pthread_cond_wait(&i->cond_state, &i->mutex);

        i->state = REG_I_WAKE;
        pthread_cond_signal(&i->cond_state);

        pthread_cleanup_pop(true);
}

void reg_api_wake(struct reg_api * i)
{
        pthread_mutex_lock(&i->mutex);

        if (i->state == REG_I_NULL) {
                pthread_mutex_unlock(&i->mutex);
                return;
        }

        i->state = REG_I_WAKE;

        pthread_cond_signal(&i->cond_state);
        pthread_mutex_unlock(&i->mutex);
}

struct reg_binding * reg_binding_create(char *   apn,
                                        uint32_t flags,
                                        char **  argv)
{
        struct reg_binding * b = malloc(sizeof(*b));
        if (b == NULL)
                return NULL;

        INIT_LIST_HEAD(&b->next);

        b->apn   = apn;
        b->flags = flags;
        b->argv  = argv;

        return b;
}

void reg_binding_destroy(struct reg_binding * b)
{
        if (b == NULL)
                return;

        if (b->argv != NULL) {
                char ** t = b->argv;
                while (*t != NULL)
                        free(*t++);
                free(b->argv);
        }

        free(b->apn);
        free(b);
}

struct reg_entry * reg_entry_create()
{
        struct reg_entry * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->name         = NULL;
        e->state        = REG_NAME_NULL;

        e->req_ae_name  = NULL;
        e->response     = -1;

        return e;
}

struct reg_entry * reg_entry_init(struct reg_entry * e,
                                  char *             name)
{
        if (e == NULL || name == NULL)
                return NULL;

        INIT_LIST_HEAD(&e->next);
        INIT_LIST_HEAD(&e->difs);
        INIT_LIST_HEAD(&e->bindings);
        INIT_LIST_HEAD(&e->reg_apis);

        e->name = name;

        if (pthread_cond_init(&e->acc_signal, NULL))
                return NULL;

        if (pthread_mutex_init(&e->state_lock, NULL))
                return NULL;

        e->state = REG_NAME_IDLE;

        return e;
}

void reg_entry_destroy(struct reg_entry * e)
{
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        bool wait = true;

        if (e == NULL)
                return;

        pthread_mutex_lock(&e->state_lock);

        e->state = REG_NAME_NULL;

        pthread_cond_broadcast(&e->acc_signal);
        pthread_mutex_unlock(&e->state_lock);

        while (wait) {
                pthread_mutex_lock(&e->state_lock);
                if (pthread_cond_destroy(&e->acc_signal))
                        pthread_cond_broadcast(&e->acc_signal);
                else
                        wait = false;
                pthread_mutex_unlock(&e->state_lock);
        }

        pthread_mutex_destroy(&e->state_lock);

        if (e->name != NULL)
                free(e->name);

        if (e->req_ae_name != NULL)
                free(e->req_ae_name);

        list_for_each_safe(pos, n, &e->reg_apis) {
                struct reg_api * i = list_entry(pos, struct reg_api, next);
                reg_api_destroy(i);
        }

        list_for_each_safe(pos, n, &e->bindings) {
                struct reg_binding * b =
                        list_entry(pos, struct reg_binding, next);
                reg_binding_destroy(b);
        }

        list_for_each_safe(pos, n, &e->difs) {
                struct reg_dif * d =
                        list_entry(pos, struct reg_dif, next);
                free(d->dif_name);
                free(d);
        }

        free(e);
}

bool reg_entry_is_local_in_dif(struct reg_entry * e,
                               char *             dif_name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &e->difs) {
                struct reg_dif * d =
                        list_entry(pos, struct reg_dif, next);

                if (!strcmp(dif_name, d->dif_name))
                        return true;
        }

        return false;
}

int reg_entry_add_local_in_dif(struct reg_entry * e,
                               char *             dif_name,
                               enum ipcp_type     type)
{
        if (!reg_entry_is_local_in_dif(e, dif_name)) {
                struct reg_dif * rdn = malloc(sizeof(*rdn));
                rdn->dif_name = strdup(dif_name);
                if (rdn->dif_name == NULL)
                        return -1;
                rdn->type = type;
                list_add(&rdn->next, &e->difs);
                return 0;
        }

        return 0; /* already registered. Is ok */
}

void reg_entry_del_local_from_dif(struct reg_entry * e,
                                  char *             dif_name)
{
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        list_for_each_safe(pos, n, &e->difs) {
                struct reg_dif * d =
                        list_entry(pos, struct reg_dif, next);

                if (!strcmp(dif_name, d->dif_name)) {
                        list_del(&d->next);
                        free(d);
                }
        }
}

struct reg_binding * reg_entry_get_binding(struct reg_entry * e,
                                           char *             apn)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &e->bindings) {
                struct reg_binding * n =
                        list_entry(pos, struct reg_binding, next);

                if (strcmp(apn, n->apn) == 0)
                        return n;
        }

        return NULL;
}

void reg_entry_del_binding(struct reg_entry * e,
                           char *             apn)
{
        struct reg_binding * b = reg_entry_get_binding(e, apn);
        if (b == NULL)
                return;

        list_del(&b->next);
        free(b);
}

struct reg_binding * reg_entry_add_binding(struct reg_entry * e,
                                           char *             apn,
                                           uint32_t           flags,
                                           char **            argv)
{
        struct reg_binding * b;
        if ((b = reg_entry_get_binding(e, apn)) != NULL) {
                LOG_DBG("Updating AP name %s binding with %s.",
                        apn, e->name);
                reg_entry_del_binding(e, b->apn);
        }

        if (flags & BIND_AP_AUTO) {
                b = reg_binding_create(apn, flags, argv);
                if (e->state == REG_NAME_IDLE)
                        e->state = REG_NAME_AUTO_ACCEPT;
        } else {
                flags &= ~BIND_AP_AUTO;
                b = reg_binding_create(apn, flags, NULL);
        }

        list_add(&b->next, &e->bindings);

        return b;
}

char ** reg_entry_get_auto_info(struct reg_entry * e)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &e->bindings) {
                struct reg_binding * b =
                        list_entry(pos, struct reg_binding, next);
                if (b->flags & BIND_AP_AUTO)
                    return b->argv;
        }

        return NULL;
}

struct reg_api * reg_entry_get_reg_api(struct reg_entry * e,
                                       pid_t              api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &e->reg_apis) {
                struct reg_api * r =
                        list_entry(pos, struct reg_api, next);

                if (r->api == api)
                        return r;
        }

        return NULL;
}

pid_t reg_entry_resolve_api(struct reg_entry * e)
{
        struct list_head * pos = NULL;

        /* FIXME: now just returns the first accepting instance */
        list_for_each(pos, &e->reg_apis) {
                struct reg_api * r =
                        list_entry(pos, struct reg_api, next);
                return r->api;
        }

        return -1;
}

struct reg_entry * registry_get_entry_by_name(struct list_head * registry,
                                              char *             name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, registry) {
                struct reg_entry * e =
                        list_entry(pos, struct reg_entry, next);

                if (strcmp(name, e->name) == 0)
                        return e;
        }

        return NULL;
}

struct reg_entry * registry_get_entry_by_apn(struct list_head * registry,
                                             char *             apn)
{
        struct list_head * pos = NULL;

        list_for_each(pos, registry) {
                struct list_head * p = NULL;
                struct reg_entry * e =
                        list_entry(pos, struct reg_entry, next);

                list_for_each(p, &e->bindings) {
                        struct reg_binding * b =
                                list_entry(p, struct reg_binding, next);

                        if (strcmp(b->apn, apn) == 0)
                                return e;
                }
        }

        return NULL;
}

struct reg_entry * registry_get_entry_by_api(struct list_head * registry,
                                             pid_t              api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, registry) {
                struct list_head * p = NULL;
                struct reg_entry * e =
                        list_entry(pos, struct reg_entry, next);

                list_for_each(p, &e->reg_apis) {
                        struct reg_api * r =
                                list_entry(p, struct reg_api, next);

                        if (r->api == api)
                                return e;
                }
        }

        return NULL;
}

struct reg_entry * registry_assign(struct list_head * registry,
                                   char *             name)
{
        struct reg_entry * e = NULL;

        if (name == NULL)
                return NULL;

        if (registry_has_name(registry, name)) {
                LOG_DBG("Name %s already registered.", name);
                return NULL;
        }

        e = reg_entry_create();
        if (e == NULL) {
                LOG_DBG("Could not create registry entry.");
                return NULL;
        }

        e = reg_entry_init(e, name);
        if (e == NULL) {
                LOG_DBG("Could not initialize registry entry.");
                reg_entry_destroy(e);
                return NULL;
        }

        list_add(&e->next, registry);

        return e;
}

void registry_deassign(struct list_head * registry,
                       char *             name)
{
        struct reg_entry * e = registry_get_entry_by_name(registry, name);
        if (e == NULL)
                return;

        list_del(&e->next);
        reg_entry_destroy(e);

        return;
}

int registry_add_binding(struct list_head * registry,
                         char *             name,
                         char *             apn,
                         uint32_t           flags,
                         char **            argv)
{
        struct reg_entry * e;

        if (name == NULL || apn == NULL)
                return -EINVAL;

        e = registry_get_entry_by_name(registry, name);
        if (e == NULL) {
                LOG_DBG("Adding new name to registry: %s.", name);
                e = registry_assign(registry, name);
        }

        if (e->state == REG_NAME_NULL) {
                LOG_DBG("Tried to add binding in NULL state.");
                return -1;
        }

        if(reg_entry_add_binding(e, apn, flags, argv) == NULL)
                return -1;

        return 0;
}


void registry_del_binding(struct list_head * registry,
                          char *             name,
                          char *             apn)
{
        struct reg_entry *   e = NULL;

        if (name == NULL || apn == NULL)
                return;

        e = registry_get_entry_by_name(registry, name);
        if (e == NULL) {
                LOG_DBG("Name %s not found in registry.", name);
                return;
        }

        reg_entry_del_binding(e, apn);

        if (e->state == REG_NAME_AUTO_ACCEPT && !reg_entry_has_auto_binding(e))
                e->state = REG_NAME_IDLE;

        return;
}


struct reg_api * registry_add_api_name(struct list_head * registry,
                                       pid_t              api,
                                       char *             name)
{
        struct reg_entry * e = NULL;
        struct reg_api *   i = NULL;

        if (name == NULL || api == -1)
                return NULL;

        e = registry_get_entry_by_name(registry, name);
        if (e == NULL) {
                LOG_DBG("Name %s not found in registry.", name);
                return NULL;
        }

        if (e->state == REG_NAME_NULL) {
                LOG_DBG("Tried to add instance in NULL state.");
                return NULL;
        }

        if (reg_entry_has_api(e, api)) {
                LOG_DBG("Instance already registered with this name.");
                return NULL;
        }

        i = reg_api_create(api);
        if (i == NULL) {
                LOG_DBG("Failed to create reg_instance");
                return NULL;
        }

        if (e->state == REG_NAME_IDLE || e->state == REG_NAME_AUTO_ACCEPT
           || e->state == REG_NAME_AUTO_EXEC) {
                e->state = REG_NAME_FLOW_ACCEPT;
                pthread_cond_signal(&e->acc_signal);
        }

        list_add(&i->next, &e->reg_apis);

        return i;
}

void registry_del_api(struct list_head * registry,
                      pid_t              api)
{
        struct reg_entry * e = NULL;
        struct reg_api * i   = NULL;

        if ( api == -1)
                return;

        e = registry_get_entry_by_api(registry, api);
        if (e == NULL) {
                LOG_DBG("Instance %d not found.", api);
                return;
        }

        i = reg_entry_get_reg_api(e, api);
        if (i == NULL) {
                LOG_DBG("Instance %d is not accepting flows for %s.",
                         api, e->name);
                return;
        }

        list_del(&i->next);

        reg_api_destroy(i);

        if (list_empty(&e->reg_apis)) {
                if (reg_entry_has_auto_binding(e))
                        e->state = REG_NAME_AUTO_ACCEPT;
                else
                        e->state = REG_NAME_IDLE;
        } else {
                e->state = REG_NAME_FLOW_ACCEPT;
        }

        return;
}

/* FIXME: optimize this */
char * registry_get_dif_for_dst(struct list_head * registry,
                                char *             dst_name)
{
        struct list_head * pos = NULL;
        struct reg_entry * re =
                registry_get_entry_by_name(registry, dst_name);

        if (re != NULL) { /* local AP */
                list_for_each(pos, &re->difs) {
                        struct reg_dif  * rd =
                                list_entry(pos, struct reg_dif, next);
                        if (rd->type == IPCP_LOCAL)
                                return rd->dif_name;
                }

                list_for_each(pos, &re->difs) {
                        struct reg_dif * rd =
                                list_entry(pos, struct reg_dif, next);
                        if (rd->type == IPCP_NORMAL)
                                return rd->dif_name;
                }

                list_for_each(pos, &re->difs) {
                        struct reg_dif * rd =
                                list_entry(pos, struct reg_dif, next);
                        if (rd->type == IPCP_SHIM_UDP)
                                return rd->dif_name;
                }

                LOG_DBG("Could not find DIF for %s.", dst_name);

                return NULL;
        } else {
                LOG_DBGF("No local ap %s found.", dst_name);
                return NULL;
        }
}

int registry_add_name_to_dif(struct list_head * registry,
                             char *             name,
                             char *             dif_name,
                             enum ipcp_type     type)
{
        struct reg_entry * re = registry_get_entry_by_name(registry, name);
        if (re == NULL)
                return -1;

        return reg_entry_add_local_in_dif(re, dif_name, type);
}

void registry_del_name_from_dif(struct list_head * registry,
                                char *             name,
                                char *             dif_name)
{
        struct reg_entry * re = registry_get_entry_by_name(registry, name);
        if (re == NULL)
                return;

        reg_entry_del_local_from_dif(re, dif_name);
}
