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

#include <ouroboros/logs.h>
#include <ouroboros/irm_config.h>

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

struct reg_instance * reg_instance_create(pid_t api)
{
        struct reg_instance * i;
        i = malloc(sizeof(*i));
        if (i == NULL)
                return NULL;

        i->api   = api;
        i->state = REG_I_WAKE;

        pthread_mutex_init(&i->mutex, NULL);
        pthread_cond_init(&i->wakeup, NULL);

        INIT_LIST_HEAD(&i->next);

        return i;
}

void reg_instance_destroy(struct reg_instance * i)
{
        bool wait = true;
        pthread_mutex_lock(&i->mutex);
        i->state = REG_I_NULL;

        pthread_cond_broadcast(&i->wakeup);
        pthread_mutex_unlock(&i->mutex);

        while (wait) {
                pthread_mutex_lock(&i->mutex);
                if (pthread_cond_destroy(&i->wakeup))
                        pthread_cond_broadcast(&i->wakeup);
                else
                        wait = false;
                pthread_mutex_unlock(&i->mutex);
        }

        pthread_mutex_destroy(&i->mutex);

        free(i);
}

void reg_instance_sleep(struct reg_instance * i)
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
                pthread_cond_wait(&i->wakeup, &i->mutex);

        pthread_cleanup_pop(true);
}

void reg_instance_wake(struct reg_instance * i)
{
        pthread_mutex_lock(&i->mutex);

        if (i->state == REG_I_NULL) {
                pthread_mutex_unlock(&i->mutex);
                return;
        }

        i->state = REG_I_WAKE;

        pthread_cond_signal(&i->wakeup);
        pthread_mutex_unlock(&i->mutex);
}

struct reg_entry * reg_entry_create()
{
        struct reg_entry * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->name         = NULL;
        e->state        = REG_NAME_NULL;
        e->flags        = 0;

        e->req_ae_name  = NULL;
        e->response     = -1;

        return e;
}

struct reg_entry * reg_entry_init(struct reg_entry * e,
                                  char *             name,
                                  char *             ap_name,
                                  uint32_t           flags)
{
        struct reg_ap_name * n = NULL;

        if (e == NULL || name == NULL || ap_name == NULL)
                return NULL;

        n = malloc(sizeof(*n));
        if (n == NULL)
                return NULL;

        INIT_LIST_HEAD(&e->next);
        INIT_LIST_HEAD(&e->ap_names);
        INIT_LIST_HEAD(&e->auto_ap_info);
        INIT_LIST_HEAD(&e->ap_instances);

        e->name    = name;
        e->flags   = flags;
        n->ap_name = ap_name;

        list_add(&n->next, &e->ap_names);

        if (pthread_cond_init(&e->acc_signal, NULL)) {
                free(e);
                return NULL;
        }

        if (pthread_mutex_init(&e->state_lock, NULL)) {
                free(e);
                return NULL;
        }

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

        list_for_each_safe(pos, n, &e->ap_instances) {
                struct reg_instance * i =
                        list_entry(pos, struct reg_instance, next);
                reg_instance_destroy(i);
        }

        list_for_each_safe(pos, n, &e->auto_ap_info) {
                struct reg_auto * a =
                        list_entry(pos, struct reg_auto, next);

                if (a->argv != NULL) {
                        char ** t = a->argv;
                        while (*a->argv != NULL)
                                free(*(a->argv++));
                        free(t);
                }

                free(a->ap_name);
                free(a);
        }

        list_for_each_safe(pos, n, &e->ap_names) {
                struct reg_ap_name * n =
                        list_entry(pos, struct reg_ap_name, next);

                free(n->ap_name);
                free(n);
        }

        free(e);
}

struct reg_ap_name * reg_entry_get_ap_name(struct reg_entry * e,
                                           char *             ap_name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &e->ap_names) {
                struct reg_ap_name * n =
                        list_entry(pos, struct reg_ap_name, next);

                if (strcmp(ap_name, n->ap_name) == 0)
                        return n;
        }

        return NULL;
}

struct reg_instance * reg_entry_get_reg_instance(struct reg_entry * e,
                                                 pid_t              api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &e->ap_instances) {
                struct reg_instance * r =
                        list_entry(pos, struct reg_instance, next);

                if (r->api == api)
                        return r;
        }

        return NULL;
}

struct reg_auto * reg_entry_get_reg_auto(struct reg_entry * e,
                                         char *             ap_name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &e->auto_ap_info) {
                struct reg_auto * a =
                        list_entry(pos, struct reg_auto, next);

                if (strcmp(ap_name, a->ap_name) == 0)
                        return a;
        }

        return NULL;
}

pid_t reg_entry_resolve_api(struct reg_entry * e)
{
        struct list_head * pos = NULL;

        /* FIXME: now just returns the first accepting instance */
        list_for_each(pos, &e->ap_instances) {
                struct reg_instance * r =
                        list_entry(pos, struct reg_instance, next);
                return r->api;
        }

        return 0;
}

char ** reg_entry_resolve_auto(struct reg_entry * e)
{
        struct list_head * pos = NULL;

        /* FIXME: now just returns the first accepting instance */
        list_for_each(pos, &e->auto_ap_info) {
                struct reg_auto * r =
                        list_entry(pos, struct reg_auto, next);
                return r->argv;
        }

        return NULL;
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

struct reg_entry * registry_get_entry_by_ap_name(struct list_head * registry,
                                                 char *             ap_name)
{
        struct list_head * pos = NULL;

        list_for_each(pos, registry) {
                struct list_head * p = NULL;
                struct reg_entry * e =
                        list_entry(pos, struct reg_entry, next);

                list_for_each(p, &e->ap_names) {
                        struct reg_ap_name * n =
                                list_entry(p, struct reg_ap_name, next);

                        if (strcmp(n->ap_name, ap_name) == 0)
                                return e;
                }
        }

        return NULL;
}

struct reg_entry * registry_get_entry_by_ap_id(struct list_head * registry,
                                               pid_t              api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, registry) {
                struct list_head * p = NULL;
                struct reg_entry * e =
                        list_entry(pos, struct reg_entry, next);

                list_for_each(p, &e->ap_instances) {
                        struct reg_instance * r =
                                list_entry(p, struct reg_instance, next);

                        if (r->api == api)
                                return e;
                }
        }

        return NULL;
}

int registry_add_entry(struct list_head * registry,
                       char *             name,
                       char *             ap_name,
                       uint16_t           flags)
{
        struct reg_entry * e = NULL;

        if (name == NULL || ap_name == NULL)
                return -EINVAL;

        e = registry_get_entry_by_name(registry, name);
        if (e != NULL) {
                LOG_DBG("Name %s already registered.", name);
                return -1;
        }

        e = reg_entry_create();
        if (e == NULL) {
                LOG_DBG("Could not create registry entry.");
                return -1;
        }

        e = reg_entry_init(e, name, ap_name, flags);
        if (e == NULL) {
                LOG_DBG("Could not initialize registry entry.");
                reg_entry_destroy(e);
                return -1;
        }

        list_add(&e->next, registry);

        return 0;
}

int registry_add_ap_auto(struct list_head * registry,
                         char *             name,
                         char *             ap_name,
                         char **            argv)
{
        struct reg_entry * e;
        struct reg_auto * a;

        if (name == NULL || ap_name == NULL)
                return -EINVAL;

        e = registry_get_entry_by_name(registry, name);
        if (e == NULL) {
                LOG_DBG("Name %s not found in registry.", name);
                return -1;
        }

        if (!(e->flags & BIND_AP_AUTO)) {
                LOG_DBG("%s does not allow auto-instantiation.", name);
                return -1;
        }

        if (!reg_entry_has_ap_name(e, ap_name)) {
                LOG_DBG("AP name %s not associated with %s.", ap_name, name);
                return -1;
        }

        if (e->state == REG_NAME_NULL) {
                LOG_DBG("Tried to add instantiation info in NULL state.");
                return -1;
        }

        a = reg_entry_get_reg_auto(e, ap_name);
        if (a != NULL) {
                LOG_DBG("Updating auto-instantiation info for %s.", ap_name);
                list_del(&a->next);
                free(a->ap_name);
                if (a->argv != NULL) {
                        while (*a->argv != NULL)
                                free(*a->argv++);
                }
        } else {
                a = malloc(sizeof(*a));
                if (a == NULL)
                        return -1;
        }

        a->ap_name = ap_name;
        a->argv    = argv;

        if (e->state == REG_NAME_IDLE)
                e->state = REG_NAME_AUTO_ACCEPT;

        list_add(&a->next, &e->auto_ap_info);

        return 0;
}


int registry_remove_ap_auto(struct list_head * registry,
                            char *             name,
                            char *             ap_name)
{
        struct reg_entry * e;
        struct reg_auto * a;

        if (name == NULL || ap_name == NULL)
                return -EINVAL;

        e = registry_get_entry_by_name(registry, name);
        if (e == NULL) {
                LOG_DBG("Name %s not found in registry.", name);
                return -1;
        }

        a = reg_entry_get_reg_auto(e, ap_name);
        if (a == NULL) {
                LOG_DBG("Auto-instantiation info for %s not found.", ap_name);
                return -1;
        }

        list_del(&a->next);

        if (e->state == REG_NAME_AUTO_ACCEPT && list_empty(&e->auto_ap_info))
                e->state = REG_NAME_IDLE;

        return 0;
}


struct reg_instance * registry_add_ap_instance(struct list_head * registry,
                                               char *             name,
                                               pid_t              api)
{
        struct reg_entry * e    = NULL;
        struct reg_instance * i = NULL;

        if (name == NULL || api == 0)
                return NULL;

        e = registry_get_entry_by_name(registry, name);
        if (e == NULL) {
                LOG_DBG("Name %s not found in registry.", name);
                return NULL;
        }

        if (api == 0) {
                LOG_DBG("Invalid api.");
                return NULL;
        }

        if (reg_entry_has_api(e, api)) {
                LOG_DBG("Instance already registered with this name.");
                return NULL;
        }

        if (e->state == REG_NAME_NULL) {
                LOG_DBG("Tried to add instance in NULL state.");
                return NULL;
        }

        i = reg_instance_create(api);
        if (i == NULL) {
                LOG_DBG("Failed to create reg_instance");
                return NULL;
        }

        if (e->state == REG_NAME_IDLE || e->state == REG_NAME_AUTO_ACCEPT
           || e->state == REG_NAME_AUTO_EXEC) {
                e->state = REG_NAME_FLOW_ACCEPT;
                pthread_cond_signal(&e->acc_signal);
        }

        list_add(&i->next, &e->ap_instances);

        return i;
}

int registry_remove_ap_instance(struct list_head * registry,
                                char *             name,
                                pid_t              api)
{
        struct reg_entry * e    = NULL;
        struct reg_instance * i = NULL;

        if (name == NULL || api == 0)
                return -1;

        e = registry_get_entry_by_name(registry, name);
        if (e == NULL) {
                LOG_DBG("Name %s is not registered.", name);
                return -1;
        }

        i = reg_entry_get_reg_instance(e, api);
        if (i == NULL) {
                LOG_DBG("Instance %d is not accepting flows for %s.",
                         api, name);
                return -1;
        }

        list_del(&i->next);

        reg_instance_destroy(i);

        if (list_empty(&e->ap_instances)) {
                if ((e->flags & BIND_AP_AUTO) &&
                        !list_empty(&e->auto_ap_info))
                        e->state = REG_NAME_AUTO_ACCEPT;
                else
                        e->state = REG_NAME_IDLE;
        } else {
                e->state = REG_NAME_FLOW_ACCEPT;
        }

        return 0;
}

void registry_del_name(struct list_head * registry,
                       char *             name)
{
        struct reg_entry * e = registry_get_entry_by_name(registry, name);
        if (e == NULL)
                return;

        list_del(&e->next);
        reg_entry_destroy(e);

        return;
}
