/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager - Registry
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#define OUROBOROS_PREFIX "registry"

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/irm_config.h>

#include "registry.h"
#include "utils.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>

struct reg_dif {
        struct list_head next;
        char *           dif_name;
        enum ipcp_type   type;
};

static struct reg_entry * reg_entry_create(void)
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

static struct reg_entry * reg_entry_init(struct reg_entry * e,
                                         char *             name)
{
        if (e == NULL || name == NULL)
                return NULL;

        INIT_LIST_HEAD(&e->next);
        INIT_LIST_HEAD(&e->difs);
        INIT_LIST_HEAD(&e->reg_apns);
        INIT_LIST_HEAD(&e->reg_apis);

        e->name = name;

        if (pthread_cond_init(&e->state_cond, NULL))
                return NULL;

        if (pthread_mutex_init(&e->state_lock, NULL))
                return NULL;

        e->state = REG_NAME_IDLE;

        return e;
}

static void reg_entry_destroy(struct reg_entry * e)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        if (e == NULL)
                return;

        pthread_mutex_lock(&e->state_lock);

        e->state = REG_NAME_DESTROY;

        pthread_cond_broadcast(&e->state_cond);
        pthread_mutex_unlock(&e->state_lock);

        pthread_cond_destroy(&e->state_cond);
        pthread_mutex_destroy(&e->state_lock);

        if (e->name != NULL)
                free(e->name);

        list_for_each_safe(p, h, &e->reg_apis) {
                struct pid_el * i = list_entry(p, struct pid_el, next);
                list_del(&i->next);
                free(i);
        }

        list_for_each_safe(p, h, &e->reg_apns) {
                struct str_el * a = list_entry(p, struct str_el, next);
                list_del(&a->next);
                free(a->str);
                free(a);
        }

        list_for_each_safe(p, h, &e->difs) {
                struct reg_dif * d = list_entry(p, struct reg_dif, next);
                list_del(&d->next);
                free(d->dif_name);
                free(d);
        }

        free(e);
}

static bool reg_entry_is_local_in_dif(struct reg_entry * e, char * dif_name)
{
        struct list_head * p = NULL;

        list_for_each(p, &e->difs) {
                struct reg_dif * d = list_entry(p, struct reg_dif, next);
                if (!strcmp(dif_name, d->dif_name))
                        return true;
        }

        return false;
}

static int reg_entry_add_local_in_dif(struct reg_entry * e,
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

static void reg_entry_del_local_from_dif(struct reg_entry * e,
                                         char *             dif_name)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        list_for_each_safe(p, h, &e->difs) {
                struct reg_dif * d = list_entry(p, struct reg_dif, next);
                if (!strcmp(dif_name, d->dif_name)) {
                        list_del(&d->next);
                        free(d);
                }
        }
}

static bool reg_entry_has_apn(struct reg_entry * e, char * apn)
{
        struct list_head * p;

        list_for_each(p, &e->reg_apns) {
                struct str_el * e = list_entry(p, struct str_el, next);
                if (!strcmp(e->str, apn))
                        return true;
        }

        return false;
}

int reg_entry_add_apn(struct reg_entry * e, struct apn_entry * a)
{
        struct str_el * n;

        if (reg_entry_has_apn(e, a->apn)) {
                LOG_WARN("AP %s already accepting flows for %s.",
                         a->apn, e->name);
                return 0;
        }

        if (!(a->flags & BIND_AP_AUTO)) {
                LOG_DBG("AP %s cannot be auto-instantiated.", a->apn);
                return -EINVAL;
        }

        n = malloc(sizeof(*n));
        if (n == NULL)
                return -ENOMEM;

        n->str = strdup(a->apn);
        if (n->str == NULL)
                return -ENOMEM;

        list_add(&n->next, &e->reg_apns);

        if (e->state == REG_NAME_IDLE)
                e->state = REG_NAME_AUTO_ACCEPT;

        return 0;
}

void reg_entry_del_apn(struct reg_entry * e, char * apn)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        list_for_each_safe(p, h, &e->reg_apns) {
                struct str_el * e = list_entry(p, struct str_el, next);
                if (!wildcard_match(apn, e->str)) {
                        list_del(&e->next);
                        free(e->str);
                        free(e);
                }
        }

        if (e->state == REG_NAME_AUTO_ACCEPT && list_empty(&e->reg_apns)) {
                e->state = REG_NAME_IDLE;
                pthread_cond_broadcast(&e->state_cond);
        }

}

char * reg_entry_get_apn(struct reg_entry * e)
{
        if (!list_empty(&e->reg_apis) || list_empty(&e->reg_apns))
                return NULL;

        return list_first_entry(&e->reg_apns, struct str_el, next)->str;
}

static bool reg_entry_has_api(struct reg_entry * e, pid_t api)
{
        struct list_head * p;

        list_for_each(p, &e->reg_apns) {
                struct pid_el * e = list_entry(p, struct pid_el, next);
                if (e->pid == api)
                        return true;
        }

        return false;
}

int reg_entry_add_api(struct reg_entry * e, pid_t api)
{
        struct pid_el * i;

        if (e == NULL)
                return -EINVAL;

        if (reg_entry_has_api(e, api)) {
                LOG_DBG("Instance already registered with this name.");
                return -EPERM;
        }

        if (e->state == REG_NAME_NULL) {
                LOG_DBG("Tried to add instance in NULL state.");
                return -EPERM;
        }

        i = malloc(sizeof(*i));
        if (i == NULL)
                return -ENOMEM;

        i->pid = api;

        pthread_mutex_lock(&e->state_lock);

        list_add(&i->next, &e->reg_apis);

        if (e->state == REG_NAME_IDLE ||
            e->state == REG_NAME_AUTO_ACCEPT ||
            e->state == REG_NAME_AUTO_EXEC) {
                e->state = REG_NAME_FLOW_ACCEPT;
                pthread_cond_signal(&e->state_cond);
        }

        pthread_mutex_unlock(&e->state_lock);

        return 0;
}

void reg_entry_del_api(struct reg_entry * e, pid_t api)
{
        struct list_head * p;
        struct list_head * h;

        if (e == NULL)
                return;

        list_for_each_safe(p, h, &e->reg_apis) {
                struct pid_el * a = list_entry(p, struct pid_el, next);
                if (a->pid == api) {
                        list_del(&a->next);
                        free(a);
                }
        }

        if (list_empty(&e->reg_apis)) {
                if (!list_empty(&e->reg_apns))
                        e->state = REG_NAME_AUTO_ACCEPT;
                else
                        e->state = REG_NAME_IDLE;
        } else {
                e->state = REG_NAME_FLOW_ACCEPT;
        }

        pthread_cond_broadcast(&e->state_cond);
}

pid_t reg_entry_get_api(struct reg_entry * e)
{
        if (e == NULL)
                return -1;

        if (list_empty(&e->reg_apis))
                return -1;

        return list_first_entry(&e->reg_apis, struct pid_el, next)->pid;
}

enum reg_name_state reg_entry_get_state(struct reg_entry * e)
{
        enum reg_name_state state;

        if (e == NULL)
                return REG_NAME_NULL;

        pthread_mutex_lock(&e->state_lock);

        state = e->state;

        pthread_mutex_unlock(&e->state_lock);

        return state;
}

int reg_entry_set_state(struct reg_entry * e, enum reg_name_state state)
{
        if (state == REG_NAME_DESTROY)
                return -EPERM;

        pthread_mutex_lock(&e->state_lock);

        e->state = state;
        pthread_cond_broadcast(&e->state_cond);

        pthread_mutex_unlock(&e->state_lock);

        return 0;
}

int reg_entry_leave_state(struct reg_entry * e, enum reg_name_state state)
{
        if (e == NULL || state == REG_NAME_DESTROY)
                return -EINVAL;

        pthread_mutex_lock(&e->state_lock);

        while (e->state == state)
                pthread_cond_wait(&e->state_cond, &e->state_lock);

        pthread_mutex_unlock(&e->state_lock);

        return 0;
}

struct reg_entry * registry_get_entry(struct list_head * registry,
                                      char *             name)
{
        struct list_head * p   = NULL;

        list_for_each(p, registry) {
                struct reg_entry * e = list_entry(p, struct reg_entry, next);
                if (!wildcard_match(name, e->name))
                        return e;
        }

        return NULL;
}

struct reg_entry * registry_add_name(struct list_head * registry,
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

void registry_del_name(struct list_head * registry,
                       char *             name)
{
        struct reg_entry * e = registry_get_entry(registry, name);
        if (e == NULL)
                return;

        list_del(&e->next);
        reg_entry_destroy(e);

        return;
}

void registry_del_api(struct list_head * registry,
                      pid_t              api)
{
        struct list_head * p;

        if ( api == -1)
                return;

        list_for_each(p, registry) {
                struct reg_entry * e = list_entry(p, struct reg_entry, next);
                pthread_mutex_lock(&e->state_lock);
                reg_entry_del_api(e, api);
                pthread_mutex_unlock(&e->state_lock);
        }

        return;
}

int registry_add_name_to_dif(struct list_head * registry,
                             char *             name,
                             char *             dif_name,
                             enum ipcp_type     type)
{
        struct reg_entry * re = registry_get_entry(registry, name);
        if (re == NULL)
                return -1;

        return reg_entry_add_local_in_dif(re, dif_name, type);
}

void registry_del_name_from_dif(struct list_head * registry,
                                char *             name,
                                char *             dif_name)
{
        struct reg_entry * re = registry_get_entry(registry, name);
        if (re == NULL)
                return;

        reg_entry_del_local_from_dif(re, dif_name);
}

void registry_destroy(struct list_head * registry)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        if (registry == NULL)
                return;

        list_for_each_safe(p, h, registry) {
                struct reg_entry * e = list_entry(p, struct reg_entry, next);
                list_del(&e->next);
                reg_entry_destroy(e);
        }
}
