/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The IPC Resource Manager - Application Instance Table
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#include <ouroboros/config.h>
#include <ouroboros/list.h>
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>

#include "api_table.h"
#include "registry.h"

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

#define ENTRY_SLEEP_TIMEOUT 10 /* ms */

struct api_entry * api_entry_create(pid_t  api,
                                    char * apn)
{
        struct api_entry * e;
        pthread_condattr_t cattr;

        assert(apn);

        e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        list_head_init(&e->next);
        list_head_init(&e->names);

        e->api      = api;
        e->apn      = apn;
        e->daf_name = NULL;

        e->re       = NULL;

        e->state    = API_INIT;

        if (pthread_condattr_init(&cattr)) {
                free(e);
                return NULL;
        }

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif

        if (pthread_mutex_init(&e->state_lock, NULL)) {
                free(e);
                return NULL;
        }


        if (pthread_cond_init(&e->state_cond, &cattr)) {
                pthread_mutex_destroy(&e->state_lock);
                free(e);
                return NULL;
        }

        return e;
}

void api_entry_destroy(struct api_entry * e)
{
        struct list_head * p;
        struct list_head * h;

        assert(e);

        pthread_mutex_lock(&e->state_lock);

        if (e->state == API_DESTROY) {
                pthread_mutex_unlock(&e->state_lock);
                return;
        }

        if (e->state == API_SLEEP)
                e->state = API_DESTROY;

        pthread_cond_signal(&e->state_cond);

        while (e->state != API_INIT)
                pthread_cond_wait(&e->state_cond, &e->state_lock);

        pthread_mutex_unlock(&e->state_lock);

        pthread_cond_destroy(&e->state_cond);
        pthread_mutex_destroy(&e->state_lock);

        if (e->apn != NULL)
                free(e->apn);

        list_for_each_safe(p, h, &e->names) {
                struct str_el * n = list_entry(p, struct str_el, next);
                list_del(&n->next);
                if (n->str != NULL)
                        free(n->str);
                free(n);
        }

        free(e);
}

int api_entry_add_name(struct api_entry * e,
                       char *             name)
{
        struct str_el * s;

        assert(e);
        assert(name);

        s = malloc(sizeof(*s));
        if (s == NULL)
                return -ENOMEM;

        s->str = name;
        list_add(&s->next, &e->names);

        return 0;
}

void api_entry_del_name(struct api_entry * e,
                        const char *       name)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        assert(e);
        assert(name);

        list_for_each_safe(p, h, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                if (!wildcard_match(name, s->str)) {
                        list_del(&s->next);
                        if (s->str != NULL)
                                free(s->str);
                        free(s);
                }
        }
}

void api_entry_cancel(struct api_entry * e)
{
        pthread_mutex_lock(&e->state_lock);

        e->state = API_INIT;
        pthread_cond_broadcast(&e->state_cond);

        pthread_mutex_unlock(&e->state_lock);
}

int api_entry_sleep(struct api_entry * e)
{
        struct timespec timeout = {(ENTRY_SLEEP_TIMEOUT / 1000),
                                   (ENTRY_SLEEP_TIMEOUT % 1000) * MILLION};
        struct timespec now;
        struct timespec dl;

        int ret = 0;

        assert(e);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        ts_add(&now, &timeout, &dl);

        pthread_mutex_lock(&e->state_lock);

        if (e->state != API_WAKE && e->state != API_DESTROY)
                e->state = API_SLEEP;

        while (e->state == API_SLEEP && ret != -ETIMEDOUT)
                ret = -pthread_cond_timedwait(&e->state_cond,
                                              &e->state_lock,
                                              &dl);

        if (e->state == API_DESTROY) {
                if (e->re != NULL)
                        reg_entry_del_api(e->re, e->api);
                ret = -1;
        }

        if (ret != -ETIMEDOUT)
                e->state = API_INIT;

        pthread_cond_broadcast(&e->state_cond);
        pthread_mutex_unlock(&e->state_lock);

        return ret;
}

void api_entry_wake(struct api_entry * e,
                    struct reg_entry * re)
{
        assert(e);
        assert(re);

        pthread_mutex_lock(&e->state_lock);

        if (e->state != API_SLEEP) {
                pthread_mutex_unlock(&e->state_lock);
                return;
        }

        e->state = API_WAKE;
        e->re    = re;

        pthread_cond_broadcast(&e->state_cond);

        while (e->state == API_WAKE)
                pthread_cond_wait(&e->state_cond, &e->state_lock);

        if (e->state == API_DESTROY)
                e->state = API_INIT;

        pthread_mutex_unlock(&e->state_lock);
}

int api_table_add(struct list_head * api_table,
                  struct api_entry * e)
{

        assert(api_table);
        assert(e);

        list_add(&e->next, api_table);

        return 0;
}

void api_table_del(struct list_head * api_table,
                   pid_t              api)
{
        struct list_head * p;
        struct list_head * h;

        assert(api_table);

        list_for_each_safe(p, h, api_table) {
                struct api_entry * e = list_entry(p, struct api_entry, next);
                if (api == e->api) {
                        list_del(&e->next);
                        api_entry_destroy(e);
                }
        }
}

struct api_entry * api_table_get(struct list_head * api_table,
                                 pid_t              api)
{
        struct list_head * h;

        assert(api_table);

        list_for_each(h, api_table) {
                struct api_entry * e = list_entry(h, struct api_entry, next);
                if (api == e->api)
                        return e;
        }

        return NULL;
}
