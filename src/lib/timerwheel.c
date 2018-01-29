/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Timerwheel
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>

#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define FRAC 10 /* accuracy of the timer */

#define tw_used(tw) ((tw->head + tw->elements - tw->tail) & (tw->elements - 1));
#define tw_free(tw) (tw_used(tw) + 1 < tw->elements)
#define tw_empty(tw) (tw->head == tw->tail)

struct tw_f {
        struct list_head next;
        void (* func)(void *);
        void * arg;
};

struct tw_el {
        struct list_head funcs;
        struct timespec  expiry;
};

struct timerwheel {
        struct tw_el *   wheel;

        struct timespec  intv;

        size_t           pos;

        pthread_mutex_t  lock;

        time_t           resolution;
        size_t           elements;
};

static void tw_el_fini(struct tw_el * e)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &e->funcs) {
                struct tw_f * f = list_entry(p, struct tw_f, next);
                list_del(&f->next);
        }
}

void timerwheel_move(struct timerwheel * tw)
{
        struct timespec now = {0, 0};
        long ms = tw->resolution * tw->elements;
        struct timespec total = {ms / 1000,
                                 (ms % 1000) * MILLION};
        struct list_head * p;
        struct list_head * h;

        clock_gettime(CLOCK_MONOTONIC, &now);

        pthread_mutex_lock(&tw->lock);

        while (ts_diff_us(&tw->wheel[tw->pos].expiry, &now) > 0) {
                list_for_each_safe(p, h, &tw->wheel[tw->pos].funcs) {
                        struct tw_f * f = list_entry(p, struct tw_f, next);
                        list_del(&f->next);
                        f->func(f->arg);
                        free(f);
                }

                ts_add(&tw->wheel[tw->pos].expiry,
                       &total,
                       &tw->wheel[tw->pos].expiry);

                tw->pos = (tw->pos + 1) & (tw->elements - 1);
        }

        pthread_mutex_unlock(&tw->lock);
}

struct timerwheel * timerwheel_create(time_t resolution,
                                      time_t max_delay)
{
        struct timespec now = {0, 0};
        struct timespec res_ts = {resolution / 1000,
                                  (resolution % 1000) * MILLION};
        size_t i;

        struct timerwheel * tw;

        assert(resolution != 0);

        tw = malloc(sizeof(*tw));
        if (tw == NULL)
                return NULL;

        if (pthread_mutex_init(&tw->lock, NULL))
                return NULL;

        tw->elements = 1;

        while (tw->elements < (size_t) max_delay / resolution)
                tw->elements <<= 1;

        tw->wheel = malloc(sizeof(*tw->wheel) * tw->elements);
        if (tw->wheel == NULL)
                goto fail_wheel_malloc;

        tw->resolution = resolution;

        tw->intv.tv_sec = (tw->resolution / FRAC) / 1000;
        tw->intv.tv_nsec = ((tw->resolution / FRAC) % 1000) * MILLION;

        if (pthread_mutex_init(&tw->lock, NULL))
                goto fail_lock_init;

        tw->pos = 0;

        clock_gettime(CLOCK_MONOTONIC, &now);
        now.tv_nsec -= (now.tv_nsec % MILLION);

        for (i = 0; i < tw->elements; ++i) {
                list_head_init(&tw->wheel[i].funcs);
                tw->wheel[i].expiry = now;
                ts_add(&now, &res_ts, &now);
        }

        return tw;

 fail_lock_init:
         free(tw->wheel);
 fail_wheel_malloc:
         free(tw);
         return NULL;
}

void timerwheel_destroy(struct timerwheel * tw)
{
        unsigned long i;

        for (i = 0; i < tw->elements; ++i)
                tw_el_fini(&tw->wheel[i]);

        pthread_mutex_destroy(&tw->lock);
        free(tw->wheel);
        free(tw);
}

struct tw_f * timerwheel_start(struct timerwheel * tw,
                               void (* func)(void *),
                               void *              arg,
                               time_t              delay)
{
        int pos;
        struct tw_f * f = malloc(sizeof(*f));
        if (f == NULL)
                return NULL;

        f->func = func;
        f->arg = arg;

        assert(delay < (time_t) tw->elements * tw->resolution);

        pthread_mutex_lock(&tw->lock);

        pos = (tw->pos + delay / tw->resolution) & (tw->elements - 1);
        list_add(&f->next, &tw->wheel[pos].funcs);

        pthread_mutex_unlock(&tw->lock);

        return f;
}

int timerwheel_restart(struct timerwheel * tw,
                       struct tw_f *       f,
                       time_t              delay)
{
        int pos;

        assert(tw);
        assert(delay < (time_t) tw->elements * tw->resolution);

        pthread_mutex_lock(&tw->lock);

        list_del(&f->next);
        pos = (tw->pos + delay / tw->resolution) & (tw->elements - 1);
        list_add(&f->next, &tw->wheel[pos].funcs);

        pthread_mutex_unlock(&tw->lock);

        return 0;
}

void timerwheel_stop(struct timerwheel * tw,
                     struct tw_f *       f)
{
        assert(tw);

        pthread_mutex_lock(&tw->lock);

        list_del(&f->next);
        free(f);

        pthread_mutex_unlock(&tw->lock);
}
