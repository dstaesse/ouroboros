/*
 * Ouroboros - Copyright (C) 2016 - 2017
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

enum tw_state {
        TW_NULL = 0,
        TW_RUNNING,
        TW_DESTROY
};

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

        struct list_head wq;

        pthread_cond_t   work;
        pthread_mutex_t  lock;

        int              resolution;
        unsigned int     elements;

        enum tw_state    state;
        pthread_mutex_t  s_lock;

        pthread_t        ticker;
        pthread_t        worker;
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

static enum tw_state tw_get_state(struct timerwheel * tw)
{
        enum tw_state state;

        assert(tw);

        pthread_mutex_lock(&tw->s_lock);

        state = tw->state;

        pthread_mutex_unlock(&tw->s_lock);

        return state;
}

static void tw_set_state(struct timerwheel * tw, enum tw_state state)
{
        assert(tw);
        assert(state != TW_NULL);

        pthread_mutex_lock(&tw->s_lock);

        tw->state = state;

        pthread_mutex_unlock(&tw->s_lock);
}

static void * worker(void * o)
{
        struct list_head * p;
        struct list_head * h;

        struct timerwheel * tw = (struct timerwheel *) o;
        struct timespec dl;
        struct timespec now;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        ts_add(&now, &tw->intv, &dl);

        pthread_mutex_lock(&tw->lock);

        while (tw_get_state(tw) == TW_RUNNING) {
                if (pthread_cond_timedwait(&tw->work, &tw->lock, &dl)
                    == ETIMEDOUT)
                        ts_add(&dl, &tw->intv, &dl);

                list_for_each_safe(p, h, &tw->wq) {
                        struct tw_f * f = list_entry(p, struct tw_f, next);
                        list_del(&f->next);
                        pthread_mutex_unlock(&tw->lock);
                        f->func(f->arg);
                        free(f);

                        pthread_mutex_lock(&tw->lock);
                }
        }

        pthread_mutex_unlock(&tw->lock);

        return (void *) o;
}

static void * movement(void * o)
{
        struct timerwheel * tw = (struct timerwheel *) o;
        struct timespec now = {0, 0};
        long ms = tw->resolution * tw->elements;
        struct timespec total = {ms / 1000,
                                 (ms % 1000) * MILLION};
        struct list_head * p;
        struct list_head * h;

        while (tw_get_state(tw) == TW_RUNNING) {
                clock_gettime(CLOCK_MONOTONIC, &now);

                pthread_mutex_lock(&tw->lock);

                if (ts_diff_us(&tw->wheel[tw->pos].expiry, &now) < 0) {
                        pthread_mutex_unlock(&tw->lock);
                        nanosleep(&tw->intv, NULL);
                        continue;
                }

                list_for_each_safe(p, h, &tw->wheel[tw->pos].funcs) {
                        struct tw_f * f = list_entry(p, struct tw_f, next);
                        list_del(&f->next);
                        list_add(&f->next, &tw->wq);
                }

                ts_add(&tw->wheel[tw->pos].expiry,
                       &total,
                       &tw->wheel[tw->pos].expiry);

                tw->pos = (tw->pos + 1) & (tw->elements - 1);

                pthread_cond_signal(&tw->work);

                pthread_mutex_unlock(&tw->lock);
        }

        return (void *) 0;
}

struct timerwheel * timerwheel_create(time_t resolution,
                                      time_t max_delay)
{
        struct timespec now = {0, 0};
        struct timespec res_ts = {resolution / 1000,
                                  (resolution % 1000) * MILLION};
        unsigned long i;

        struct timerwheel * tw;

        pthread_condattr_t cattr;

        assert(resolution != 0);

        tw = malloc(sizeof(*tw));
        if (tw == NULL)
                return NULL;

        if (pthread_mutex_init(&tw->lock, NULL))
                return NULL;

        tw->elements = 1;

        while (tw->elements < max_delay / resolution)
                tw->elements <<= 1;

        tw->wheel = malloc(sizeof(*tw->wheel) * tw->elements);
        if (tw->wheel == NULL)
                goto fail_wheel_malloc;

        tw->resolution = resolution;

        tw->intv.tv_sec = (tw->resolution / FRAC) / 1000;
        tw->intv.tv_nsec = ((tw->resolution / FRAC) % 1000) * MILLION;

        list_head_init(&tw->wq);

        if (pthread_mutex_init(&tw->lock, NULL))
                goto fail_lock_init;

        if (pthread_mutex_init(&tw->s_lock, NULL))
                goto fail_s_lock_init;

        if (pthread_condattr_init(&cattr))
                goto fail_cond_init;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&tw->work, &cattr))
                goto fail_cond_init;

        tw->pos = 0;
        tw->state = TW_RUNNING;

        clock_gettime(CLOCK_MONOTONIC, &now);
        now.tv_nsec -= (now.tv_nsec % MILLION);

        for (i = 0; i < tw->elements; ++i) {
                list_head_init(&tw->wheel[i].funcs);
                tw->wheel[i].expiry = now;
                ts_add(&now, &res_ts, &now);
        }

        if (pthread_create(&tw->worker, NULL, worker, (void *) tw))
                goto fail_worker_create;

        if (pthread_create(&tw->ticker, NULL, movement, (void *) tw)) {
                tw_set_state(tw, TW_DESTROY);
                goto fail_ticker_create;
        }

        return tw;

 fail_ticker_create:
         pthread_join(tw->worker, NULL);
 fail_worker_create:
         pthread_cond_destroy(&tw->work);
 fail_cond_init:
         pthread_mutex_destroy(&tw->s_lock);
 fail_s_lock_init:
         pthread_mutex_destroy(&tw->lock);
 fail_lock_init:
         free(tw->wheel);
 fail_wheel_malloc:
         free(tw);
         return NULL;
}

void timerwheel_destroy(struct timerwheel * tw)
{
        unsigned long i;

        struct list_head * p;
        struct list_head * h;

        tw_set_state(tw, TW_DESTROY);

        pthread_join(tw->ticker, NULL);
        pthread_join(tw->worker, NULL);

        for (i = 0; i < tw->elements; ++i)
                tw_el_fini(&tw->wheel[i]);

        pthread_mutex_lock(&tw->lock);

        list_for_each_safe(p, h, &tw->wq) {
                struct tw_f * f = list_entry(p, struct tw_f, next);
                list_del(&f->next);
                free(f);
        }

        pthread_mutex_unlock(&tw->lock);

        pthread_cond_destroy(&tw->work);
        pthread_mutex_destroy(&tw->lock);
        pthread_mutex_destroy(&tw->s_lock);

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

        assert(delay < tw->elements * tw->resolution);

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
        assert(delay < tw->elements * tw->resolution);

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
