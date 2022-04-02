/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Threadpool management
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/tpm.h>

#include <pthread.h>
#include <stdlib.h>
#include <assert.h>

#define TPM_TIMEOUT 1000

struct pthr_el {
        struct list_head next;

        bool             kill;
        bool             busy;

        pthread_t        thr;
};

enum tpm_state {
        TPM_NULL = 0,
        TPM_INIT,
        TPM_RUNNING
};

struct tpm {
        size_t           min;
        size_t           inc;
        size_t           cur;
        size_t           wrk;

        void * (* func)(void *);
        void *           o;

        struct list_head pool;

        enum tpm_state   state;
        pthread_cond_t   cond;
        pthread_mutex_t  lock;

        pthread_t        mgr;
};

static void tpm_join(struct tpm * tpm)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &tpm->pool) {
                struct pthr_el * e = list_entry(p, struct pthr_el, next);
                if (tpm->state != TPM_RUNNING) {
                        if (!e->kill) {
                                e->kill = true;
                                pthread_cancel(e->thr);
                                --tpm->cur;
                        }
                }
        }

        list_for_each_safe(p, h, &tpm->pool) {
                struct pthr_el * e = list_entry(p, struct pthr_el, next);
                if (e->kill) {
                        pthread_t thr = e->thr;
                        list_del(&e->next);
                        free(e);
                        pthread_mutex_unlock(&tpm->lock);

                        pthread_join(thr, NULL);

                        pthread_mutex_lock(&tpm->lock);
                }
        }
}

static void tpm_kill(struct tpm * tpm)
{
        struct list_head * p;

        list_for_each(p, &tpm->pool) {
                struct pthr_el * e = list_entry(p, struct pthr_el, next);
                if (!e->busy && !e->kill) {
                        e->kill = true;
                        pthread_cancel(e->thr);
                        --tpm->cur;
                        return;
                }
        }
}

static void * tpmgr(void * o)
{
        struct timespec dl;
        struct timespec to = {(TPM_TIMEOUT / 1000),
                              (TPM_TIMEOUT % 1000) * MILLION};
        struct tpm * tpm = (struct tpm *) o;

        while (true) {
                clock_gettime(PTHREAD_COND_CLOCK, &dl);
                ts_add(&dl, &to, &dl);

                pthread_mutex_lock(&tpm->lock);

                if (tpm->state != TPM_RUNNING) {
                        tpm_join(tpm);
                        pthread_mutex_unlock(&tpm->lock);
                        break;
                }

                tpm_join(tpm);

                if (tpm->cur - tpm->wrk < tpm->min) {
                        size_t i;
                        for (i = 0; i < tpm->inc; ++i) {
                                struct pthr_el * e = malloc(sizeof(*e));
                                if (e == NULL)
                                        break;

                                e->kill = false;
                                e->busy = false;

                                if (pthread_create(&e->thr, NULL,
                                                   tpm->func, tpm->o)) {
                                        free(e);
                                        break;
                                }

                                list_add(&e->next, &tpm->pool);
                        }

                        tpm->cur += i;
                }

                if (pthread_cond_timedwait(&tpm->cond, &tpm->lock, &dl)
                    == ETIMEDOUT)
                        if (tpm->cur - tpm->wrk > tpm->min)
                                tpm_kill(tpm);

                pthread_mutex_unlock(&tpm->lock);
        }

        return (void *) 0;
}

struct tpm * tpm_create(size_t min,
                        size_t inc,
                        void * (* func)(void *),
                        void * o)
{
        struct tpm *       tpm;
        pthread_condattr_t cattr;

        tpm = malloc(sizeof(*tpm));
        if (tpm == NULL)
                goto fail_malloc;

        if (pthread_mutex_init(&tpm->lock, NULL))
                goto fail_lock;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&tpm->cond, &cattr))
                goto fail_cond;

        list_head_init(&tpm->pool);

        pthread_condattr_destroy(&cattr);

        tpm->state = TPM_INIT;
        tpm->func  = func;
        tpm->o     = o;
        tpm->min   = min;
        tpm->inc   = inc;
        tpm->cur   = 0;
        tpm->wrk   = 0;

        return tpm;

 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(&tpm->lock);
 fail_lock:
        free(tpm);
 fail_malloc:
        return NULL;
}

int tpm_start(struct tpm * tpm)
{
        pthread_mutex_lock(&tpm->lock);

        if (pthread_create(&tpm->mgr, NULL, tpmgr, tpm)) {
                pthread_mutex_unlock(&tpm->lock);
                return -1;
        }

        tpm->state = TPM_RUNNING;

        pthread_mutex_unlock(&tpm->lock);

        return 0;
}

void tpm_stop(struct tpm * tpm)
{
        pthread_mutex_lock(&tpm->lock);

        tpm->state = TPM_NULL;

        pthread_mutex_unlock(&tpm->lock);
}

void tpm_destroy(struct tpm * tpm)
{
        pthread_join(tpm->mgr, NULL);

        pthread_mutex_destroy(&tpm->lock);
        pthread_cond_destroy(&tpm->cond);

        free(tpm);
}

static struct pthr_el * tpm_pthr_el(struct tpm * tpm,
                                    pthread_t    thr)
{
        struct list_head * p;
        struct pthr_el *   e;

        list_for_each(p, &tpm->pool) {
                e = list_entry(p, struct pthr_el, next);
                if (e->thr == thr)
                        return e;

        }

        return NULL;
}

void tpm_inc(struct tpm * tpm)
{
        struct pthr_el * e;

        pthread_mutex_lock(&tpm->lock);

        e = tpm_pthr_el(tpm, pthread_self());
        if (e != NULL) {
                e->busy = false;
                --tpm->wrk;
        }

        pthread_mutex_unlock(&tpm->lock);
}

void tpm_dec(struct tpm * tpm)
{
        struct pthr_el * e;

        pthread_mutex_lock(&tpm->lock);

        e = tpm_pthr_el(tpm, pthread_self());
        if (e != NULL) {
                e->busy = true;
                ++tpm->wrk;
        }

        pthread_cond_signal(&tpm->cond);

        pthread_mutex_unlock(&tpm->lock);
}
