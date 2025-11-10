/*
 * Ouroboros - Copyright (C) 2016 - 2024
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
#include <ouroboros/pthread.h>
#include <ouroboros/time.h>
#include <ouroboros/tpm.h>

#ifdef CONFIG_OUROBOROS_DEBUG
#define OUROBOROS_PREFIX "tpm"
#include <ouroboros/logs.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TPM_TIMEOUT      1000

struct pthr_el {
        struct list_head next;

        bool             kill;
        bool             busy;
        bool             wait;
#ifdef CONFIG_OUROBOROS_DEBUG
        struct timespec  start;
        struct timespec  last;
#endif
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
        pthread_mutex_t  mtx;

        pthread_t        mgr;
};

#ifdef CONFIG_OUROBOROS_DEBUG
#define BETWEEN(a, x, y) ((a) > (x) && (a) <= (y))
static void tpm_debug_thread(struct pthr_el * e)
{
        struct timespec now;
        time_t diff;
        time_t intv;

        if (e->wait || !e->busy)
                return;

        clock_gettime(CLOCK_REALTIME, &now);

        diff = ts_diff_ms(&now, &e->start) / 1000;
        intv = ts_diff_ms(&now, &e->last) / 1000;

        (void) diff; /* Never read if both build options off (0) */
        (void) intv; /* Never read if report option off (0)      */

        if (BETWEEN(TPM_DEBUG_REPORT_INTERVAL, 0, intv)) {
                log_dbg("Thread %d:%lx running for %ld s.\n",
                        getpid(), (unsigned long) e->thr, diff);
                e->last = now;
        }

        if (BETWEEN(TPM_DEBUG_ABORT_TIMEOUT, 0, diff))
                assert(false); /* TODO: Grab a coffee and fire up GDB */
}
#endif

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
#ifdef CONFIG_OUROBOROS_DEBUG
                tpm_debug_thread(e);
#endif
                if (e->kill) {
                        pthread_t thr = e->thr;
                        list_del(&e->next);
                        free(e);
                        pthread_mutex_unlock(&tpm->mtx);

                        pthread_join(thr, NULL);

                        pthread_mutex_lock(&tpm->mtx);
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

static int __tpm(struct tpm * tpm)
{
        struct timespec dl;
        struct timespec to = TIMESPEC_INIT_MS(TPM_TIMEOUT);

        clock_gettime(PTHREAD_COND_CLOCK, &dl);
        ts_add(&dl, &to, &dl);

        pthread_mutex_lock(&tpm->mtx);

        if (tpm->state != TPM_RUNNING) {
                tpm_join(tpm);
                pthread_mutex_unlock(&tpm->mtx);
                return -1;
        }

        tpm_join(tpm);

        if (tpm->cur - tpm->wrk < tpm->min) {
                size_t i;
                for (i = 0; i < tpm->inc; ++i) {
                        struct pthr_el * e = malloc(sizeof(*e));
                        if (e == NULL)
                                break;

                        memset(e, 0, sizeof(*e));

                        if (pthread_create(&e->thr, NULL, tpm->func, tpm->o)) {
                                free(e);
                                break;
                        }

                        list_add(&e->next, &tpm->pool);
                }

                tpm->cur += i;
        }

        pthread_cleanup_push(__cleanup_mutex_unlock, &tpm->mtx);

        if (pthread_cond_timedwait(&tpm->cond, &tpm->mtx, &dl) == ETIMEDOUT)
                if (tpm->cur - tpm->wrk > tpm->min)
                        tpm_kill(tpm);

        pthread_cleanup_pop(true);

        return 0;
}

static void * tpmgr(void * o)
{
        while (__tpm((struct tpm *) o) == 0);

        return (void *) 0;
}

struct tpm * tpm_create(size_t min,
                        size_t inc,
                        void * (* func)(void *),
                        void * o)
{
        struct tpm *       tpm;
        pthread_condattr_t cattr;

        assert(func != NULL);
        assert(inc > 0);

        tpm = malloc(sizeof(*tpm));
        if (tpm == NULL)
                goto fail_malloc;

        if (pthread_mutex_init(&tpm->mtx, NULL))
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
        pthread_mutex_destroy(&tpm->mtx);
 fail_lock:
        free(tpm);
 fail_malloc:
        return NULL;
}

int tpm_start(struct tpm * tpm)
{
        pthread_mutex_lock(&tpm->mtx);

        if (pthread_create(&tpm->mgr, NULL, tpmgr, tpm)) {
                pthread_mutex_unlock(&tpm->mtx);
                return -1;
        }

        tpm->state = TPM_RUNNING;

        pthread_mutex_unlock(&tpm->mtx);

        return 0;
}

void tpm_stop(struct tpm * tpm)
{
        pthread_mutex_lock(&tpm->mtx);

        if (tpm->state != TPM_RUNNING) {
                pthread_mutex_unlock(&tpm->mtx);
                return;
        }

        tpm->state = TPM_NULL;

        pthread_mutex_unlock(&tpm->mtx);

        pthread_join(tpm->mgr, NULL);
}

void tpm_destroy(struct tpm * tpm)
{
        pthread_mutex_destroy(&tpm->mtx);
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

void tpm_begin_work(struct tpm * tpm)
{
        struct pthr_el * e;

#ifdef CONFIG_OUROBOROS_DEBUG
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
#endif

        pthread_mutex_lock(&tpm->mtx);

        e = tpm_pthr_el(tpm, pthread_self());
        if (e != NULL) {
                e->busy = true;
                ++tpm->wrk;
#ifdef CONFIG_OUROBOROS_DEBUG
                e->start = now;
                e->last  = now;
#endif
        }

        pthread_cond_signal(&tpm->cond);

        pthread_mutex_unlock(&tpm->mtx);
}

void tpm_wait_work(struct tpm * tpm)
{
        struct pthr_el * e;

        pthread_mutex_lock(&tpm->mtx);

        e = tpm_pthr_el(tpm, pthread_self());
        if (e != NULL)
                e->wait = true;

        pthread_mutex_unlock(&tpm->mtx);
}

void tpm_end_work(struct tpm * tpm)
{
        struct pthr_el * e;

        pthread_mutex_lock(&tpm->mtx);

        e = tpm_pthr_el(tpm, pthread_self());
        if (e != NULL) {
                e->busy = false;
                --tpm->wrk;
        }

        pthread_mutex_unlock(&tpm->mtx);
}
