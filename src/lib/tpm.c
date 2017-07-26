/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Threadpool management
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/tpm.h>

#include <pthread.h>
#include <stdlib.h>

#define TPM_TIMEOUT 1000

struct pthr_el {
        struct list_head next;

        bool             join;

        pthread_t        thr;
};

enum tpm_state {
        TPM_NULL = 0,
        TPM_INIT,
        TPM_RUNNING
};

struct {
        size_t           min;
        size_t           inc;
        size_t           max;
        size_t           cur;

        void * (* func)(void *);

        struct list_head pool;

        enum tpm_state   state;

        pthread_cond_t   cond;
        pthread_mutex_t  lock;

        pthread_t        mgr;
} tpm;

static void tpm_join(void)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &tpm.pool) {
                struct pthr_el * e = list_entry(p, struct pthr_el, next);
                if (tpm.state != TPM_RUNNING)
                        while (!e->join)
                                pthread_cond_wait(&tpm.cond, &tpm.lock);

                if (e->join) {
                        pthread_join(e->thr, NULL);
                        list_del(&e->next);
                        free(e);
                }
        }
}

static void * tpmgr(void * o)
{
        struct timespec dl;
        struct timespec to = {(TPM_TIMEOUT / 1000),
                              (TPM_TIMEOUT % 1000) * MILLION};
        (void) o;

        while (true) {
                clock_gettime(PTHREAD_COND_CLOCK, &dl);
                ts_add(&dl, &to, &dl);

                pthread_mutex_lock(&tpm.lock);

                tpm_join();

                if (tpm.state != TPM_RUNNING) {
                        tpm.max = 0;
                        tpm_join();
                        pthread_mutex_unlock(&tpm.lock);
                        break;
                }

                if (tpm.cur < tpm.min) {
                        tpm.max = tpm.inc;

                        while (tpm.cur < tpm.max) {
                                struct pthr_el * e = malloc(sizeof(*e));
                                if (e == NULL)
                                        break;

                                e->join = false;

                                if (pthread_create(&e->thr, NULL,
                                                   tpm.func, NULL)) {
                                        free(e);
                                } else {
                                        list_add(&e->next, &tpm.pool);
                                        ++tpm.cur;
                                }
                        }
                }

                if (pthread_cond_timedwait(&tpm.cond, &tpm.lock, &dl)
                    == ETIMEDOUT)
                        if (tpm.cur > tpm.min )
                                --tpm.max;

                pthread_mutex_unlock(&tpm.lock);
        }

        return (void *) 0;
}

int tpm_init(size_t min,
             size_t inc,
             void * (* func)(void *))
{
        pthread_condattr_t cattr;

        if (pthread_mutex_init(&tpm.lock, NULL))
                goto fail_lock;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&tpm.cond, &cattr))
                goto fail_cond;

        list_head_init(&tpm.pool);

        pthread_condattr_destroy(&cattr);

        tpm.state = TPM_INIT;
        tpm.func  = func;
        tpm.min   = min;
        tpm.inc   = inc;
        tpm.max   = 0;
        tpm.cur   = 0;

        return 0;

 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(&tpm.lock);
 fail_lock:
        return -1;
}

int tpm_start(void)
{
        pthread_mutex_lock(&tpm.lock);

        if (pthread_create(&tpm.mgr, NULL, tpmgr, NULL)) {
                pthread_mutex_unlock(&tpm.lock);
                return -1;
        }

        tpm.state = TPM_RUNNING;

        pthread_mutex_unlock(&tpm.lock);

        return 0;
}

void tpm_stop(void)
{
        pthread_mutex_lock(&tpm.lock);

        tpm.state = TPM_NULL;

        pthread_mutex_unlock(&tpm.lock);
}

void tpm_fini(void)
{
        pthread_join(tpm.mgr, NULL);

        pthread_mutex_destroy(&tpm.lock);
        pthread_cond_destroy(&tpm.cond);
}

bool tpm_check(void)
{
        bool ret;

        pthread_mutex_lock(&tpm.lock);

        ret = tpm.cur > tpm.max;

        pthread_mutex_unlock(&tpm.lock);

        return ret;
}

void tpm_inc(void)
{
        pthread_mutex_lock(&tpm.lock);

        ++tpm.cur;

        pthread_mutex_unlock(&tpm.lock);
}

void tpm_dec(void)
{
        pthread_mutex_lock(&tpm.lock);

        --tpm.cur;

        pthread_cond_signal(&tpm.cond);

        pthread_mutex_unlock(&tpm.lock);
}

void tpm_exit(void)
{
        struct list_head * p;
        pthread_t          id;

        id = pthread_self();

        pthread_mutex_lock(&tpm.lock);

        --tpm.cur;

        list_for_each(p, &tpm.pool) {
                struct pthr_el * e = list_entry(p, struct pthr_el, next);
                if (e->thr == id) {
                        e->join = true;
                        break;
                }
        }

        pthread_cond_signal(&tpm.cond);

        pthread_mutex_unlock(&tpm.lock);
}
