/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * The IPC Resource Manager - Flows
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

#define _POSIX_C_SOURCE 200112L

#include "config.h"

#define OUROBOROS_PREFIX "irm_flow"

#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>

#include "irm_flow.h"

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

struct irm_flow * irm_flow_create(pid_t     n_pid,
                                  pid_t     n_1_pid,
                                  int       flow_id,
                                  qosspec_t qs)
{
        pthread_condattr_t cattr;
        struct irm_flow *  f = malloc(sizeof(*f));
        if (f == NULL)
                goto fail_malloc;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&f->state_cond, &cattr))
                goto fail_state_cond;

        if (pthread_mutex_init(&f->state_lock, NULL))
                goto fail_mutex;

        f->n_pid   = n_pid;
        f->n_1_pid = n_1_pid;
        f->flow_id = flow_id;
        f->qs      = qs;
        f->data    = NULL;
        f->len     = 0;

        f->n_rb = shm_rbuff_create(n_pid, flow_id);
        if (f->n_rb == NULL) {
                log_err("Could not create ringbuffer for process %d.", n_pid);
                goto fail_n_rbuff;
        }

        f->n_1_rb = shm_rbuff_create(n_1_pid, flow_id);
        if (f->n_1_rb == NULL) {
                log_err("Could not create ringbuffer for process %d.", n_1_pid);
                goto fail_n_1_rbuff;
        }

        f->state = FLOW_ALLOC_PENDING;

        if (clock_gettime(CLOCK_MONOTONIC, &f->t0) < 0)
                log_warn("Failed to set timestamp.");

        pthread_condattr_destroy(&cattr);

        return f;

 fail_n_1_rbuff:
        shm_rbuff_destroy(f->n_rb);
 fail_n_rbuff:
        pthread_mutex_destroy(&f->state_lock);
 fail_mutex:
        pthread_cond_destroy(&f->state_cond);
 fail_state_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        free(f);
 fail_malloc:
        return NULL;
}

static void cancel_irm_destroy(void * o)
{
        struct irm_flow * f = (struct irm_flow *) o;

        pthread_mutex_unlock(&f->state_lock);

        pthread_cond_destroy(&f->state_cond);
        pthread_mutex_destroy(&f->state_lock);

        shm_rbuff_destroy(f->n_rb);
        shm_rbuff_destroy(f->n_1_rb);

        free(f);
}

void irm_flow_destroy(struct irm_flow * f)
{
        assert(f);

        pthread_mutex_lock(&f->state_lock);

        assert(f->len == 0);

        if (f->state == FLOW_DESTROY) {
                pthread_mutex_unlock(&f->state_lock);
                return;
        }

        if (f->state == FLOW_ALLOC_PENDING)
                f->state = FLOW_DESTROY;
        else
                f->state = FLOW_NULL;

        pthread_cond_signal(&f->state_cond);

        pthread_cleanup_push(cancel_irm_destroy, f);

        while (f->state != FLOW_NULL)
                pthread_cond_wait(&f->state_cond, &f->state_lock);

        pthread_cleanup_pop(true);
}

enum flow_state irm_flow_get_state(struct irm_flow * f)
{
        enum flow_state state;

        assert(f);

        pthread_mutex_lock(&f->state_lock);

        state = f->state;

        pthread_mutex_unlock(&f->state_lock);

        return state;
}

void irm_flow_set_state(struct irm_flow * f,
                        enum flow_state   state)
{
        assert(f);
        assert(state != FLOW_DESTROY);

        pthread_mutex_lock(&f->state_lock);

        f->state = state;
        pthread_cond_broadcast(&f->state_cond);

        pthread_mutex_unlock(&f->state_lock);
}

int irm_flow_wait_state(struct irm_flow * f,
                        enum flow_state   state,
                        struct timespec * timeo)
{
        int ret = 0;
        int s;

        struct timespec dl;

        assert(f);
        assert(state != FLOW_NULL);
        assert(state != FLOW_DESTROY);
        assert(state != FLOW_DEALLOC_PENDING);

        if (timeo != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &dl);
                ts_add(&dl, timeo, &dl);
        }

        pthread_mutex_lock(&f->state_lock);

        assert(f->state != FLOW_NULL);

        pthread_cleanup_push((void *)(void *) pthread_mutex_unlock,
                             &f->state_lock);

        while (!(f->state == state ||
                 f->state == FLOW_DESTROY ||
                 f->state == FLOW_DEALLOC_PENDING) &&
               ret != -ETIMEDOUT) {
                if (timeo == NULL)
                        ret = -pthread_cond_wait(&f->state_cond,
                                                 &f->state_lock);
                else
                        ret = -pthread_cond_timedwait(&f->state_cond,
                                                      &f->state_lock,
                                                      &dl);
        }

        if (f->state == FLOW_DESTROY ||
            f->state == FLOW_DEALLOC_PENDING ||
            ret == -ETIMEDOUT) {
                f->state = FLOW_NULL;
                pthread_cond_broadcast(&f->state_cond);
        }

        s = f->state;

        pthread_cleanup_pop(true);

        return ret ? ret : s;
}
