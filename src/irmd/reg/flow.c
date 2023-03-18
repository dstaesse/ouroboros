/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager - Registry - Flows
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#define OUROBOROS_PREFIX "reg-flow"

#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/pthread.h>

#include "flow.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct reg_flow * reg_flow_create(pid_t     n_pid,
                                  pid_t     n_1_pid,
                                  int       flow_id,
                                  qosspec_t qs)
{
        pthread_condattr_t cattr;
        struct reg_flow *  f;

        f = malloc(sizeof(*f));
        if (f == NULL)
                goto fail_malloc;

        memset(f, 0, sizeof(*f));

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&f->cond, &cattr))
                goto fail_cond;

        if (pthread_mutex_init(&f->mtx, NULL))
                goto fail_mutex;

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

        if (clock_gettime(CLOCK_MONOTONIC, &f->t0) < 0)
                log_warn("Failed to set timestamp.");

        pthread_condattr_destroy(&cattr);

        f->n_pid   = n_pid;
        f->n_1_pid = n_1_pid;
        f->flow_id = flow_id;
        f->qs      = qs;

        f->state = FLOW_ALLOC_PENDING;

        return f;

 fail_n_1_rbuff:
        shm_rbuff_destroy(f->n_rb);
 fail_n_rbuff:
        pthread_mutex_destroy(&f->mtx);
 fail_mutex:
        pthread_cond_destroy(&f->cond);
 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        free(f);
 fail_malloc:
        return NULL;
}

static void cancel_irm_destroy(void * o)
{
        struct reg_flow * f = (struct reg_flow *) o;

        pthread_mutex_unlock(&f->mtx);

        pthread_cond_destroy(&f->cond);
        pthread_mutex_destroy(&f->mtx);

        shm_rbuff_destroy(f->n_rb);
        shm_rbuff_destroy(f->n_1_rb);

        free(f);
}

void reg_flow_destroy(struct reg_flow * f)
{
        assert(f);

        pthread_mutex_lock(&f->mtx);

        assert(f->data.len == 0);

        if (f->state == FLOW_DESTROY) {
                pthread_mutex_unlock(&f->mtx);
                return;
        }

        if (f->state == FLOW_ALLOC_PENDING)
                f->state = FLOW_DESTROY;
        else
                f->state = FLOW_NULL;

        pthread_cond_broadcast(&f->cond);

        pthread_cleanup_push(cancel_irm_destroy, f);

        while (f->state != FLOW_NULL)
                pthread_cond_wait(&f->cond, &f->mtx);

        pthread_cleanup_pop(true);
}

enum flow_state reg_flow_get_state(struct reg_flow * f)
{
        enum flow_state state;

        assert(f);

        pthread_mutex_lock(&f->mtx);

        state = f->state;

        pthread_mutex_unlock(&f->mtx);

        return state;
}

void reg_flow_set_state(struct reg_flow * f,
                        enum flow_state   state)
{
        assert(f);
        assert(state != FLOW_DESTROY);

        pthread_mutex_lock(&f->mtx);

        f->state = state;
        pthread_cond_broadcast(&f->cond);

        pthread_mutex_unlock(&f->mtx);
}

int reg_flow_wait_state(struct reg_flow * f,
                        enum flow_state   state,
                        struct timespec * dl)
{
        int ret = 0;
        int s;

        assert(f);
        assert(state != FLOW_NULL);
        assert(state != FLOW_DESTROY);
        assert(state != FLOW_DEALLOC_PENDING);

        pthread_mutex_lock(&f->mtx);

        assert(f->state != FLOW_NULL);

        pthread_cleanup_push(__cleanup_mutex_unlock, &f->mtx);

        while (!(f->state == state ||
                 f->state == FLOW_DESTROY ||
                 f->state == FLOW_DEALLOC_PENDING) &&
               ret != -ETIMEDOUT) {
                if (dl != NULL)
                        ret = -pthread_cond_timedwait(&f->cond,
                                                      &f->mtx,
                                                      dl);
                else
                        ret = -pthread_cond_wait(&f->cond,
                                                 &f->mtx);
        }

        if (f->state == FLOW_DESTROY ||
            f->state == FLOW_DEALLOC_PENDING ||
            ret == -ETIMEDOUT) {
                f->state = FLOW_NULL;
                pthread_cond_broadcast(&f->cond);
        }

        s = f->state;

        pthread_cleanup_pop(true);

        return ret ? ret : s;
}
