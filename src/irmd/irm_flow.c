/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager - Flows
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

#include <ouroboros/config.h>

#include "irm_flow.h"

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

struct irm_flow * irm_flow_create()
{
        struct irm_flow * f = malloc(sizeof(*f));
        if (f == NULL)
                return NULL;

        f->n_api   = -1;
        f->n_1_api = -1;
        f->port_id = -1;
        f->n_rb    = NULL;
        f->n_1_rb  = NULL;

        f->state   = FLOW_NULL;

        if (pthread_cond_init(&f->state_cond, NULL)) {
                free(f);
                return NULL;
        }

        if (pthread_mutex_init(&f->state_lock, NULL)) {
                free(f);
                return NULL;
        }

        f->t0.tv_sec  = 0;
        f->t0.tv_nsec = 0;

        return f;
}

void irm_flow_destroy(struct irm_flow * f)
{
        assert(f);

        pthread_mutex_lock(&f->state_lock);

        if (f->state == FLOW_DESTROY) {
                pthread_mutex_unlock(&f->state_lock);
                return;
        }

        if (f->state == FLOW_ALLOC_PENDING)
                f->state = FLOW_DESTROY;
        else
                f->state = FLOW_NULL;

        pthread_cond_signal(&f->state_cond);

        while (f->state != FLOW_NULL)
                pthread_cond_wait(&f->state_cond, &f->state_lock);

        pthread_mutex_unlock(&f->state_lock);

        pthread_cond_destroy(&f->state_cond);
        pthread_mutex_destroy(&f->state_lock);

        shm_rbuff_destroy(f->n_rb);
        shm_rbuff_destroy(f->n_1_rb);

        free(f);
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

void irm_flow_set_state(struct irm_flow * f, enum flow_state state)
{
        assert(f);
        assert(state != FLOW_NULL);
        assert(state != FLOW_DESTROY);

        pthread_mutex_lock(&f->state_lock);

        f->state = state;
        pthread_cond_broadcast(&f->state_cond);

        pthread_mutex_unlock(&f->state_lock);
}

enum flow_state irm_flow_wait_state(struct irm_flow * f, enum flow_state state)
{
        assert(f);
        assert(state != FLOW_NULL);
        assert(state != FLOW_DESTROY);

        pthread_mutex_lock(&f->state_lock);

        while (!(f->state == state || f->state == FLOW_DESTROY))
                pthread_cond_wait(&f->state_cond, &f->state_lock);

        if (state == FLOW_DESTROY) {
                f->state = FLOW_NULL;
                pthread_cond_broadcast(&f->state_cond);
        }

        state = f->state;

        pthread_mutex_unlock(&f->state_lock);

        return state;
}
