/*
 * Ouroboros - Copyright (C) 2016
 *
 * Normal IPCP - RIB Manager - CDAP request
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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
#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>

#include "cdap_request.h"

#include <stdlib.h>

struct cdap_request * cdap_request_create(enum cdap_opcode code,
                                          char *           name,
                                          int              invoke_id,
                                          struct cdap *    instance)
{
        struct cdap_request * creq = malloc(sizeof(*creq));
        pthread_condattr_t cattr;

        if (creq == NULL)
                return NULL;

        creq->code = code;
        creq->name = name;
        creq->invoke_id = invoke_id;
        creq->instance = instance;
        creq->state = REQ_INIT;
        creq->result = -1;

        pthread_condattr_init(&cattr);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        pthread_cond_init(&creq->cond, &cattr);
        pthread_mutex_init(&creq->lock, NULL);

        INIT_LIST_HEAD(&creq->next);

        return creq;
}

void cdap_request_destroy(struct cdap_request * creq)
{
        if (creq == NULL)
                return;

        pthread_mutex_lock(&creq->lock);

        if (creq->state == REQ_DESTROY) {
                pthread_mutex_unlock(&creq->lock);
                return;
        }

        if (creq->state == REQ_INIT)
                creq->state = REQ_DONE;

        if (creq->state == REQ_PENDING) {
                creq->state = REQ_DESTROY;
                pthread_cond_broadcast(&creq->cond);
        }

        while (creq->state != REQ_DONE)
                pthread_cond_wait(&creq->cond, &creq->lock);

        pthread_mutex_unlock(&creq->lock);

        pthread_cond_destroy(&creq->cond);
        pthread_mutex_destroy(&creq->lock);

        if (creq->name != NULL)
                free(creq->name);

        free(creq);
}

int cdap_request_wait(struct cdap_request * creq)
{
        struct timespec timeout = {(CDAP_REPLY_TIMEOUT / 1000),
                                   (CDAP_REPLY_TIMEOUT % 1000) * MILLION};
        struct timespec abstime;
        int ret = -1;

        if (creq == NULL)
                return -EINVAL;

        clock_gettime(CLOCK_REALTIME, &abstime);
        ts_add(&abstime, &timeout, &abstime);

        pthread_mutex_lock(&creq->lock);

        if (creq->state != REQ_INIT) {
                pthread_mutex_unlock(&creq->lock);
                return -EINVAL;
        }

        creq->state = REQ_PENDING;

        while (creq->state == REQ_PENDING) {
                if ((ret = -pthread_cond_timedwait(&creq->cond,
                                                   &creq->lock,
                                                   &abstime)) == -ETIMEDOUT) {
                        break;
                }
        }

        if (creq->state == REQ_DESTROY)
                ret = -1;

        creq->state = REQ_DONE;
        pthread_cond_broadcast(&creq->cond);

        pthread_mutex_unlock(&creq->lock);

        return ret;
}

void cdap_request_respond(struct cdap_request * creq, int response)
{
        if (creq == NULL)
                return;

        pthread_mutex_lock(&creq->lock);

        if (creq->state != REQ_PENDING) {
                pthread_mutex_unlock(&creq->lock);
                return;
        }

        creq->state = REQ_RESPONSE;
        creq->result = response;
        pthread_cond_broadcast(&creq->cond);

        while (creq->state == REQ_RESPONSE)
                pthread_cond_wait(&creq->cond, &creq->lock);

        pthread_mutex_unlock(&creq->lock);
}
