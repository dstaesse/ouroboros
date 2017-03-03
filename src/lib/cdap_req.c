/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * CDAP - CDAP request management
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
#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>

#include "cdap_req.h"

#include <stdlib.h>
#include <assert.h>

struct cdap_req * cdap_req_create(cdap_key_t key)
{
        struct cdap_req * creq = malloc(sizeof(*creq));
        pthread_condattr_t cattr;

        if (creq == NULL)
                return NULL;

        creq->key = key;
        creq->state     = REQ_INIT;

        creq->response = -1;
        creq->data.data = NULL;
        creq->data.len  = 0;

        pthread_condattr_init(&cattr);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        pthread_cond_init(&creq->cond, &cattr);
        pthread_mutex_init(&creq->lock, NULL);

        list_head_init(&creq->next);

        clock_gettime(PTHREAD_COND_CLOCK, &creq->birth);

        return creq;
}

void cdap_req_destroy(struct cdap_req * creq)
{
        assert(creq);

        pthread_mutex_lock(&creq->lock);

        switch(creq->state) {
        case REQ_DESTROY:
                pthread_mutex_unlock(&creq->lock);
                return;
        case REQ_INIT:
                creq->state = REQ_NULL;
                pthread_cond_broadcast(&creq->cond);
                break;
        case REQ_PENDING:
        case REQ_RESPONSE:
                creq->state = REQ_DESTROY;
                pthread_cond_broadcast(&creq->cond);
                break;
        default:
                break;
        }

        while (creq->state != REQ_NULL)
                pthread_cond_wait(&creq->cond, &creq->lock);

        pthread_mutex_unlock(&creq->lock);

        pthread_cond_destroy(&creq->cond);
        pthread_mutex_destroy(&creq->lock);

        free(creq);
}

int cdap_req_wait(struct cdap_req * creq)
{
        struct timespec timeout = {(CDAP_REPLY_TIMEOUT / 1000),
                                   (CDAP_REPLY_TIMEOUT % 1000) * MILLION};
        struct timespec abstime;
        int ret = -1;

        assert(creq);

        ts_add(&creq->birth, &timeout, &abstime);

        pthread_mutex_lock(&creq->lock);

        if (creq->state != REQ_INIT) {
                pthread_mutex_unlock(&creq->lock);
                return -EINVAL;
        }

        creq->state = REQ_PENDING;
        pthread_cond_broadcast(&creq->cond);

        while (creq->state == REQ_PENDING && ret != -ETIMEDOUT)
                ret = -pthread_cond_timedwait(&creq->cond,
                                              &creq->lock,
                                              &abstime);

        switch(creq->state) {
        case REQ_DESTROY:
                ret = -1;
        case REQ_PENDING:
                creq->state = REQ_NULL;
                pthread_cond_broadcast(&creq->cond);
                break;
        case REQ_RESPONSE:
                creq->state = REQ_DONE;
                pthread_cond_broadcast(&creq->cond);
                break;
        default:
                assert(false);
                break;
        }

        pthread_mutex_unlock(&creq->lock);

        return ret;
}

void cdap_req_respond(struct cdap_req * creq,
                      int               response,
                      buffer_t          data)
{
        assert(creq);

        pthread_mutex_lock(&creq->lock);

        while (creq->state == REQ_INIT)
                pthread_cond_wait(&creq->cond, &creq->lock);

        if (creq->state != REQ_PENDING) {
                creq->state = REQ_NULL;
                pthread_cond_broadcast(&creq->cond);
                pthread_mutex_unlock(&creq->lock);
                return;
        }

        creq->state    = REQ_RESPONSE;
        creq->response = response;
        creq->data     = data;

        pthread_cond_broadcast(&creq->cond);

        while (creq->state == REQ_RESPONSE)
                pthread_cond_wait(&creq->cond, &creq->lock);

        creq->state = REQ_NULL;
        pthread_cond_broadcast(&creq->cond);

        pthread_mutex_unlock(&creq->lock);
}
