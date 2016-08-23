/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Flow and Retransmission control component
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "flow-rtx-control"

#define IDS_SIZE 2048

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/list.h>

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

#include "frct.h"


enum conn_state {
        CONN_PENDING = 0,
        CONN_ESTABLISHED
};

struct frct_i {
        uint32_t cep_id;
        uint32_t r_address;
        uint32_t r_cep_id;

        enum conn_state state;
        struct list_head next;
};

struct frct {
        struct dt_const * dtc;
        uint32_t address;

        struct list_head instances;
        pthread_mutex_t instances_lock;

        struct bmp * cep_ids;
        pthread_mutex_t cep_ids_lock;
} * frct = NULL;

static int next_cep_id()
{
        int ret;

        pthread_mutex_lock(&frct->cep_ids_lock);
        ret = bmp_allocate(frct->cep_ids);
        pthread_mutex_unlock(&frct->cep_ids_lock);

        return ret;
}

static int release_cep_id(int id)
{
        int ret;

        pthread_mutex_lock(&frct->cep_ids_lock);
        ret = bmp_release(frct->cep_ids, id);
        pthread_mutex_unlock(&frct->cep_ids_lock);

        return ret;
}

int frct_init(struct dt_const * dtc, uint32_t address)
{
        if (dtc == NULL)
                return -1;

        frct = malloc(sizeof(*frct));
        if (frct == NULL)
                return -1;

        frct->dtc = dtc;
        frct->address = address;

        INIT_LIST_HEAD(&frct->instances);

        if (pthread_mutex_init(&frct->cep_ids_lock, NULL)) {
                free(frct);
                return -1;
        }

        if (pthread_mutex_init(&frct->instances_lock, NULL)) {
                free(frct);
                return -1;
        }

        frct->cep_ids = bmp_create(IDS_SIZE, 0);
        if (frct->cep_ids == NULL) {
                free(frct);
                return -1;
        }

        return 0;
}

int frct_fini()
{
        pthread_mutex_lock(&frct->cep_ids_lock);
        bmp_destroy(frct->cep_ids);
        pthread_mutex_unlock(&frct->cep_ids_lock);
        free(frct);

        return 0;
}

int frct_dt_flow(int fd,
                 enum qos_cube qos)
{
        LOG_MISSING;

        return -1;
}

int frct_rmt_post()
{
        LOG_MISSING;

        return -1;
}

/* Call under instances lock */
static void destroy_frct_i(struct frct_i * instance)
{
        release_cep_id(instance->cep_id);
        list_del(&instance->next);
        free(instance);
}

struct frct_i * frct_i_create(uint32_t      address,
                              buffer_t *    buf,
                              enum qos_cube cube)
{
        struct frct_i * instance;

        if (buf == NULL ||
            buf->data == NULL)
                return NULL;

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return NULL;

        pthread_mutex_lock(&frct->instances_lock);

        instance->r_address = address;
        instance->cep_id = next_cep_id();
        instance->state = CONN_PENDING;

        INIT_LIST_HEAD(&instance->next);
        list_add(&instance->next, &frct->instances);

        pthread_mutex_unlock(&frct->instances_lock);

        /* FIXME: Pack into FRCT header and hand SDU to RMT */

        return instance;
}

int frct_i_accept(struct frct_i * instance,
                  buffer_t *      buf)
{
        if (instance == NULL || buf == NULL || buf->data == NULL)
                return -1;

        pthread_mutex_lock(&frct->instances_lock);
        if (instance->state != CONN_PENDING) {
                pthread_mutex_unlock(&frct->instances_lock);
                return -1;
        }

        instance->state = CONN_ESTABLISHED;
        instance->cep_id = next_cep_id();

        pthread_mutex_unlock(&frct->instances_lock);

        /* FIXME: Pack into FRCT header and hand SDU to RMT */

        return 0;
}

int frct_i_destroy(struct frct_i * instance,
                   buffer_t *      buf)
{
        if (instance == NULL)
                return -1;

        pthread_mutex_lock(&frct->instances_lock);

        if (!(instance->state == CONN_PENDING ||
              instance->state == CONN_ESTABLISHED)) {
                pthread_mutex_unlock(&frct->instances_lock);
                return -1;
        }

        destroy_frct_i(instance);
        pthread_mutex_unlock(&frct->instances_lock);

        if (buf != NULL && buf->data != NULL) {

                /* FIXME: Pack into FRCT header and hand SDU to RMT */
        }

        return 0;
}
