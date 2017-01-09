/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * PDU Forwarding Function
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "pff"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/hashtable.h>
#include <ouroboros/errno.h>

#include <assert.h>
#include <pthread.h>

#include "pff.h"

struct pff {
        struct htable * table;
        pthread_mutex_t lock;
};

struct pff * pff_create(void)
{
        struct pff * tmp;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        tmp->table = htable_create(PFT_SIZE, false);
        if (tmp->table == NULL) {
                free(tmp);
                return NULL;
        }

        pthread_mutex_init(&tmp->lock, NULL);

        return tmp;
}

int pff_destroy(struct pff * instance)
{
        assert(instance);

        htable_destroy(instance->table);
        pthread_mutex_destroy(&instance->lock);
        free(instance);

        return 0;
}

int pff_add(struct pff * instance, uint64_t addr, int fd)
{
        int * val;

        assert(instance);

        val = malloc(sizeof(*val));
        if (val == NULL)
                return -ENOMEM;
        *val = fd;

        pthread_mutex_lock(&instance->lock);
        if (htable_insert(instance->table, addr, val)) {
                pthread_mutex_unlock(&instance->lock);
                free(val);
                return -1;
        }
        pthread_mutex_unlock(&instance->lock);

        return 0;
}

int pff_update(struct pff * instance, uint64_t addr, int fd)
{
        int * val;

        assert(instance);

        val = malloc(sizeof(*val));
        if (val == NULL)
                return -ENOMEM;
        *val = fd;

        pthread_mutex_lock(&instance->lock);
        if (htable_delete(instance->table, addr)) {
                pthread_mutex_unlock(&instance->lock);
                free(val);
                return -1;
        }

        if (htable_insert(instance->table, addr, val)) {
                pthread_mutex_unlock(&instance->lock);
                free(val);
                return -1;
        }
        pthread_mutex_unlock(&instance->lock);

        return 0;
}

int pff_remove(struct pff * instance, uint64_t addr)
{
        assert(instance);

        pthread_mutex_lock(&instance->lock);
        if (htable_delete(instance->table, addr)) {
                pthread_mutex_unlock(&instance->lock);
                return -1;
        }
        pthread_mutex_unlock(&instance->lock);

        return 0;
}

int pff_nhop(struct pff * instance, uint64_t addr)
{
        int * j;
        int   fd;

        assert(instance);

        pthread_mutex_lock(&instance->lock);
        j = (int *) htable_lookup(instance->table, addr);
        if (j == NULL) {
                pthread_mutex_unlock(&instance->lock);
                return -1;
        }
        fd = *j;
        pthread_mutex_unlock(&instance->lock);

        return fd;
}
