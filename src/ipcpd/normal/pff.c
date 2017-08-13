/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * PDU Forwarding Function
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

#define OUROBOROS_PREFIX "pff"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/hashtable.h>
#include <ouroboros/errno.h>

#include <assert.h>
#include <pthread.h>

#include "pff.h"

struct pff {
        struct htable *  table;
        pthread_rwlock_t lock;
};

struct pff * pff_create(void)
{
        struct pff * tmp;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        if (pthread_rwlock_init(&tmp->lock, NULL)) {
                free(tmp);
                return NULL;
        }

        tmp->table = htable_create(PFT_SIZE, false);
        if (tmp->table == NULL) {
                pthread_rwlock_destroy(&tmp->lock);
                free(tmp);
                return NULL;
        }

        return tmp;
}

void pff_destroy(struct pff * instance)
{
        assert(instance);

        htable_destroy(instance->table);

        pthread_rwlock_destroy(&instance->lock);
        free(instance);
}

void pff_lock(struct pff * instance)
{
        pthread_rwlock_wrlock(&instance->lock);
}

void pff_unlock(struct pff * instance)
{
        pthread_rwlock_unlock(&instance->lock);
}

int pff_add(struct pff * instance,
            uint64_t     addr,
            int          fd)
{
        int * val;

        assert(instance);

        val = malloc(sizeof(*val));
        if (val == NULL)
                return -ENOMEM;

        *val = fd;

        if (htable_insert(instance->table, addr, val)) {
                free(val);
                return -1;
        }

        return 0;
}

int pff_update(struct pff * instance,
               uint64_t     addr,
               int          fd)
{
        int * val;

        assert(instance);

        val = malloc(sizeof(*val));
        if (val == NULL)
                return -ENOMEM;
        *val = fd;

        if (htable_delete(instance->table, addr)) {
                free(val);
                return -1;
        }

        if (htable_insert(instance->table, addr, val)) {
                free(val);
                return -1;
        }

        return 0;
}

int pff_remove(struct pff * instance,
               uint64_t     addr)
{
        assert(instance);

        if (htable_delete(instance->table, addr))
                return -1;

        return 0;
}

void pff_flush(struct pff * instance)
{
        assert(instance);

        htable_flush(instance->table);
}

int pff_nhop(struct pff * instance,
             uint64_t     addr)
{
        int * j;
        int   fd = -1;

        assert(instance);

        pthread_rwlock_rdlock(&instance->lock);

        j = (int *) htable_lookup(instance->table, addr);
        if (j != NULL)
                fd = *j;

        pthread_rwlock_unlock(&instance->lock);

        return fd;
}
