/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Simple PDU Forwarding Function
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

#include <ouroboros/hashtable.h>
#include <ouroboros/errno.h>

#include <assert.h>
#include <pthread.h>

#include "simple_pff.h"

struct pff_i {
        struct htable *  table;
        pthread_rwlock_t lock;
};

struct pol_pff_ops simple_pff_ops = {
        .create            = simple_pff_create,
        .destroy           = simple_pff_destroy,
        .lock              = simple_pff_lock,
        .unlock            = simple_pff_unlock,
        .add               = simple_pff_add,
        .update            = simple_pff_update,
        .del               = simple_pff_del,
        .flush             = simple_pff_flush,
        .nhop              = simple_pff_nhop,
        .flow_state_change = NULL
};

struct pff_i * simple_pff_create(void)
{
        struct pff_i * tmp;

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

void simple_pff_destroy(struct pff_i * pff_i)
{
        assert(pff_i);

        htable_destroy(pff_i->table);

        pthread_rwlock_destroy(&pff_i->lock);
        free(pff_i);
}

void simple_pff_lock(struct pff_i * pff_i)
{
        pthread_rwlock_wrlock(&pff_i->lock);
}

void simple_pff_unlock(struct pff_i * pff_i)
{
        pthread_rwlock_unlock(&pff_i->lock);
}

int simple_pff_add(struct pff_i * pff_i,
                   uint64_t       addr,
                   int *          fd,
                   size_t         len)
{
        int * val;

        assert(pff_i);
        assert(len > 0);

        (void) len;

        val = malloc(sizeof(*val));
        if (val == NULL)
                return -ENOMEM;

        *val = fd[0];

        if (htable_insert(pff_i->table, addr, val, 1)) {
                free(val);
                return -1;
        }

        return 0;
}

int simple_pff_update(struct pff_i * pff_i,
                      uint64_t       addr,
                      int *          fd,
                      size_t         len)
{
        int * val;

        assert(pff_i);
        assert(len > 0);

        (void) len;

        val = malloc(sizeof(*val));
        if (val == NULL)
                return -ENOMEM;
        *val = fd[0];

        if (htable_delete(pff_i->table, addr)) {
                free(val);
                return -1;
        }

        if (htable_insert(pff_i->table, addr, val, 1)) {
                free(val);
                return -1;
        }

        return 0;
}

int simple_pff_del(struct pff_i * pff_i,
                   uint64_t       addr)
{
        assert(pff_i);

        if (htable_delete(pff_i->table, addr))
                return -1;

        return 0;
}

void simple_pff_flush(struct pff_i * pff_i)
{
        assert(pff_i);

        htable_flush(pff_i->table);
}

int simple_pff_nhop(struct pff_i * pff_i,
                    uint64_t       addr)
{
        void * j;
        size_t len;
        int    fd = -1;

        assert(pff_i);

        pthread_rwlock_rdlock(&pff_i->lock);

        if (!htable_lookup(pff_i->table, addr, &j, &len))
                fd = *((int *) j);

        pthread_rwlock_unlock(&pff_i->lock);

        return fd;
}
