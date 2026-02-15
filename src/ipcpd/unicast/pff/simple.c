/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Simple PDU Forwarding Function
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

#include <ouroboros/errno.h>

#include "pft.h"
#include "simple.h"

#include <assert.h>
#include <pthread.h>

struct pff_i {
        struct pft *     pft;
        pthread_rwlock_t lock;
};

struct pff_ops simple_pff_ops = {
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

        tmp->pft = pft_create(PFT_SIZE, false);
        if (tmp->pft == NULL) {
                pthread_rwlock_destroy(&tmp->lock);
                free(tmp);
                return NULL;
        }

        return tmp;
}

void simple_pff_destroy(struct pff_i * pff_i)
{
        assert(pff_i);

        pft_destroy(pff_i->pft);

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
        int * fds;

        assert(pff_i);
        assert(fd);
        assert(len > 0);

        (void) len;

        fds = malloc(sizeof(*fds));
        if (fds == NULL)
                return -ENOMEM;

        *fds = *fd;

        if (pft_insert(pff_i->pft, addr, fds, 1)) {
                free(fds);
                return -1;
        }

        return 0;
}

int simple_pff_update(struct pff_i * pff_i,
                      uint64_t       addr,
                      int *          fd,
                      size_t         len)
{
        int * fds;

        assert(pff_i);
        assert(fd);
        assert(len > 0);

        (void) len;

        fds = malloc(sizeof(*fds));
        if (fds == NULL)
                return -ENOMEM;

        *fds = *fd;

        if (pft_delete(pff_i->pft, addr)) {
                free(fds);
                return -1;
        }

        if (pft_insert(pff_i->pft, addr, fds, 1)) {
                free(fds);
                return -1;
        }

        return 0;
}

int simple_pff_del(struct pff_i * pff_i,
                   uint64_t       addr)
{
        assert(pff_i);

        if (pft_delete(pff_i->pft, addr))
                return -1;

        return 0;
}

void simple_pff_flush(struct pff_i * pff_i)
{
        assert(pff_i);

        pft_flush(pff_i->pft);
}

int simple_pff_nhop(struct pff_i * pff_i,
                    uint64_t       addr)
{
        int *  fds;
        size_t len;
        int    fd = -1;

        assert(pff_i);

        pthread_rwlock_rdlock(&pff_i->lock);

        if (pft_lookup(pff_i->pft, addr, &fds, &len) == 0)
                fd = *fds;

        pthread_rwlock_unlock(&pff_i->lock);

        return fd;
}
