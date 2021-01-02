/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Policy for PFF supporting multipath routing
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *    Nick Aerts        <nick.aerts@ugent.be>
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
#include "multipath_pff.h"

#include <string.h>
#include <assert.h>
#include <pthread.h>

struct pff_i {
        struct pft *     pft;
        pthread_rwlock_t lock;
};

struct pol_pff_ops multipath_pff_ops = {
        .create            = multipath_pff_create,
        .destroy           = multipath_pff_destroy,
        .lock              = multipath_pff_lock,
        .unlock            = multipath_pff_unlock,
        .add               = multipath_pff_add,
        .update            = multipath_pff_update,
        .del               = multipath_pff_del,
        .flush             = multipath_pff_flush,
        .nhop              = multipath_pff_nhop,
        .flow_state_change = NULL
};

struct pff_i * multipath_pff_create(void)
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

void multipath_pff_destroy(struct pff_i * pff_i)
{
        assert(pff_i);

        pft_destroy(pff_i->pft);

        pthread_rwlock_destroy(&pff_i->lock);
        free(pff_i);
}

void multipath_pff_lock(struct pff_i * pff_i)
{
        pthread_rwlock_wrlock(&pff_i->lock);
}

void multipath_pff_unlock(struct pff_i * pff_i)
{
        pthread_rwlock_unlock(&pff_i->lock);
}

int multipath_pff_add(struct pff_i * pff_i,
                      uint64_t       addr,
                      int *          fds,
                      size_t         len)
{
        int * tmp;

        assert(pff_i);
        assert(fds);
        assert(len > 0);

        tmp = malloc(len * sizeof(*tmp));
        if (tmp == NULL)
                return -ENOMEM;

        memcpy(tmp,fds, len * sizeof(*tmp));

        if (pft_insert(pff_i->pft, addr, tmp, len)) {
                free(tmp);
                return -1;
        }

        return 0;
}

int multipath_pff_update(struct pff_i * pff_i,
                         uint64_t       addr,
                         int *          fds,
                         size_t         len)
{
        int * tmp;

        assert(pff_i);
        assert(fds);
        assert(len > 0);

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return -ENOMEM;

        memcpy(tmp,fds, len * sizeof(*tmp));

        if (pft_delete(pff_i->pft, addr)) {
                free(tmp);
                return -1;
        }

        if (pft_insert(pff_i->pft, addr, tmp, 1)) {
                free(tmp);
                return -1;
        }

        return 0;
}

int multipath_pff_del(struct pff_i * pff_i,
                      uint64_t       addr)
{
        assert(pff_i);

        if (pft_delete(pff_i->pft, addr))
                return -1;

        return 0;
}

void multipath_pff_flush(struct pff_i * pff_i)
{
        assert(pff_i);

        pft_flush(pff_i->pft);
}

int multipath_pff_nhop(struct pff_i * pff_i,
                       uint64_t       addr)
{
        int    fd;
        int *  fds;
        size_t len;

        assert(pff_i);

        pthread_rwlock_rdlock(&pff_i->lock);

        if (pft_lookup(pff_i->pft, addr, &fds, &len)) {
                pthread_rwlock_unlock(&pff_i->lock);
                return -1;
        }

        fd = *fds;

        assert(len > 0);

        /* Rotate fds left. */
        memcpy(fds, fds + 1, (len - 1) * sizeof(*fds));
        fds[len - 1] = fd;

        pthread_rwlock_unlock(&pff_i->lock);

        return fd;
}
