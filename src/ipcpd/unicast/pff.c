/*
 * Ouroboros - Copyright (C) 2016 - 2019
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

#include <ouroboros/errno.h>
#include <ouroboros/logs.h>

#include "pff.h"
#include "pol-pff-ops.h"
#include "pol/alternate_pff.h"
#include "pol/simple_pff.h"

struct pff {
        struct pol_pff_ops * ops;
        struct pff_i *       pff_i;
};

struct pff * pff_create(enum pol_pff pol)
{
        struct pff * pff;

        pff = malloc(sizeof(*pff));
        if (pff == NULL)
                return NULL;

        switch (pol) {
        case PFF_ALTERNATE:
                log_dbg("Using alternate PFF policy.");
                pff->ops = &alternate_pff_ops;
                break;
        case PFF_SIMPLE:
                log_dbg("Using simple PFF policy.");
                pff->ops = &simple_pff_ops;
                break;
        default:
                goto err;
        }

        pff->pff_i = pff->ops->create();
        if (pff->pff_i == NULL)
                goto err;

        return pff;
 err:
        free(pff);
        return NULL;
}

void pff_destroy(struct pff * pff)
{
        pff->ops->destroy(pff->pff_i);

        free(pff);
}

void pff_lock(struct pff * pff)
{
        return pff->ops->lock(pff->pff_i);
}

void pff_unlock(struct pff * pff)
{
        return pff->ops->unlock(pff->pff_i);
}

int pff_add(struct pff * pff,
            uint64_t     addr,
            int *        fd,
            size_t       len)
{
        return pff->ops->add(pff->pff_i, addr, fd, len);
}

int pff_update(struct pff * pff,
               uint64_t     addr,
               int *        fd,
               size_t       len)
{
        return pff->ops->update(pff->pff_i, addr, fd, len);
}

int pff_del(struct pff * pff,
            uint64_t     addr)
{
        return pff->ops->del(pff->pff_i, addr);
}

void pff_flush(struct pff * pff)
{
        return pff->ops->flush(pff->pff_i);
}

int pff_nhop(struct pff * pff,
             uint64_t     addr)
{
        return pff->ops->nhop(pff->pff_i, addr);
}

int pff_flow_state_change(struct pff * pff,
                          int          fd,
                          bool         up)
{
        if (pff->ops->flow_state_change != NULL)
                return pff->ops->flow_state_change(pff->pff_i, fd, up);

        return 0;
}
