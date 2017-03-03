/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Routing component of the IPCP
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "routing"

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>

#include "routing.h"
#include "ribmgr.h"

#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

struct edge {
        struct vertex * ep;
        qosspec_t       qs;
};

struct vertex {
        struct list_head next;

        uint64_t         addr;

        struct list_head edges;
};

struct routing {
        struct pff *       pff;
        struct nbs *       nbs;

        struct nb_notifier nb_notifier;

        struct list_head   vertices;
};

static int routing_neighbor_event(enum nb_event event,
                                  struct conn   conn)
{
        (void) conn;

        /* FIXME: React to events here */
        switch (event) {
        case NEIGHBOR_ADDED:
                break;
        case NEIGHBOR_REMOVED:
                break;
        case NEIGHBOR_QOS_CHANGE:
                break;
        default:
                break;
        }

        return 0;
}

#if 0
/* FIXME: If zeroed since it is not used currently */
static int add_vertex(struct routing * instance,
                      uint64_t         addr)
{
        struct vertex *  vertex;

        vertex = malloc(sizeof(*vertex));
        if (vertex == NULL)
                return -1;

        list_head_init(&vertex->next);
        list_head_init(&vertex->edges);
        vertex->addr = addr;

        list_add(&vertex->next, &instance->vertices);

        return 0;
}
#endif

struct routing * routing_create(struct pff * pff,
                                struct nbs * nbs)
{
        struct routing * tmp;

        assert(pff);

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        tmp->pff = pff;
        tmp->nbs = nbs;

        list_head_init(&tmp->vertices);

        tmp->nb_notifier.notify_call = routing_neighbor_event;
        if (nbs_reg_notifier(tmp->nbs, &tmp->nb_notifier)) {
                free(tmp);
                return NULL;
        }

        return tmp;
}

void routing_destroy(struct routing * instance)
{
        assert(instance);

        nbs_unreg_notifier(instance->nbs, &instance->nb_notifier);

        free(instance);
}
