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
#include <ouroboros/rib.h>

#include "routing.h"
#include "ribmgr.h"
#include "ribconfig.h"
#include "ipcp.h"

#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#define ADDR_SIZE 30

struct edge {
        struct list_head next;

        uint64_t         addr;

        qosspec_t        qs;
};

struct vertex {
        struct list_head next;

        uint64_t         addr;

        struct list_head edges;
};

struct routing_i {
        struct pff *     pff;
        struct list_head vertices;
};

struct {
        struct nbs *       nbs;
        struct nb_notifier nb_notifier;
        char               fso_path[RIB_MAX_PATH_LEN + 1];
} routing;

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

struct routing_i * routing_i_create(struct pff * pff)
{
        struct routing_i * tmp;

        assert(pff);

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        tmp->pff = pff;

        list_head_init(&tmp->vertices);

        return tmp;
}

void routing_i_destroy(struct routing_i * instance)
{
        assert(instance);

        free(instance);
}

static int routing_neighbor_event(enum nb_event event,
                                  struct conn   conn)
{
        char addr[ADDR_SIZE];
        char path[RIB_MAX_PATH_LEN + 1];

        strcpy(path, routing.fso_path);
        snprintf(addr, ADDR_SIZE, "%" PRIx64, conn.conn_info.addr);
        rib_path_append(path, addr);

        switch (event) {
        case NEIGHBOR_ADDED:
                if (rib_add(routing.fso_path, addr)) {
                        log_err("Failed to add FSO.");
                        return -1;
                }

                if (rib_write(path, &conn.flow_info.qs,
                              sizeof(conn.flow_info.qs))) {
                        log_err("Failed to write qosspec to FSO.");
                        rib_del(path);
                        return -1;
                }

                break;
        case NEIGHBOR_REMOVED:
                if (rib_del(path)) {
                        log_err("Failed to remove FSO.");
                        return -1;
                }

                break;
        case NEIGHBOR_QOS_CHANGE:
                if (rib_write(path, &conn.flow_info.qs,
                              sizeof(conn.flow_info.qs))) {
                        log_err("Failed to write qosspec to FSO.");
                        return -1;
                }

                break;
        default:
                log_info("Unsupported event for routing.");
                break;
        }

        return 0;
}

int routing_init(struct nbs * nbs)
{
        char addr[ADDR_SIZE];

        if (rib_add(RIB_ROOT, ROUTING_NAME))
                return -1;

        rib_path_append(routing.fso_path, ROUTING_NAME);

        snprintf(addr, ADDR_SIZE, "%" PRIx64, ipcpi.dt_addr);

        if (rib_add(routing.fso_path, addr)) {
                rib_del(ROUTING_PATH);
                return -1;
        }

        rib_path_append(routing.fso_path, addr);

        routing.nbs = nbs;

        routing.nb_notifier.notify_call = routing_neighbor_event;
        if (nbs_reg_notifier(routing.nbs, &routing.nb_notifier)) {
                rib_del(ROUTING_PATH);
                return -1;
        }

        return 0;
}

void routing_fini(void)
{
        rib_del(ROUTING_PATH);

        nbs_unreg_notifier(routing.nbs, &routing.nb_notifier);
}
