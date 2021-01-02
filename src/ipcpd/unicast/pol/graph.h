/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Undirected graph structure
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

#ifndef OUROBOROS_IPCPD_UNICAST_GRAPH_H
#define OUROBOROS_IPCPD_UNICAST_GRAPH_H

#include <ouroboros/list.h>
#include <ouroboros/qos.h>

#include <inttypes.h>

enum routing_algo {
         ROUTING_SIMPLE = 0,
         ROUTING_LFA,
         ROUTING_ECMP
};

struct nhop {
        struct list_head next;
        uint64_t         nhop;
};

struct routing_table {
        struct list_head next;
        uint64_t         dst;
        struct list_head nhops;
};

struct graph * graph_create(void);

void           graph_destroy(struct graph * graph);

int            graph_update_edge(struct graph * graph,
                                 uint64_t       s_addr,
                                 uint64_t       d_addr,
                                 qosspec_t      qs);

int            graph_del_edge(struct graph * graph,
                              uint64_t       s_addr,
                              uint64_t       d_addr);

int            graph_routing_table(struct graph *     graph,
                                   enum routing_algo  algo,
                                   uint64_t           s_addr,
                                   struct list_head * table);

void           graph_free_routing_table(struct graph *     graph,
                                        struct list_head * table);

#endif /* OUROBOROS_IPCPD_UNICAST_GRAPH_H */
