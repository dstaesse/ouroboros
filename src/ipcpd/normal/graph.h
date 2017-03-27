/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Graph structure
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

#ifndef OUROBOROS_IPCPD_NORMAL_GRAPH_H
#define OUROBOROS_IPCPD_NORMAL_GRAPH_H

#include <ouroboros/list.h>
#include <ouroboros/qos.h>

#include <inttypes.h>

struct routing_table {
        uint64_t dst;
        uint64_t nhop;
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

ssize_t        graph_routing_table(struct graph *           graph,
                                   uint64_t                 s_addr,
                                   struct routing_table *** table);

#endif /* OUROBOROS_IPCPD_NORMAL_GRAPH_H */
