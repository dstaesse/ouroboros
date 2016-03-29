/*
 * Ouroboros - Copyright (C) 2016
 *
 * Flows
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#ifndef OUROBOROS_FLOW_H
#define OUROBOROS_FLOW_H

#include <ouroboros/common.h>

#include <pthread.h>

/* same values as fcntl.h */
#define FLOW_O_RDONLY   00000000
#define FLOW_O_WRONLY   00000001
#define FLOW_O_RDWR     00000002
#define FLOW_O_ACCMODE  00000003

#define FLOW_O_NONBLOCK 00004000
#define FLOW_O_DEFAULT  00000002

#define FLOW_O_INVALID  00037777

enum flow_state {
        FLOW_INIT = 0,
        FLOW_ALLOCATED,
        FLOW_PENDING
};

typedef struct flow {
        int32_t         port_id;
        uint16_t        oflags;
        enum flow_state state;

        pthread_mutex_t lock;
} flow_t;

flow_t * flow_create(int32_t   port_id);
void     flow_destroy(flow_t * flow);

int      flow_set_opts(flow_t * flow, uint16_t opts);
uint16_t flow_get_opts(const flow_t * flow);

#endif /* OUROBOROS_FLOW_H */
