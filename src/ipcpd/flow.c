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

#include <stdlib.h>
#include "flow.h"

#define OUROBOROS_PREFIX "ipcpd/flow"

#include <ouroboros/logs.h>
#include <ouroboros/flow.h>

struct flow * flow_create(int port_id)
{
        struct flow * flow = malloc(sizeof *flow);
        if (flow == NULL) {
                LOG_DBGF("Could not malloc flow.");
                return NULL;
        }

        INIT_LIST_HEAD(&flow->list);

        flow->port_id = port_id;
        flow->state   = FLOW_NULL;

        pthread_mutex_init(&flow->lock, NULL);

        return flow;
}

void flow_destroy(struct flow * flow)
{
        if (flow == NULL)
                return;
        free(flow);
}
