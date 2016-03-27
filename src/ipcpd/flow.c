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

#include "flow.h"
#include <malloc.h>

#define OUROBOROS_PREFIX "ipcpd/flow"

#include <ouroboros/logs.h>

flow_t * flow_create(port_id_t port_id)
{
        flow_t * flow = malloc(sizeof *flow);
        flow->port_id = port_id;
        flow->flags = FLOW_O_DEFAULT;
        flow->state = FLOW_INIT;

#ifdef FLOW_MT_SAFE
        pthread_mutex_init(&flow->lock, NULL);
#endif
        return flow;
}

void flow_destroy(flow_t * flow)
{
        free(flow);
}

int flow_set_opts(flow_t * flow, uint16_t opts)
{
        if (flow == NULL) {
                LOG_ERR("Non-existing flow.");
                return -1;
        }

#ifdef FLOW_MT_SAFE
        pthread_mutex_lock(&flow->lock);
#endif

        if ((opts & FLOW_O_ACCMODE) == FLOW_O_ACCMODE) {
#ifdef FLOW_MT_SAFE
                pthread_mutex_unlock(&flow->lock);
#endif
                LOG_WARN("Invalid flow options. Setting default.");
                opts = FLOW_O_DEFAULT;
        }

        flow->flags = opts;

#ifdef FLOW_MT_SAFE
                pthread_mutex_unlock(&flow->lock);
#endif
        return 0;
}

uint16_t flow_get_opts(const flow_t * flow)
{
        if (flow == NULL) {
                LOG_ERR("Non-existing flow.");
                return FLOW_O_INVALID;
        }

        return flow->flags;
}
