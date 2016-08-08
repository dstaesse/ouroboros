/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager - Flows
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

#ifndef OUROBOROS_IRMD_IRM_FLOW_H
#define OUROBOROS_IRMD_IRM_FLOW_H

#include <ouroboros/list.h>
#include <ouroboros/shared.h>

#include <sys/types.h>
#include <pthread.h>
#include <time.h>

struct irm_flow {
        struct list_head next;

        int              port_id;

        pid_t            n_api;
        pid_t            n_1_api;

        struct timespec  t0;

        enum flow_state  state;
        pthread_cond_t   state_cond;
        pthread_mutex_t  state_lock;
};

struct irm_flow * irm_flow_create();
void              irm_flow_destroy(struct irm_flow * f);

#endif /* OUROBOROS_IRMD_IRM_FLOW_H */
