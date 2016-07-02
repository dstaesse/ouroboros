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

#ifndef OUROBOROS_IPCP_FLOW_H
#define OUROBOROS_IPCP_FLOW_H

#include <ouroboros/list.h>
#include <ouroboros/common.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <pthread.h>

struct flow {
        int                   port_id;
        struct shm_ap_rbuff * rb;
        enum flow_state       state;

        pid_t                 api;
};

#endif /* OUROBOROS_FLOW_H */
