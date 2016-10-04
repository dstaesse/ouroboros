/*
 * Ouroboros - Copyright (C) 2016
 *
 * Adapter functions for N + 1 flow descriptors
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

#include <unistd.h>
#include <stdint.h>
#include <time.h>

#include <ouroboros/qos.h>
#include <ouroboros/flow.h>
#include <ouroboros/shm_rdrbuff.h>

#ifndef OUROBOROS_NP1_FLOW_H
#define OUROBOROS_NP1_FLOW_H

int  np1_flow_alloc(pid_t n_api,
                    int   port_id);

int  np1_flow_resp(pid_t n_api,
                   int   port_id);

int  np1_flow_dealloc(int port_id);

#endif /* OUROBOROS_NP1_FLOW_H */
