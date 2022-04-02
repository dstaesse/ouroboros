/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Adapter functions for N + 1 flow descriptors
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_NP1_FLOW_H
#define OUROBOROS_NP1_FLOW_H

#include <ouroboros/qos.h>

#include <unistd.h>

int  np1_flow_alloc(pid_t n_pid,
                    int   flow_id);

int  np1_flow_resp(int flow_id);

int  np1_flow_dealloc(int    flow_id,
                      time_t timeo);

static const qosspec_t qos_np1 = {
        .delay        = UINT32_MAX,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = UINT32_MAX,
        .ber          = UINT32_MAX,
        .in_order     = 0,
        .max_gap      = UINT32_MAX,
        .cypher_s     = 0,
        .timeout      = 0
};

#endif /* OUROBOROS_NP1_FLOW_H */
