/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Flows
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

#ifndef OUROBOROS_LIB_FLOW_H
#define OUROBOROS_LIB_FLOW_H

#include <ouroboros/qos.h>

#include <sys/types.h>

 enum flow_state { /* DO NOT CHANGE ORDER! */
        FLOW_INIT = 0,
        FLOW_ALLOC_PENDING,
        FLOW_ALLOC_REQ_PENDING,
        FLOW_ALLOCATED,
        FLOW_DEALLOC_PENDING,
        FLOW_DEALLOCATED,
        FLOW_DESTROY,
        FLOW_NULL
};

struct flow_info {
        int             id;

        pid_t           n_pid;
        pid_t           n_1_pid;

        time_t          mpl;

        struct qos_spec qs;

        enum flow_state state;
};

#endif /* OUROBOROS_LIB_FLOW_H */