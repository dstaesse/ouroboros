/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Flows
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#ifndef OUROBOROS_IRMD_REG_FLOW_H
#define OUROBOROS_IRMD_REG_FLOW_H

#include <ouroboros/list.h>
#include <ouroboros/flow.h>
#include <ouroboros/pthread.h>
#include <ouroboros/qos.h>
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/utils.h>

#include <sys/types.h>
#include <time.h>

struct reg_flow {
        struct list_head next;

        struct flow_info info;

        buffer_t         data;
        struct timespec  t0;

        struct shm_rbuff * n_rb;
        struct shm_rbuff * n_1_rb;
};

struct reg_flow * reg_flow_create(const struct flow_info * info);

void              reg_flow_destroy(struct reg_flow * flow);

int               reg_flow_update(struct reg_flow *  flow,
                                  struct flow_info * info);

void              reg_flow_set_data(struct reg_flow * flow,
                                    const buffer_t *  buf);

void              reg_flow_get_data(struct reg_flow * flow,
                                    buffer_t *        buf);

void              reg_flow_free_data(struct reg_flow * flow);

#endif /* OUROBOROS_IRMD_REG_FLOW_H */
