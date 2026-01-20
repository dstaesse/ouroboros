/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Management of flow_sets for fqueue
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

#ifndef OUROBOROS_LIB_SSM_FLOW_SET_H
#define OUROBOROS_LIB_SSM_FLOW_SET_H

#include <ouroboros/fqueue.h>

#include <sys/time.h>

struct flowevent {
        int flow_id;
        int event;
};

struct ssm_flow_set;

struct ssm_flow_set * ssm_flow_set_create(pid_t pid);

void                  ssm_flow_set_destroy(struct ssm_flow_set * set);

struct ssm_flow_set * ssm_flow_set_open(pid_t pid);

void                  ssm_flow_set_close(struct ssm_flow_set * set);

void                  ssm_flow_set_zero(struct ssm_flow_set * set,
                                        size_t                idx);

int                   ssm_flow_set_add(struct ssm_flow_set * set,
                                       size_t                idx,
                                       int                   flow_id);

int                   ssm_flow_set_has(struct ssm_flow_set * set,
                                       size_t                idx,
                                       int                   flow_id);

void                  ssm_flow_set_del(struct ssm_flow_set * set,
                                       size_t                idx,
                                       int                   flow_id);

void                  ssm_flow_set_notify(struct ssm_flow_set * set,
                                          int                   flow_id,
                                          int                   event);

ssize_t               ssm_flow_set_wait(const struct ssm_flow_set * set,
                                        size_t                      idx,
                                        struct flowevent *          fqueue,
                                        const struct timespec *     abstime);

#endif /* OUROBOROS_LIB_SSM_FLOW_SET_H */
