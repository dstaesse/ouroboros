/*
 * Ouroboros - Copyright (C) 2016 - 2023
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

#ifndef OUROBOROS_LIB_SHM_FLOW_SET_H
#define OUROBOROS_LIB_SHM_FLOW_SET_H

#include <ouroboros/fqueue.h>

#include <sys/time.h>

struct portevent {
        int flow_id;
        int event;
};

struct shm_flow_set;

struct shm_flow_set * shm_flow_set_create(pid_t pid);

void                  shm_flow_set_destroy(struct shm_flow_set * set);

struct shm_flow_set * shm_flow_set_open(pid_t pid);

void                  shm_flow_set_close(struct shm_flow_set * set);

void                  shm_flow_set_zero(struct shm_flow_set * shm_set,
                                        size_t                idx);

int                   shm_flow_set_add(struct shm_flow_set * shm_set,
                                       size_t                idx,
                                       int                   flow_id);

int                   shm_flow_set_has(struct shm_flow_set * shm_set,
                                       size_t                idx,
                                       int                   flow_id);

void                  shm_flow_set_del(struct shm_flow_set * shm_set,
                                       size_t                idx,
                                       int                   flow_id);

void                  shm_flow_set_notify(struct shm_flow_set * set,
                                          int                   flow_id,
                                          int                   event);

ssize_t               shm_flow_set_wait(const struct shm_flow_set * shm_set,
                                        size_t                      idx,
                                        struct portevent *          fqueue,
                                        const struct timespec *     abstime);

#endif /* OUROBOROS_LIB_SHM_FLOW_SET_H */
