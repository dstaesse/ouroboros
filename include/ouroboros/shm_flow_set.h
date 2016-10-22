/*
 * Ouroboros - Copyright (C) 2016
 *
 * Management of flow_sets for fqueue
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

#ifndef OUROBOROS_SHM_FLOW_SET_H
#define OUROBOROS_SHM_FLOW_SET_H

#include <ouroboros/fqueue.h>

#include <sys/time.h>

struct shm_flow_set;

struct shm_flow_set * shm_flow_set_create(void);

void                  shm_flow_set_destroy(struct shm_flow_set * set);

struct shm_flow_set * shm_flow_set_open(pid_t api);

void                  shm_flow_set_close(struct shm_flow_set * set);

void                  shm_flow_set_zero(struct shm_flow_set * shm_set,
                                        size_t                idx);

int                   shm_flow_set_add(struct shm_flow_set * shm_set,
                                       size_t                idx,
                                       int                   port_id);

int                   shm_flow_set_has(struct shm_flow_set * shm_set,
                                       size_t                idx,
                                       int                   port_id);

void                  shm_flow_set_del(struct shm_flow_set * shm_set,
                                       size_t                idx,
                                       int                   port_id);

void                  shm_flow_set_notify(struct shm_flow_set * set,
                                          int                   port_id);

ssize_t               shm_flow_set_wait(const struct shm_flow_set * shm_set,
                                        size_t                      idx,
                                        int *                       fqueue,
                                        const struct timespec *     timeout);

#endif /* OUROBOROS_SHM_FLOW_SET_H */
