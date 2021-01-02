/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Ring buffer for incoming packets
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

#ifndef OUROBOROS_SHM_RBUFF_H
#define OUROBOROS_SHM_RBUFF_H

#include <sys/types.h>
#include <sys/time.h>

#include <stdint.h>

#define ACL_RDWR     0000
#define ACL_RDONLY   0001
#define ACL_FLOWDOWN 0002

struct shm_rbuff;

struct shm_rbuff * shm_rbuff_create(pid_t pid,
                                    int   flow_id);

struct shm_rbuff * shm_rbuff_open(pid_t pid,
                                  int   flow_id);

void               shm_rbuff_close(struct shm_rbuff * rb);

void               shm_rbuff_destroy(struct shm_rbuff * rb);

void               shm_rbuff_set_acl(struct shm_rbuff * rb,
                                     uint32_t           flags);

uint32_t           shm_rbuff_get_acl(struct shm_rbuff * rb);

void               shm_rbuff_fini(struct shm_rbuff * rb);

int                shm_rbuff_write(struct shm_rbuff * rb,
                                   size_t             idx);

int                shm_rbuff_write_b(struct shm_rbuff *      rb,
                                     size_t                  idx,
                                     const struct timespec * abstime);

ssize_t            shm_rbuff_read(struct shm_rbuff * rb);

ssize_t            shm_rbuff_read_b(struct shm_rbuff *      rb,
                                    const struct timespec * abstime);

size_t             shm_rbuff_queued(struct shm_rbuff * rb);

#endif /* OUROBOROS_SHM_RBUFF_H */
