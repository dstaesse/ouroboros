/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Ring buffer for incoming SDUs
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_SHM_RBUFF_H
#define OUROBOROS_SHM_RBUFF_H

#include <sys/types.h>
#include <sys/time.h>

struct shm_rbuff;

struct shm_rbuff * shm_rbuff_create(pid_t api, int port_id);

struct shm_rbuff * shm_rbuff_open(pid_t api, int port_id);

void               shm_rbuff_close(struct shm_rbuff * rb);

void               shm_rbuff_destroy(struct shm_rbuff * rb);

void               shm_rbuff_block(struct shm_rbuff * rb);

void               shm_rbuff_unblock(struct shm_rbuff * rb);

void               shm_rbuff_fini(struct shm_rbuff * rb);

int                shm_rbuff_write(struct shm_rbuff * rb,
                                   size_t             idx);

ssize_t            shm_rbuff_read(struct shm_rbuff * rb);

ssize_t            shm_rbuff_read_b(struct shm_rbuff *      rb,
                                    const struct timespec * timeout);

#endif /* OUROBOROS_SHM_RBUFF_H */
