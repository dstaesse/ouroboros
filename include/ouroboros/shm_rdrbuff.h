/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Random Deletion Ring Buffer for Data Units
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

#ifndef OUROBOROS_LIB_SHM_RDRBUFF_H
#define OUROBOROS_LIB_SHM_RDRBUFF_H

#include <ouroboros/shm_du_buff.h>
#include <ouroboros/time.h>

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

struct shm_rdrbuff;

struct shm_rdrbuff * shm_rdrbuff_create(void);

struct shm_rdrbuff * shm_rdrbuff_open(void);

void                 shm_rdrbuff_close(struct shm_rdrbuff * rdrb);

void                 shm_rdrbuff_destroy(struct shm_rdrbuff * rdrb);

void                 shm_rdrbuff_purge(void);

/* Returns block index, a ptr and du_buff.  */
ssize_t              shm_rdrbuff_alloc(struct shm_rdrbuff *  rdrb,
                                       size_t                count,
                                       uint8_t **            ptr,
                                       struct shm_du_buff ** sdb);

ssize_t              shm_rdrbuff_alloc_b(struct shm_rdrbuff *    rdrb,
                                         size_t                  count,
                                         uint8_t **              ptr,
                                         struct shm_du_buff **   sdb,
                                         const struct timespec * abstime);

ssize_t              shm_rdrbuff_read(uint8_t **           dst,
                                      struct shm_rdrbuff * rdrb,
                                      size_t               idx);

struct shm_du_buff * shm_rdrbuff_get(struct shm_rdrbuff * rdrb,
                                     size_t               idx);

int                  shm_rdrbuff_remove(struct shm_rdrbuff  * rdrb,
                                        size_t                idx);

#endif /* OUROBOROS_LIB_SHM_RDRBUFF_H */
