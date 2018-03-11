/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Random Deletion Ring Buffer for Data Units
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#ifndef OUROBOROS_SHM_RDRBUFF_H
#define OUROBOROS_SHM_RDRBUFF_H

#include <ouroboros/shm_du_buff.h>
#include <ouroboros/qoscube.h>
#include <ouroboros/time_utils.h>

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

struct shm_rdrbuff;

struct shm_rdrbuff * shm_rdrbuff_create(void);

struct shm_rdrbuff * shm_rdrbuff_open(void);

void                 shm_rdrbuff_close(struct shm_rdrbuff * rdrb);

void                 shm_rdrbuff_destroy(struct shm_rdrbuff * rdrb);

void                 shm_rdrbuff_purge(void);

int                  shm_rdrbuff_wait_full(struct shm_rdrbuff * rdrb,
                                           struct timespec *    timeo);

/* returns the index of the buffer in the DU map */
ssize_t              shm_rdrbuff_write(struct shm_rdrbuff * rdrb,
                                       size_t               headspace,
                                       size_t               tailspace,
                                       const uint8_t *      data,
                                       size_t               data_len);

ssize_t              shm_rdrbuff_write_b(struct shm_rdrbuff *    rdrb,
                                         size_t                  headspace,
                                         size_t                  tailspace,
                                         const uint8_t *         data,
                                         size_t                  data_len,
                                         const struct timespec * abstime);

ssize_t              shm_rdrbuff_read(uint8_t **           dst,
                                      struct shm_rdrbuff * rdrb,
                                      size_t               idx);

struct shm_du_buff * shm_rdrbuff_get(struct shm_rdrbuff * rdrb,
                                     size_t               idx);

int                  shm_rdrbuff_remove(struct shm_rdrbuff  * rdrb,
                                        size_t                idx);

#endif /* OUROBOROS_SHM_RDRBUFF_H */
