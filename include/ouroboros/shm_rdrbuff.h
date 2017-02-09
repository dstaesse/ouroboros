/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Random Deletion Ring Buffer for Data Units
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#ifndef OUROBOROS_SHM_RDRBUFF_H
#define OUROBOROS_SHM_RDRBUFF_H

#include <ouroboros/shared.h>

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

struct shm_du_buff;
struct shm_rdrbuff;

size_t               shm_du_buff_get_idx(struct shm_du_buff * sdb);

struct shm_rdrbuff * shm_rdrbuff_create(void);

struct shm_rdrbuff * shm_rdrbuff_open(void);

void                 shm_rdrbuff_close(struct shm_rdrbuff * rdrb);

void                 shm_rdrbuff_destroy(struct shm_rdrbuff * rdrb);

void                 shm_rdrbuff_wait_full(struct shm_rdrbuff * rdrb);

/* returns the index of the buffer in the DU map */
ssize_t              shm_rdrbuff_write(struct shm_rdrbuff * rdrb,
                                       size_t               headspace,
                                       size_t               tailspace,
                                       const uint8_t *      data,
                                       size_t               data_len);

ssize_t              shm_rdrbuff_write_b(struct shm_rdrbuff * rdrb,
                                         size_t               headspace,
                                         size_t               tailspace,
                                         const uint8_t *      data,
                                         size_t               data_len);

ssize_t              shm_rdrbuff_read(uint8_t **           dst,
                                      struct shm_rdrbuff * rdrb,
                                      size_t               idx);

struct shm_du_buff * shm_rdrbuff_get(struct shm_rdrbuff * rdrb,
                                     size_t               idx);

int                  shm_rdrbuff_remove(struct shm_rdrbuff  * rdrb,
                                        size_t                idx);

uint8_t *            shm_du_buff_head(struct shm_du_buff * sdb);

uint8_t *            shm_du_buff_tail(struct shm_du_buff * sdb);

uint8_t *            shm_du_buff_head_alloc(struct shm_du_buff * sdb,
                                            size_t               size);

uint8_t *            shm_du_buff_tail_alloc(struct shm_du_buff * sdb,
                                            size_t               size);

void                 shm_du_buff_head_release(struct shm_du_buff * sdb,
                                              size_t               size);

void                 shm_du_buff_tail_release(struct shm_du_buff * sdb,
                                              size_t               size);
#endif /* OUROBOROS_SHM_RDRBUFF_H */
