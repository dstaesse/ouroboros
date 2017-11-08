/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Data Buffer element in Random Deletion Ring Buffer
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

#ifndef OUROBOROS_SHM_DU_BUFF_H
#define OUROBOROS_SHM_DU_BUFF_H

#include <sys/types.h>
#include <stdint.h>

struct shm_du_buff;

size_t    shm_du_buff_get_idx(struct shm_du_buff * sdb);

uint8_t * shm_du_buff_head(struct shm_du_buff * sdb);

uint8_t * shm_du_buff_tail(struct shm_du_buff * sdb);

uint8_t * shm_du_buff_head_alloc(struct shm_du_buff * sdb,
                                 size_t               size);

uint8_t * shm_du_buff_tail_alloc(struct shm_du_buff * sdb,
                                 size_t               size);

uint8_t * shm_du_buff_head_release(struct shm_du_buff * sdb,
                                   size_t               size);

uint8_t * shm_du_buff_tail_release(struct shm_du_buff * sdb,
                                   size_t               size);

void      shm_du_buff_truncate(struct shm_du_buff * sdb,
                               size_t               len);

#endif /* OUROBOROS_SHM_DU_BUFF_H */
