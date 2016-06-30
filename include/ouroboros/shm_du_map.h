/*
 * Ouroboros - Copyright (C) 2016
 *
 * Shared memory map for data units
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#ifndef OUROBOROS_SHM_DU_MAP_H
#define OUROBOROS_SHM_DU_MAP_H

#include "common.h"
#include <sys/types.h>
#include <pthread.h>

struct shm_du_buff;
struct shm_du_map;

struct shm_du_map * shm_du_map_create();
struct shm_du_map * shm_du_map_open();
void                shm_du_map_close(struct shm_du_map * dum);
void                shm_du_map_destroy(struct shm_du_map * dum);
pid_t               shm_du_map_owner(struct shm_du_map * dum);
void *              shm_du_map_sanitize(void * o);

/* returns the index of the buffer in the DU map */
ssize_t  shm_du_map_write(struct shm_du_map * dum,
                          pid_t               dst_api,
                          size_t              headspace,
                          size_t              tailspace,
                          uint8_t *           data,
                          size_t              data_len);

int       shm_du_map_read(uint8_t **          dst,
                          struct shm_du_map * dum,
                          ssize_t             idx);
int       shm_du_map_remove(struct shm_du_map  * dum,
                            ssize_t idx);

/* FIXME: use shm_du_map * and index */
uint8_t * shm_du_buff_head_alloc(struct shm_du_buff * sdb,
                                 size_t size);
uint8_t * shm_du_buff_tail_alloc(struct shm_du_buff * sdb,
                                 size_t size);
int       shm_du_buff_head_release(struct shm_du_buff * sdb,
                                   size_t size);
int       shm_du_buff_tail_release(struct shm_du_buff * sdb,
                                   size_t size);

#endif /* OUROBOROS_SHM_DU_MAP_H */
