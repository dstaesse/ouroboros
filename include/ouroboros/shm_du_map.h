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

#ifndef SHM_DU_BUFF_BLOCK_SIZE
#define SHM_DU_BUFF_BLOCK_SIZE sysconf(_SC_PAGESIZE)
#endif

#ifndef SHM_DU_MAP_FILENAME
#define SHM_DU_MAP_FILENAME "ouroboros_du_map"
#endif

#ifndef SHM_BLOCKS_IN_MAP
#define SHM_BLOCKS_IN_MAP (1 << 12)
#endif

#include "common.h"

struct shm_du_buff;
struct shm_du_map;

struct shm_du_map  * shm_du_map_create();
struct shm_du_map  * shm_du_map_open();
void                 shm_du_map_close(struct shm_du_map * dum);
void                 shm_du_map_destroy(struct shm_du_map * dum);

/* returns the index of the buffer in the DU map */
int shm_create_du_buff(struct shm_du_map * dum,
                       size_t              size,
                       size_t              headspace,
                       uint8_t           * data,
                       size_t              len);

/* FIXME: revise these */
int       shm_du_map_read_sdu(uint8_t **           dst,
                               struct shm_du_map * dum,
                               size_t              idx);
int       shm_release_du_buff(struct shm_du_map  * dum, size_t idx);


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
