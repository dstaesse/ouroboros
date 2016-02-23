/*
 * Ouroboros - Copyright (C) 2016
 *
 * Data Unit Buffer
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

#ifndef OUROBOROS_DU_BUFF_H
#define OUROBOROS_DU_BUFF_H

#include "common.h"
#include "list.h"

struct du_buff;

typedef struct du_buff du_buff_t;

du_buff_t * du_buff_create(size_t size);
void        du_buff_destroy(du_buff_t * dub);

int         du_buff_init(du_buff_t * dub,
                         size_t      start,
                         uint8_t   * data,
                         size_t      len);

uint8_t   * du_buff_data_ptr_start(du_buff_t * dub);
uint8_t   * du_buff_data_ptr_end(du_buff_t * dub);

int         du_buff_head_alloc(du_buff_t * dub, size_t size);
int         du_buff_tail_alloc(du_buff_t * dub, size_t size);
int         du_buff_head_release(du_buff_t * dub, size_t size);
int         du_buff_tail_release(du_buff_t * dub, size_t size);

#endif /* OUROBOROS_DU_BUFF_H */
