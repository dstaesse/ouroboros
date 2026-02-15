/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Data Buffer element in Random Deletion Ring Buffer
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

#ifndef OUROBOROS_LIB_SSM_PK_BUFF_H
#define OUROBOROS_LIB_SSM_PK_BUFF_H

#include <sys/types.h>
#include <stdint.h>

struct ssm_pk_buff;

size_t    ssm_pk_buff_get_idx(struct ssm_pk_buff * spb);

uint8_t * ssm_pk_buff_head(struct ssm_pk_buff * spb);

uint8_t * ssm_pk_buff_tail(struct ssm_pk_buff * spb);

size_t    ssm_pk_buff_len(struct ssm_pk_buff * spb);

uint8_t * ssm_pk_buff_head_alloc(struct ssm_pk_buff * spb,
                                 size_t               size);

uint8_t * ssm_pk_buff_tail_alloc(struct ssm_pk_buff * spb,
                                 size_t               size);

uint8_t * ssm_pk_buff_head_release(struct ssm_pk_buff * spb,
                                   size_t               size);

uint8_t * ssm_pk_buff_tail_release(struct ssm_pk_buff * spb,
                                   size_t               size);

void      ssm_pk_buff_truncate(struct ssm_pk_buff * spb,
                               size_t               len);

int       ssm_pk_buff_wait_ack(struct ssm_pk_buff * spb);

int       ssm_pk_buff_ack(struct ssm_pk_buff * spb);

#endif /* OUROBOROS_LIB_SSM_PK_BUFF_H */
