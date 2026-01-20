/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Secure Shared Memory infrastructure (SSM) Packet Buffer
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

#ifndef OUROBOROS_LIB_SSM_POOL_H
#define OUROBOROS_LIB_SSM_POOL_H

#include <ouroboros/ssm_pk_buff.h>
#include <ouroboros/time.h>

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

struct ssm_pool;

struct ssm_pool *    ssm_pool_create(void);

struct ssm_pool *    ssm_pool_open(void);

void                 ssm_pool_close(struct ssm_pool * pool);

void                 ssm_pool_destroy(struct ssm_pool * pool);

void                 ssm_pool_purge(void);

int                  ssm_pool_mlock(struct ssm_pool * pool);

/* Alloc count bytes, returns block index, a ptr and pk_buff.  */
ssize_t              ssm_pool_alloc(struct ssm_pool *    pool,
                                   size_t                count,
                                   uint8_t **            ptr,
                                   struct ssm_pk_buff ** spb);

ssize_t              ssm_pool_alloc_b(struct ssm_pool *        pool,
                                      size_t                  count,
                                      uint8_t **              ptr,
                                      struct ssm_pk_buff **   spb,
                                      const struct timespec * abstime);

ssize_t              ssm_pool_read(uint8_t **        dst,
                                   struct ssm_pool * pool,
                                   size_t            idx);

struct ssm_pk_buff * ssm_pool_get(struct ssm_pool * pool,
                                  size_t            idx);

int                  ssm_pool_remove(struct ssm_pool * pool,
                                     size_t            idx);

void                 ssm_pool_reclaim_orphans(struct ssm_pool * pool,
                                              pid_t             pid);

#endif /* OUROBOROS_LIB_SSM_POOL_H */
