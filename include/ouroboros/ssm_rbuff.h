/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Ring buffer for incoming packets
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

#ifndef OUROBOROS_LIB_SSM_RBUFF_H
#define OUROBOROS_LIB_SSM_RBUFF_H

#include <sys/types.h>
#include <sys/time.h>

#include <stdint.h>

#define ACL_RDWR     0000
#define ACL_RDONLY   0001
#define ACL_FLOWDOWN 0002
#define ACL_FLOWPEER 0004

struct ssm_rbuff;

struct ssm_rbuff * ssm_rbuff_create(pid_t pid,
                                    int   flow_id);

void               ssm_rbuff_destroy(struct ssm_rbuff * rb);

struct ssm_rbuff * ssm_rbuff_open(pid_t pid,
                                  int   flow_id);

void               ssm_rbuff_close(struct ssm_rbuff * rb);

void               ssm_rbuff_set_acl(struct ssm_rbuff * rb,
                                     uint32_t           flags);

uint32_t           ssm_rbuff_get_acl(struct ssm_rbuff * rb);

void               ssm_rbuff_fini(struct ssm_rbuff * rb);

int                ssm_rbuff_mlock(struct ssm_rbuff * rb);

int                ssm_rbuff_write(struct ssm_rbuff * rb,
                                   size_t             idx);

int                ssm_rbuff_write_b(struct ssm_rbuff *      rb,
                                     size_t                  idx,
                                     const struct timespec * abstime);

ssize_t            ssm_rbuff_read(struct ssm_rbuff * rb);

ssize_t            ssm_rbuff_read_b(struct ssm_rbuff *      rb,
                                    const struct timespec * abstime);

size_t             ssm_rbuff_queued(struct ssm_rbuff * rb);

#endif /* OUROBOROS_LIB_SSM_RBUFF_H */
