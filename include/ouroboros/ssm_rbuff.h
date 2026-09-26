/*
 * Ouroboros - Copyright (C) 2016 - 2026
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

#define RB_RD       0001 /* read permitted  (0 = no access)        */
#define RB_WR       0002 /* write permitted (0 = no access)        */
#define RB_RDWR     (RB_RD | RB_WR)
#define RB_FLOWDOWN 0004
#define RB_FLOWPEER 0010
#define RB_REKEY    0020 /* re-key seed parked (out-of-band signal) */

#define SSM_RBUFF_TXQ_MAX_DELAY 1000000000LL

struct ssm_rbuff;

struct ssm_rbuff * ssm_rbuff_create(pid_t pid,
                                    int   flow_id);

void               ssm_rbuff_destroy(struct ssm_rbuff * rb);

struct ssm_rbuff * ssm_rbuff_open(pid_t pid,
                                  int   flow_id);

void               ssm_rbuff_close(struct ssm_rbuff * rb);

void               ssm_rbuff_set_flags(struct ssm_rbuff * rb,
                                       uint32_t           flags);

void               ssm_rbuff_clr_flags(struct ssm_rbuff * rb,
                                       uint32_t           flags);

uint32_t           ssm_rbuff_get_flags(struct ssm_rbuff * rb);

size_t             ssm_rbuff_get_limit(struct ssm_rbuff * rb);

void               ssm_rbuff_set_txq_target(struct ssm_rbuff *      rb,
                                            const struct timespec * ts);

void               ssm_rbuff_get_txq_target(struct ssm_rbuff * rb,
                                            struct timespec *  ts);

void               ssm_rbuff_fini(struct ssm_rbuff * rb);

int                ssm_rbuff_drain(struct ssm_rbuff *      rb,
                                   const struct timespec * abstime);

int                ssm_rbuff_mlock(struct ssm_rbuff * rb);

int                ssm_rbuff_write(struct ssm_rbuff * rb,
                                   size_t             off);

int                ssm_rbuff_write_prio(struct ssm_rbuff * rb,
                                        size_t             off);

int                ssm_rbuff_write_b(struct ssm_rbuff *      rb,
                                     size_t                  off,
                                     const struct timespec * abstime);

ssize_t            ssm_rbuff_read(struct ssm_rbuff * rb);

ssize_t            ssm_rbuff_read_b(struct ssm_rbuff *      rb,
                                    const struct timespec * abstime);

size_t             ssm_rbuff_queued(struct ssm_rbuff * rb);

#endif /* OUROBOROS_LIB_SSM_RBUFF_H */
