/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * RIB event queues
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

#ifndef OUROBOROS_RQUEUE_H
#define OUROBOROS_RQUEUE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define RO_READ    0x00000001
#define RO_MODIFY  0x00000002
#define RO_CREATE  0x00000004
#define RO_DELETE  0x00000008
#define RO_START   0x00000010
#define RO_STOP    0x00000020

#define RO_NO_OPS  0x00000000
#define RO_ALL_OPS 0xFFFFFFFF

struct ro_set;

struct rqueue;

typedef struct ro_set ro_set_t;
typedef struct rqueue rqueue_t;

ro_set_t *   ro_set_create(void);

void         ro_set_destroy(ro_set_t * set);

rqueue_t *   rqueue_create(void);

int          rqueue_destroy(struct rqueue * rq);

int          ro_set_zero(ro_set_t * set);

int          ro_set_add(ro_set_t *   set,
                        const char * path,
                        int32_t      flags);

int          ro_set_del(ro_set_t *   set,
                        const char * path);

int32_t      rqueue_next(rqueue_t * rq,
                         char *     path);

int          rib_event_wait(ro_set_t *              set,
                            rqueue_t *              rq,
                            const struct timespec * timeout);

#endif /* OUROBOROS_RQUEUE_H */
