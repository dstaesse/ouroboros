/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Reordering queue
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

#ifndef OUROBOROS_LIB_RQ_H
#define OUROBOROS_LIB_RQ_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

struct rq * rq_create(int size);

void        rq_destroy(struct rq * rq);

int         rq_push(struct rq * rq,
                    uint64_t    seqno,
                    size_t      idx);

uint64_t    rq_peek(struct rq * rq);

bool        rq_is_empty(struct rq * rq);

size_t      rq_pop(struct rq * rq);

bool        rq_has(struct rq * rq,
                   uint64_t    seqno);

#endif /* OUROBOROS_LIB_RQ_H */
