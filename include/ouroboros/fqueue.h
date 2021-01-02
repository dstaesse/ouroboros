/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Flow queues
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

#ifndef OUROBOROS_FQUEUE_H
#define OUROBOROS_FQUEUE_H

#include <ouroboros/cdefs.h>

#include <stdbool.h>
#include <time.h>

enum fqtype {
        FLOW_PKT     = (1 << 0),
        FLOW_DOWN    = (1 << 1),
        FLOW_UP      = (1 << 2),
        FLOW_ALLOC   = (1 << 3),
        FLOW_DEALLOC = (1 << 4)
};

struct flow_set;

struct fqueue;

typedef struct flow_set fset_t;
typedef struct fqueue fqueue_t;

__BEGIN_DECLS

fset_t *    fset_create(void);

void        fset_destroy(fset_t * set);

fqueue_t *  fqueue_create(void);

void        fqueue_destroy(struct fqueue * fq);

void        fset_zero(fset_t * set);

int         fset_add(fset_t * set,
                     int      fd);

bool        fset_has(const fset_t * set,
                     int            fd);

void        fset_del(fset_t * set,
                     int      fd);

int         fqueue_next(fqueue_t * fq);

enum fqtype fqueue_type(fqueue_t * fq);

ssize_t     fevent(fset_t *                set,
                   fqueue_t *              fq,
                   const struct timespec * timeo);

__END_DECLS

#endif /* OUROBOROS_FQUEUE_H */
