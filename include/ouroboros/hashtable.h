/*
 * Ouroboros - Copyright (C) 2016 - 2019
 *
 * Hash table with integer keys with separate chaining on collisions
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

#ifndef OUROBOROS_HASHTABLE_H
#define OUROBOROS_HASHTABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

struct htable;

/* Buckets is rounded up to the nearest power of 2 */
struct htable * htable_create(uint64_t buckets,
                              bool     hash_key);

void            htable_destroy(struct htable * table);

void            htable_flush(struct htable * table);

/* Passes ownership of the block of memory */
int             htable_insert(struct htable * table,
                              uint64_t        key,
                              void *          val,
                              size_t          len);

/* The block of memory returned is no copy */
int             htable_lookup(struct htable * table,
                              uint64_t        key,
                              void **         val,
                              size_t *        len);

int             htable_delete(struct htable * table,
                              uint64_t        key);

#endif /* OUROBOROS_HASHTABLE_H */
