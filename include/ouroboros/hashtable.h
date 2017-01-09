/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Hash table with integer keys with separate chaining on collisions
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
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

int             htable_destroy(struct htable * table);

/* Passes ownership of the block of memory */
int             htable_insert(struct htable * table,
                              uint64_t        key,
                              void *          val);

/* The block of memory returned is no copy */
void *          htable_lookup(struct htable * table,
                              uint64_t        key);

int             htable_delete(struct htable * table,
                              uint64_t        key);

#endif /* OUROBOROS_HASHTABLE_H */
