/*
 * Ouroboros - Copyright (C) 2016
 *
 * Hash table with integer keys with separate chaining on collisions
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
