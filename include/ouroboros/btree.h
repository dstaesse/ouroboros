/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * B-trees
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_LIB_BTREE_H
#define OUROBOROS_LIB_BTREE_H

#include <stddef.h>
#include <stdint.h>

struct btree;

/* Create a B-tree of order k */
struct btree * btree_create(size_t k);

void           btree_destroy(struct btree * tree);

int            btree_insert(struct btree * tree,
                            uint32_t       key,
                            void *         val);

int            btree_remove(struct btree * tree,
                            uint32_t       key);

void *         btree_search(struct btree * tree,
                            uint32_t       key);

#endif /* OUROBOROS_LIB_BTREE_H */
