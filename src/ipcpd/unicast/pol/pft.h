/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Packet forwarding table (PFT) with chaining on collisions
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_PFT_H
#define OUROBOROS_PFT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

struct pft;

/* Buckets is rounded up to the nearest power of 2 */
struct pft * pft_create(uint64_t buckets,
                        bool     hash_key);

void         pft_destroy(struct pft * table);

void         pft_flush(struct pft * table);

/* Passes ownership of the block of memory */
int          pft_insert(struct pft * pft,
                        uint64_t     dst,
                        int *        fds,
                        size_t       len);

/* The block of memory returned is no copy */
int          pft_lookup(struct pft * pft,
                        uint64_t     dst,
                        int **       fds,
                        size_t *     len);

int          pft_delete(struct pft * pft,
                        uint64_t     dst);

#endif /* OUROBOROS_PFT_H */
