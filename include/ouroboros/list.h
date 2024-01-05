/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Simple doubly linked list implementation.
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

#ifndef OUROBOROS_LIB_LIST_H
#define OUROBOROS_LIB_LIST_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

struct list_head {
        struct list_head * nxt;
        struct list_head * prv;
};

#define list_entry(ptr, type, mbr)                              \
        ((type *)((uint8_t *)(ptr) - offsetof(type, mbr)))

#define list_first_entry(ptr, type, mbr)                        \
        list_entry((ptr)->nxt, type, mbr)

#define list_last_entry(ptr, type, mbr)                         \
        list_entry((ptr)->prv, type, mbr)

#define list_for_each(p, h)                                     \
        for (p = (h)->nxt; p != (h); p = p->nxt)

#define list_for_each_safe(p, t, h)                             \
        for (p = (h)->nxt, t = p->nxt; p != (h); p = t, t = p->nxt)

void list_head_init(struct list_head * h);

void list_add(struct list_head * e,
              struct list_head * h);

void list_add_tail(struct list_head * e,
                   struct list_head * h);

void list_del(struct list_head * e);

void list_move(struct list_head * dst,
               struct list_head * src);

bool list_is_empty(struct list_head * h);

#endif /* OUROBOROS_LIB_LIST_H */
