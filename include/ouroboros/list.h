/*
 * Ouroboros - Copyright (C) 2016 - 2026
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

struct llist {
        struct list_head list;
        size_t           len;
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

#define list_head_init(h) do {                                  \
        (h)->nxt = (h);                                         \
        (h)->prv = (h);                                         \
} while (0)

#define __list_add(_n, _prv, _nxt) do {                         \
        struct list_head * __nxt = (_nxt);                      \
        struct list_head * __prv = (_prv);                      \
        struct list_head * __n = (_n);                          \
        __nxt->prv = __n;                                       \
        __n->nxt = __nxt;                                       \
        __n->prv = __prv;                                       \
        __prv->nxt = __n;                                       \
} while (0)

#define __list_del(_prv, _nxt) do {                             \
        struct list_head * __nxt = (_nxt);                      \
        struct list_head * __prv = (_prv);                      \
        __nxt->prv = __prv;                                     \
        __prv->nxt = __nxt;                                     \
} while (0)

#define list_add(n, h) do {                                     \
        __list_add(n, h, (h)->nxt);                             \
} while (0)

#define list_add_tail(n, h) do {                                \
        __list_add(n, (h)->prv, h);                             \
} while (0)

#define list_del(e) do {                                        \
        __list_del((e)->prv, (e)->nxt);                         \
        (e)->nxt = (e)->prv = (e);                              \
} while (0)

#define list_move(n, h) do {                                    \
        __list_del((n)->prv, (n)->nxt);                         \
        __list_add(n, h, (h)->nxt);                             \
} while (0)

#define list_is_empty(h) ((h)->nxt == (h))

#define llist_init(l) do {                                      \
        list_head_init(&(l)->list);                             \
        (l)->len = 0;                                           \
} while (0)

#define llist_add(e, l) do {                                    \
        list_add(e, &(l)->list);                                \
        (l)->len++;                                             \
} while (0)

#define llist_add_tail(e, l) do {                               \
        list_add_tail(e, &(l)->list);                           \
        (l)->len++;                                             \
} while (0)

#define llist_add_at(e, pos, l) do {                            \
        list_add(e, pos);                                       \
        (l)->len++;                                             \
} while (0)

#define llist_add_tail_at(e, pos, l) do {                       \
        list_add_tail(e, pos);                                  \
        (l)->len++;                                             \
} while (0)

#define llist_del(e, l) do {                                    \
        list_del(e);                                            \
        (l)->len--;                                             \
} while (0)

#define llist_is_empty(l) ((l)->len == 0)

#define llist_first_entry(l, type, mbr)                        \
        list_first_entry(&(l)->list, type, mbr)

#define llist_last_entry(l, type, mbr)                         \
        list_last_entry(&(l)->list, type, mbr)

#define llist_for_each(p, l) list_for_each(p, &(l)->list)

#define llist_for_each_safe(p, t, l)                            \
        list_for_each_safe(p, t, &(l)->list)

#endif /* OUROBOROS_LIB_LIST_H */
