/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Simple doubly linked list implementation.
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#include <ouroboros/list.h>

#include <stddef.h>

void list_head_init(struct list_head * h)
{
        h->nxt = h;
        h->prv = h;
}

static void add_list(struct list_head * n,
                     struct list_head * prv,
                     struct list_head * nxt)
{
        nxt->prv = n;
        n->nxt = nxt;
        n->prv = prv;
        prv->nxt = n;
}

static void del_list(struct list_head * prv,
                     struct list_head * nxt)
{
        nxt->prv = prv;
        prv->nxt = nxt;
}

void list_add(struct list_head * n,
              struct list_head * h)
{
        add_list(n, h, h->nxt);
}

void list_add_tail(struct list_head * n,
                   struct list_head * h)
{
        add_list(n, h->prv, h);
}

void list_del(struct list_head * e)
{
        del_list(e->prv, e->nxt);
        e->nxt = e->prv = NULL;
}

bool list_is_empty(struct list_head * h)
{
        return h->nxt == h;
}
