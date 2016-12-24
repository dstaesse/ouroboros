/*
 * Ouroboros - Copyright (C) 2016
 *
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 *
 * This file is from the Linux Kernel (include/linux/list.h)
 * and modified by simply removing hardware prefetching of list items.
 * Here by copyright, credits attributed to wherever they belong.
 * Kulesh Shanmugasundaram (kulesh [squiggly] isis.poly.edu)
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/list.h>

static void __list_add(struct list_head * new,
                       struct list_head * prev,
                       struct list_head * next)
{
        next->prev = new;
        new->next = next;
        new->prev = prev;
        prev->next = new;
}

void list_add(struct list_head * new,
              struct list_head * head)
{
        __list_add(new, head, head->next);
}

void list_add_tail(struct list_head * new,
                   struct list_head * head)
{
        __list_add(new, head->prev, head);
}

static void __list_del(struct list_head * prev,
                       struct list_head * next)
{
        next->prev = prev;
        prev->next = next;
}

void list_del(struct list_head * entry)
{
        __list_del(entry->prev, entry->next);
        entry->next = (void *) 0;
        entry->prev = (void *) 0;
}

void list_del_init(struct list_head * entry)
{
        __list_del(entry->prev, entry->next);
        INIT_LIST_HEAD(entry);
}

void list_move(struct list_head * list,
               struct list_head * head)
{
        __list_del(list->prev, list->next);
        list_add(list, head);
}

void list_move_tail(struct list_head * list,
                    struct list_head * head)
{
        __list_del(list->prev, list->next);
        list_add_tail(list, head);
}

int list_empty(struct list_head * head)
{
        return head->next == head;
}

static void __list_splice(struct list_head *list,
                          struct list_head *head)
{
        struct list_head *first = list->next;
        struct list_head *last = list->prev;
        struct list_head *at = head->next;

        first->prev = head;
        head->next = first;

        last->next = at;
        at->prev = last;
}

void list_splice(struct list_head * list,
                 struct list_head * head)
{
        if (!list_empty(list))
                __list_splice(list, head);
}

void list_splice_init(struct list_head * list,
                      struct list_head * head)
{
        if (!list_empty(list)) {
                __list_splice(list, head);
                INIT_LIST_HEAD(list);
        }
}
