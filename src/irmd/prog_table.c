/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * The IPC Resource Manager - Program Table
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#include <ouroboros/errno.h>
#include <ouroboros/irm.h>

#include "prog_table.h"
#include "utils.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct prog_entry * prog_entry_create(char *   prog,
                                      uint32_t flags,
                                      char **  argv)
{
        struct prog_entry * e;

        assert(prog);

        e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        list_head_init(&e->next);
        list_head_init(&e->names);

        e->prog  = prog;
        e->flags = flags;

        if (flags & BIND_AUTO) {
                e->argv = argv;
        } else {
                e->argv  = NULL;
                argvfree(argv);
                argv = NULL;
        }

        return e;
}
void prog_entry_destroy(struct prog_entry * e)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        if (e == NULL)
                return;

        if (e->prog != NULL)
                free(e->prog);

        if (e->argv != NULL)
                argvfree(e->argv);

        list_for_each_safe(p, h, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                list_del(&s->next);
                free(s->str);
                free(s);
        }

        free(e);
}

int prog_entry_add_name(struct prog_entry * e,
                        char *              name)
{
        struct str_el * s;

        if (e == NULL || name == NULL)
                return -EINVAL;

        s = malloc(sizeof(*s));
        if (s == NULL)
                return -ENOMEM;

        s->str = name;
        list_add(&s->next, &e->names);

        return 0;
}

void prog_entry_del_name(struct prog_entry * e,
                         char *              name)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        list_for_each_safe(p, h, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                if (!strcmp(name, s->str)) {
                        list_del(&s->next);
                        free(s->str);
                        free(s);
                }
        }
}

int prog_table_add(struct list_head *  prog_table,
                   struct prog_entry * e)
{
        assert(prog_table);
        assert(e);

        list_add(&e->next, prog_table);

        return 0;
}

void prog_table_del(struct list_head * prog_table,
                    char *             prog)
{
        struct list_head * p;
        struct list_head * h;

        assert(prog_table);
        assert(prog);

        list_for_each_safe(p, h, prog_table) {
                struct prog_entry * e = list_entry(p, struct prog_entry, next);
                if (!strcmp(prog, e->prog)) {
                        list_del(&e->next);
                        prog_entry_destroy(e);
                }
        }
}

struct prog_entry * prog_table_get(struct list_head * prog_table,
                                   char *             prog)
{
        struct list_head * p;

        assert(prog_table);
        assert(prog);

        list_for_each(p, prog_table) {
                struct prog_entry * e = list_entry(p, struct prog_entry, next);
                if (!strcmp(e->prog, prog))
                        return e;
        }

        return NULL;
}
