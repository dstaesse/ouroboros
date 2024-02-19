/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Programs
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

#define _POSIX_C_SOURCE 200809L

#define OUROBOROS_PREFIX "reg/prog"

#include <ouroboros/logs.h>
#include <ouroboros/utils.h>

#include "prog.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct name_entry {
        struct list_head next;
        char *           name;
};

static void __free_name_entry(struct name_entry * entry)
{
        assert(entry != NULL);
        assert(entry->name != NULL);

        free(entry->name);
        free(entry);
}

static void __reg_prog_clear_names(struct reg_prog * prog)
{
        struct list_head * p;
        struct list_head * h;

        assert(prog != NULL);

        list_for_each_safe(p, h, &prog->names) {
                struct name_entry * entry;
                entry = list_entry(p, struct name_entry, next);
                list_del(&entry->next);
                __free_name_entry(entry);
                prog->n_names--;
        }
}

struct reg_prog * reg_prog_create(const struct prog_info * info)
{
        struct reg_prog * p;

        assert(info != NULL);

        p = malloc(sizeof(*p));
        if (p == NULL) {
                log_err("Failed to malloc prog.");
                goto fail_malloc;
        }

        list_head_init(&p->next);
        list_head_init(&p->names);

        p->info    = *info;
        p->n_names = 0;

        return p;

 fail_malloc:
        return NULL;
}

void reg_prog_destroy(struct reg_prog * prog)
{
        assert(prog != NULL);

        __reg_prog_clear_names(prog);

        assert(list_is_empty(&prog->next));

        assert(prog->n_names == 0);

        assert(list_is_empty(&prog->names));

        free(prog);
}

static struct name_entry * __reg_prog_get_name(const struct reg_prog * prog,
                                               const char *            name)
{
        struct list_head * p;

        list_for_each(p, &prog->names) {
                struct name_entry * entry;
                entry = list_entry(p, struct name_entry, next);
                if (strcmp(entry->name, name) == 0)
                        return entry;
        }

        return NULL;
}

int reg_prog_add_name(struct reg_prog * prog,
                      const char *      name)
{
        struct name_entry * entry;

        assert(__reg_prog_get_name(prog, name) == NULL);

        entry = malloc(sizeof(*entry));
        if (entry == NULL) {
                log_err("Failed to malloc name.");
                goto fail_malloc;
        }

        entry->name = strdup(name);
        if (entry == NULL) {
                log_err("Failed to strdup name.");
                goto fail_name;
        }

        list_add(&entry->next, &prog->names);

        prog->n_names++;

        return 0;

 fail_name:
        free(entry);
 fail_malloc:
        return -1;
}

void reg_prog_del_name(struct reg_prog * prog,
                       const char *      name)
{
        struct name_entry * entry;

        entry = __reg_prog_get_name(prog, name);
        if (entry == NULL)
                return;

        list_del(&entry->next);

        __free_name_entry(entry);

        prog->n_names--;

        assert(__reg_prog_get_name(prog, name) == NULL);
}

bool reg_prog_has_name(const struct reg_prog * prog,
                       const char *            name)
{
        return __reg_prog_get_name(prog, name) != NULL;
}
