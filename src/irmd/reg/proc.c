/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Processes
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This procram is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This procram is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this procram; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200809L

#define OUROBOROS_PREFIX "reg/proc"

#include <ouroboros/logs.h>

#include "proc.h"

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

static void __reg_proc_clear_names(struct reg_proc * proc)
{
        struct list_head * p;
        struct list_head * h;

        assert(proc != NULL);

        list_for_each_safe(p, h, &proc->names) {
                struct name_entry * entry;
                entry = list_entry(p, struct name_entry, next);
                list_del(&entry->next);
                __free_name_entry(entry);
                proc->n_names--;
        }
}

struct reg_proc * reg_proc_create(const struct proc_info * info)
{
        struct reg_proc * proc;

        assert(info != NULL);

        proc = malloc(sizeof(*proc));
        if (proc == NULL) {
                log_err("Failed to malloc proc.");
                goto fail_malloc;
        }

        proc->set = shm_flow_set_create(info->pid);
        if (proc->set == NULL) {
                log_err("Failed to create flow set for %d.", info->pid);
                goto fail_set;
        }

        list_head_init(&proc->next);
        list_head_init(&proc->names);

        proc->info    = *info;
        proc->n_names = 0;

        return proc;

 fail_set:
        free(proc);
 fail_malloc:
        return NULL;
}

void reg_proc_destroy(struct reg_proc * proc)
{
        assert(proc != NULL);

        shm_flow_set_destroy(proc->set);

        __reg_proc_clear_names(proc);

        assert(list_is_empty(&proc->next));

        assert(proc->n_names == 0);

        assert(list_is_empty(&proc->names));

        free(proc);
}

static struct name_entry * __reg_proc_get_name(const struct reg_proc * proc,
                                               const char *            name)
{
        struct list_head * p;

        list_for_each(p, &proc->names) {
                struct name_entry * entry;
                entry = list_entry(p, struct name_entry, next);
                if (strcmp(entry->name, name) == 0)
                        return entry;
        }

        return NULL;
}

int reg_proc_add_name(struct reg_proc * proc,
                      const char *      name)
{
        struct name_entry * entry;

        assert(__reg_proc_get_name(proc, name) == NULL);

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

        list_add(&entry->next, &proc->names);

        proc->n_names++;

        return 0;

 fail_name:
        free(entry);
 fail_malloc:
        return -1;
}

void reg_proc_del_name(struct reg_proc * proc,
                       const char *      name)
{
        struct name_entry * entry;

        entry = __reg_proc_get_name(proc, name);
        if(entry == NULL)
                return;

        list_del(&entry->next);

        __free_name_entry(entry);

        proc->n_names--;

        assert(__reg_proc_get_name(proc, name) == NULL);
}

bool reg_proc_has_name(const struct reg_proc * proc,
                       const char *            name)
{
        return __reg_proc_get_name(proc, name) != NULL;
}
