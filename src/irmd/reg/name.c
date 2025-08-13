
/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Names
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

#define OUROBOROS_PREFIX "reg/name"

#include <ouroboros/logs.h>
#include <ouroboros/utils.h>

#include "name.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct prog_entry {
        struct list_head next;
        char **          exec;
};

struct proc_entry {
        struct list_head next;
        pid_t            pid;
};

static void __free_prog_entry(struct prog_entry * entry)
{
        assert(entry != NULL);
        assert(entry->exec != NULL);

        argvfree(entry->exec);
        free(entry);
}

struct reg_name * reg_name_create(const struct name_info * info)
{
        struct reg_name * name;

        assert(info != NULL);

        name = malloc(sizeof(*name));
        if (name == NULL) {
                log_err("Failed to malloc name.");
                goto fail_malloc;
        }

        memset(name, 0, sizeof(*name));

        list_head_init(&name->next);
        list_head_init(&name->progs.list);
        list_head_init(&name->procs.list);
        list_head_init(&name->active.list);

        name->info = *info;

        return name;

 fail_malloc:
        return NULL;
}

void reg_name_destroy(struct reg_name * name)
{
        assert(name != NULL);

        assert(list_is_empty(&name->next));

        assert(name->progs.len == 0);
        assert(name->procs.len == 0);
        assert(name->active.len == 0);

        assert(list_is_empty(&name->progs.list));
        assert(list_is_empty(&name->procs.list));
        assert(list_is_empty(&name->active.list));

        free(name);
}

static struct proc_entry * __reg_name_get_active(const struct reg_name * name,
                                                 pid_t                   pid)
{
        struct list_head * p;

        assert(name != NULL);
        assert(pid > 0);

        list_for_each(p, &name->active.list) {
                struct proc_entry * entry;
                entry = list_entry(p, struct proc_entry, next);
                if (entry->pid == pid)
                        return entry;
        }

        return NULL;
}

static void __reg_name_del_all_active(struct reg_name * name,
                                      pid_t             pid)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &name->active.list) {
                struct proc_entry * entry;
                entry = list_entry(p, struct proc_entry, next);
                if (entry->pid == pid) {
                        list_del(&entry->next);
                        free(entry);
                        --name->active.len;
                }
        }
}

static struct proc_entry * __reg_name_get_proc(const struct reg_name * name,
                                               pid_t                   pid)
{
        struct list_head * p;

        assert(name != NULL);
        assert(pid > 0);

        list_for_each(p, &name->procs.list) {
                struct proc_entry * entry;
                entry = list_entry(p, struct proc_entry, next);
                if (entry->pid == pid)
                        return entry;
        }

        return NULL;
}

static struct prog_entry * __reg_name_get_prog(const struct reg_name * name,
                                               const char *            prog)
{
        struct list_head * p;

        assert(name != NULL);
        assert(prog != NULL);

        list_for_each(p, &name->progs.list) {
                struct prog_entry * entry;
                entry = list_entry(p, struct prog_entry, next);
                if (strcmp(entry->exec[0], prog) == 0)
                        return entry;
        }

        return NULL;
}

int reg_name_add_active(struct reg_name * name,
                        pid_t             pid)
{
        struct proc_entry * entry;

        assert(name != NULL);
        assert(pid > 0);

        assert(__reg_name_get_proc(name, pid) != NULL);

        log_dbg("Process %d accepting flows for %s.", pid, name->info.name);

        if (__reg_name_get_active(name, pid) != NULL)
                log_dbg("Process calling accept from multiple threads.");

        entry = malloc(sizeof(*entry));
        if (entry == NULL) {
                log_err("Failed to malloc active.");
                goto fail_malloc;
        }

        entry->pid = pid;

        switch (name->info.pol_lb) {
        case LB_RR:    /* Round robin policy. */
                list_add_tail(&entry->next, &name->active.list);
                break;
        case LB_SPILL: /* Keep accepting flows on the current process */
                list_add(&entry->next, &name->active.list);
                break;
        default:
                goto fail_unreachable;
        }

        ++name->active.len;

        return 0;

 fail_unreachable:
        free(entry);
        assert(false);
 fail_malloc:
        return -1;
}

void reg_name_del_active(struct reg_name * name,
                         pid_t             pid)
{
        struct proc_entry * entry;

        entry = __reg_name_get_active(name, pid);
        if (entry == NULL)
                return;

        list_del(&entry->next);

        --name->active.len;

        free(entry);
}

pid_t reg_name_get_active(struct reg_name * name)
{
        struct proc_entry * e;

        assert(name != NULL);

        if (list_is_empty(&name->active.list))
                return -1;

        e = list_first_entry(&name->active.list, struct proc_entry, next);

        return e->pid;
}

int reg_name_add_proc(struct reg_name * name,
                      pid_t             pid)
{
        struct proc_entry * entry;

        assert(name != NULL);
        assert(pid > 0);

        assert(__reg_name_get_proc(name, pid) == NULL);

        entry = malloc(sizeof(*entry));
        if (entry == NULL) {
                log_err("Failed to malloc proc.");
                goto fail_malloc;
        }

        entry->pid = pid;

        list_add(&entry->next, &name->procs.list);

        ++name->procs.len;

        return 0;

 fail_malloc:
        return -1;
}

void reg_name_del_proc(struct reg_name * name,
                       pid_t             pid)
{
        struct proc_entry * entry;

        assert(name != NULL);
        assert(pid > 0);

        entry = __reg_name_get_proc(name, pid);
        if (entry == NULL)
                return;

        __reg_name_del_all_active(name, pid);

        list_del(&entry->next);

        free(entry);

        --name->procs.len;

        assert(__reg_name_get_proc(name, pid) == NULL);
}

bool reg_name_has_proc(const struct reg_name * name,
                       pid_t                   pid)
{
        return __reg_name_get_proc(name, pid) != NULL;
}

int reg_name_add_prog(struct reg_name * name,
                      char **           exec)
{
        struct prog_entry * entry;

        assert(name != NULL);
        assert(exec != NULL);
        assert(exec[0] != NULL);

        assert(__reg_name_get_prog(name, exec[0]) == NULL);

        entry = malloc(sizeof(*entry));
        if (entry == NULL) {
                log_err("Failed to malloc prog.");
                goto fail_malloc;
        }

        entry->exec = argvdup(exec);
        if (entry->exec == NULL) {
                log_err("Failed to argvdup prog.");
                goto fail_exec;
        }

        list_add(&entry->next, &name->progs.list);

        log_dbg("Add prog %s to name %s.", exec[0], name->info.name);

        ++name->progs.len;

        return 0;

 fail_exec:
        free(entry);
 fail_malloc:
        return -1;
}

void reg_name_del_prog(struct reg_name * name,
                       const char *      prog)
{
        struct prog_entry * entry;

        assert(name != NULL);
        assert(prog != NULL);

        entry = __reg_name_get_prog(name, prog);
        if (entry == NULL)
                return;

        list_del(&entry->next);

        __free_prog_entry(entry);

        --name->progs.len;

        assert(__reg_name_get_prog(name, prog) == NULL);
}

bool reg_name_has_prog(const struct reg_name * name,
                       const char *            prog)
{
        assert(name != NULL);
        assert(prog != NULL);

        return __reg_name_get_prog(name, prog) != NULL;
}

char ** reg_name_get_exec(const struct reg_name * name)
{
        struct prog_entry * e;

        if (list_is_empty(&name->progs.list))
                return NULL;

        e = list_first_entry(&name->progs.list, struct prog_entry, next);

        return e->exec;
}
