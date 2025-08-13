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

#ifndef OUROBOROS_IRMD_REG_NAME_H
#define OUROBOROS_IRMD_REG_NAME_H

#include <ouroboros/list.h>
#include <ouroboros/name.h>

#define BIND_AUTO 0x01

struct reg_name {
        struct list_head next;

        struct name_info info;

        struct {
                void * key;
                void * crt;
        } cache;

        struct {
                struct list_head list;
                size_t           len;
        } progs;  /* autostart programs for this name  */

        struct {
                struct list_head list;
                size_t           len;
        } procs;  /* processes bound to this name      */

        struct {
                struct list_head list;
                size_t           len;
        } active; /* processes actively calling accept */
};

struct reg_name * reg_name_create(const struct name_info * info);

void              reg_name_destroy(struct reg_name * name);

int               reg_name_add_proc(struct reg_name * name,
                                    pid_t             proc);

void              reg_name_del_proc(struct reg_name * name,
                                    pid_t             proc);

bool              reg_name_has_proc(const struct reg_name * name,
                                    pid_t                   proc);

int               reg_name_add_prog(struct reg_name * name,
                                    char **           exec);

void              reg_name_del_prog(struct reg_name * name,
                                    const char *      prog);

bool              reg_name_has_prog(const struct reg_name * name,
                                    const char *            prog);

char **           reg_name_get_exec(const struct reg_name * name);

int               reg_name_add_active(struct reg_name * name,
                                      pid_t             proc);

pid_t             reg_name_get_active(struct reg_name * name);

void              reg_name_del_active(struct reg_name * name,
                                      pid_t             proc);
#endif /* OUROBOROS_IRMD_REG_NAME_H */
