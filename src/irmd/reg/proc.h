/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Processes
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

#ifndef OUROBOROS_IRMD_REG_PROC_H
#define OUROBOROS_IRMD_REG_PROC_H

#include <ouroboros/list.h>
#include <ouroboros/proc.h>
#include <ouroboros/ssm_flow_set.h>

struct reg_proc {
        struct list_head      next;

        struct proc_info      info;

        struct list_head      names;   /* process accepts flows for names */
        size_t                n_names; /* number of names                 */

        struct ssm_flow_set * set;
};

struct reg_proc * reg_proc_create(const struct proc_info * info);

void              reg_proc_destroy(struct reg_proc * proc);

void              reg_proc_clear(struct reg_proc * proc);

int               reg_proc_add_name(struct reg_proc * proc,
                                    const char *      name);

void              reg_proc_del_name(struct reg_proc * proc,
                                    const char *      name);

bool              reg_proc_has_name(const struct reg_proc * proc,
                                    const char *            name);

bool              reg_proc_is_privileged(const struct reg_proc * proc);

#endif /* OUROBOROS_IRMD_REG_PROC_H */
