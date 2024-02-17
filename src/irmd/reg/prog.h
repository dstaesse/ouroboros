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

#ifndef OUROBOROS_IRMD_REG_PROG_H
#define OUROBOROS_IRMD_REG_PROG_H

#include <ouroboros/list.h>
#include <ouroboros/proc.h>

#include <stdint.h>

struct reg_prog {
        struct list_head next;

        struct prog_info info;

        struct list_head names;   /* names to listen for       */
        size_t           n_names; /* number of names in list   */
 };

struct reg_prog * reg_prog_create(const struct prog_info * info);

void              reg_prog_destroy(struct reg_prog * prog);

int               reg_prog_add_name(struct reg_prog * prog,
                                    const char *      name);

void              reg_prog_del_name(struct reg_prog * prog,
                                    const char *      name);

bool              reg_prog_has_name(const struct reg_prog * prog,
                                    const char *            name);

#endif /* OUROBOROS_IRMD_REG_PROG_H */
