/*
 * Ouroboros - Copyright (C) 2016 - 2023
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

#ifndef OUROBOROS_IRMD_PROG_TABLE_H
#define OUROBOROS_IRMD_PROG_TABLE_H

#include <ouroboros/list.h>

#include <unistd.h>
#include <stdint.h>

struct prog_entry {
        struct list_head next;
        char *           prog;    /* name of binary */
        uint32_t         flags;
        char **          argv;
        struct list_head names; /* names that all instances will listen for */
};

struct prog_entry * prog_entry_create(char *   prog,
                                      uint32_t flags,
                                      char **  argv);

void                prog_entry_destroy(struct prog_entry * e);

int                 prog_entry_add_name(struct prog_entry * e,
                                        char *              name);

void                prog_entry_del_name(struct prog_entry * e,
                                        char *              name);

int                 prog_table_add(struct list_head * prog_table,
                                   struct prog_entry * e);

void                prog_table_del(struct list_head * prog_table,
                                   char *             prog);

struct prog_entry * prog_table_get(struct list_head * prog_table,
                                   char *             prog);

#endif /* OUROBOROS_IRMD_PROG_TABLE_H */
