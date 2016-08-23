/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager - Application Process Names Table
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#ifndef OUROBOROS_IRMD_APN_TABLE_H
#define OUROBOROS_IRMD_APN_TABLE_H

#include <ouroboros/list.h>

#include <unistd.h>
#include <stdint.h>

struct apn_entry {
        struct list_head next;
        char *           apn;   /* name for irmd */
        char *           ap;    /* name of binary */
        uint32_t         flags;
        char **          argv;
        struct list_head names; /* names that all instances will listen for */
};

struct apn_entry * apn_entry_create(char *   apn,
                                    char *   ap,
                                    uint32_t flags,
                                    char **  argv);

void               apn_entry_destroy(struct apn_entry * e);

int                apn_entry_add_name(struct apn_entry * e,
                                      char *             name);

void               apn_entry_del_name(struct apn_entry * e,
                                      char *             name);

int                apn_table_add(struct list_head * apn_table,
                                 struct apn_entry * e);

void               apn_table_del(struct list_head * apn_table,
                                 char *             ap);

struct apn_entry * apn_table_get(struct list_head * apn_table,
                                 char *             ap);

struct apn_entry * apn_table_get_by_apn(struct list_head * apn_table,
                                        char *             apn);

#endif /* OUROBOROS_IRMD_APN_TABLE_H */
