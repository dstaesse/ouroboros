/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager - Application Instance Table
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

#ifndef OUROBOROS_IRMD_API_TABLE_H
#define OUROBOROS_IRMD_API_TABLE_H

#include <unistd.h>

struct api_entry {
        struct list_head next;
        pid_t  api;
        char * apn;
        char * ap_subset; /* unique instance identifier */
};

struct api_entry * api_entry_create(pid_t api, char * apn, char * ap_subset);
void               api_entry_destroy(struct api_entry * e);

int    api_table_add_api(struct list_head * api_table,
                         pid_t api,
                         char * apn,
                         char * ap_subset);
void   api_table_del_api(struct list_head * api_table, pid_t api);
char * api_table_get_apn(struct list_head * api_table, pid_t api);
char * api_table_get_ap_subset(struct list_head * api_table, pid_t api);

#endif /* OUROBOROS_IRMD_API_TABLE_H */
