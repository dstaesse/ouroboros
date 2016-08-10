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

#include <ouroboros/config.h>
#include <ouroboros/list.h>
#include <ouroboros/errno.h>

#include "api_table.h"

#include <stdlib.h>

struct api_entry * api_entry_create(pid_t api,
                                    char * apn,
                                    char * ap_subset)
{
        struct api_entry * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        INIT_LIST_HEAD(&e->next);

        e->api = api;
        e->apn = apn;
        e->ap_subset = ap_subset;

        return e;
}

void api_entry_destroy(struct api_entry * e)
{
        if (e->apn != NULL)
                free(e->apn);
        if (e->ap_subset != NULL)
                free(e->ap_subset);
        free(e);
}

int api_table_add_api(struct list_head * api_table,
                      pid_t api, char * apn, char * ap_subset)
{
        if (apn == NULL)
                return -EINVAL;

        struct api_entry * e = api_entry_create(api, apn, ap_subset);
        if (e == NULL)
                return -ENOMEM;

        list_add(&e->next, api_table);

        return 0;
}

void api_table_del_api(struct list_head * api_table, pid_t api)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, api_table) {
                struct api_entry * e =
                        list_entry(p, struct api_entry, next);

                if (api == e->api) {
                        list_del(&e->next);
                        api_entry_destroy(e);
                }
        }
}

char * api_table_get_apn(struct list_head * api_table, pid_t api)
{
        struct list_head * h;

        list_for_each(h, api_table) {
                struct api_entry * e =
                        list_entry(h, struct api_entry, next);

                if (api == e->api)
                        return e->apn;
        }

        return NULL;
}
char * api_table_get_ap_subset(struct list_head * api_table, pid_t api)
{
        struct list_head * h;

        list_for_each(h, api_table) {
                struct api_entry * e =
                        list_entry(h, struct api_entry, next);

                if (api == e->api)
                        return e->ap_subset;
        }

        return NULL;
}
