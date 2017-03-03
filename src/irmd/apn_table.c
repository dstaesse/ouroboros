/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The IPC Resource Manager - Application Process Table
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/errno.h>
#include <ouroboros/irm_config.h>

#include "apn_table.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

struct apn_entry * apn_entry_create(char * apn,
                                    char * ap,
                                    uint32_t flags,
                                    char ** argv)
{
        struct apn_entry * e;
        if (apn == NULL)
                return NULL;

        e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        list_head_init(&e->next);
        list_head_init(&e->names);

        e->apn   = apn;
        e->ap    = ap;
        e->flags = flags;

        if (flags & BIND_AP_AUTO) {
                e->argv = argv;
        } else {
                e->argv  = NULL;
                argvfree(argv);
                argv = NULL;
        }

        return e;
}
void apn_entry_destroy(struct apn_entry * e)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        if (e == NULL)
                return;

        if (e->apn != NULL)
                free(e->apn);

        if (e->ap != NULL)
                free(e->ap);

        if (e->argv != NULL)
                argvfree(e->argv);

        list_for_each_safe(p, h, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                list_del(&s->next);
                if (s->str != NULL)
                        free(s->str);
                free(s);
        }

        free(e);
}

int apn_entry_add_name(struct apn_entry * e, char * name)
{
        struct str_el * s;

        if (e == NULL || name == NULL)
                return -EINVAL;

        s = malloc(sizeof(*s));
        if (s == NULL)
                return -ENOMEM;

        s->str = name;
        list_add(&s->next, &e->names);

        return 0;
}

void apn_entry_del_name(struct apn_entry * e, char * name)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        list_for_each_safe(p, h, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                if (!wildcard_match(name, s->str)) {
                        list_del(&s->next);
                        if (s->str != NULL)
                                free(s->str);
                        free(s);
                }
        }
}

int apn_table_add(struct list_head * apn_table, struct apn_entry * e)
{
        if (apn_table == NULL || e == NULL)
                return -EINVAL;

        list_add(&e->next, apn_table);

        return 0;
}

void apn_table_del(struct list_head * apn_table, char * ap)
{
        struct list_head * p;
        struct list_head * h;

        if (apn_table == NULL || ap == NULL)
                return;

        list_for_each_safe(p, h, apn_table) {
                struct apn_entry * e = list_entry(p, struct apn_entry, next);
                if (!wildcard_match(ap, e->ap)) {
                        list_del(&e->next);
                        apn_entry_destroy(e);
                }
        }
}

struct apn_entry * apn_table_get(struct list_head * apn_table, char * ap)
{
        struct list_head * p;

        if (apn_table == NULL || ap == NULL)
                return NULL;

        list_for_each(p, apn_table) {
                struct apn_entry * e = list_entry(p, struct apn_entry, next);
                if (!strcmp(e->ap, ap))
                        return e;
        }

        return NULL;
}

struct apn_entry * apn_table_get_by_apn(struct list_head * apn_table,
                                        char *             apn)
{
        struct list_head * p;

        if (apn_table == NULL || apn == NULL)
                return NULL;

        list_for_each(p, apn_table) {
                struct apn_entry * e = list_entry(p, struct apn_entry, next);
                if (!strcmp(e->apn, apn))
                        return e;
        }

        return NULL;
}
