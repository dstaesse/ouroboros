/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The IPC Resource Manager - Application Instance Table
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_IRMD_API_TABLE_H
#define OUROBOROS_IRMD_API_TABLE_H

#include "utils.h"

#include <unistd.h>
#include <pthread.h>

enum api_state {
        API_NULL = 0,
        API_INIT,
        API_SLEEP,
        API_WAKE,
        API_DESTROY
};

struct api_entry {
        struct list_head   next;
        pid_t              api;
        char *             apn;      /* application process instantiated */
        char *             daf_name; /* DAF this AP-I belongs to */
        struct list_head   names;    /* names for which api accepts flows */

        struct reg_entry * re;       /* reg_entry for which a flow arrived */

        /* the api will block on this */
        enum api_state     state;
        pthread_cond_t     state_cond;
        pthread_mutex_t    state_lock;
};

struct api_entry * api_entry_create(pid_t  api,
                                    char * apn);

void               api_entry_destroy(struct api_entry * e);

int                api_entry_sleep(struct api_entry * e);

void               api_entry_wake(struct api_entry * e,
                                  struct reg_entry * re);

void               api_entry_cancel(struct api_entry * e);

int                api_entry_add_name(struct api_entry * e,
                                      char *             name);

void               api_entry_del_name(struct api_entry * e,
                                      const char *       name);

int                api_table_add(struct list_head * api_table,
                                 struct api_entry * e);

void               api_table_del(struct list_head * api_table,
                                 pid_t              api);

struct api_entry * api_table_get(struct list_head * api_table,
                                 pid_t              api);

#endif /* OUROBOROS_IRMD_API_TABLE_H */
