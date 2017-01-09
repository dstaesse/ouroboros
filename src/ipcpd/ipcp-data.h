/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Utitilies for building IPC processes
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#ifndef IPCPD_IPCP_DATA_H
#define IPCPD_IPCP_DATA_H

#include <ouroboros/shared.h>
#include <ouroboros/list.h>

#include "ipcp-ops.h"

#include <sys/types.h>
#include <pthread.h>

enum dir_query_state {
        QUERY_INIT = 0,
        QUERY_PENDING,
        QUERY_RESPONSE,
        QUERY_DONE,
        QUERY_DESTROY
};

struct dir_query {
        struct list_head     next;
        char *               name;
        enum dir_query_state state;

        pthread_mutex_t      lock;
        pthread_cond_t       cond;
};

struct ipcp_data {
        enum ipcp_type      type;
        char *              dif_name;

        struct list_head    registry;
        pthread_rwlock_t    reg_lock;

        struct list_head    directory;
        pthread_rwlock_t    dir_lock;

        struct list_head    dir_queries;
        pthread_mutex_t     dir_queries_lock;
};

struct ipcp_data * ipcp_data_create(void);

struct ipcp_data * ipcp_data_init(struct ipcp_data * dst,
                                  enum ipcp_type     ipcp_type);

void               ipcp_data_destroy(struct ipcp_data * data);

int                ipcp_data_reg_add_entry(struct ipcp_data * data,
                                           char *             name);

int                ipcp_data_reg_del_entry(struct ipcp_data * data,
                                           const char *       name);

bool               ipcp_data_reg_has(struct ipcp_data * data,
                                     const char *       name);

int                ipcp_data_dir_add_entry(struct ipcp_data * data,
                                           char *             name,
                                           uint64_t           addr);

int                ipcp_data_dir_del_entry(struct ipcp_data * data,
                                           const char *       name,
                                           uint64_t           addr);

bool               ipcp_data_dir_has(struct ipcp_data * data,
                                     const char *       name);

uint64_t           ipcp_data_dir_get_addr(struct ipcp_data * data,
                                          const char *       name);

struct dir_query * ipcp_data_dir_query_create(char * name);

void               ipcp_data_dir_query_respond(struct dir_query * query);

void               ipcp_data_dir_query_destroy(struct dir_query * query);

int                ipcp_data_dir_query_wait(struct dir_query *      query,
                                            const struct timespec * timeout);
#endif /* IPCPD_IPCP_DATA_H */
