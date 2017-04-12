/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Utitilies for building IPC processes
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

#ifndef IPCPD_IPCP_DATA_H
#define IPCPD_IPCP_DATA_H

#include <ouroboros/shared.h>
#include <ouroboros/list.h>

#include <sys/types.h>
#include <pthread.h>
#include <stdint.h>

enum dir_query_state {
        QUERY_INIT = 0,
        QUERY_PENDING,
        QUERY_RESPONSE,
        QUERY_DONE,
        QUERY_DESTROY
};

struct dir_query {
        struct list_head     next;
        uint8_t *            hash;
        enum dir_query_state state;

        pthread_mutex_t      lock;
        pthread_cond_t       cond;
};

struct shim_data {
        struct list_head registry;
        pthread_rwlock_t reg_lock;

        struct list_head directory;
        pthread_rwlock_t dir_lock;

        struct list_head dir_queries;
        pthread_mutex_t  dir_queries_lock;
};

struct shim_data * shim_data_create(void);

void               shim_data_destroy(struct shim_data * data);

int                shim_data_reg_add_entry(struct shim_data * data,
                                           uint8_t *          hash);

int                shim_data_reg_del_entry(struct shim_data * data,
                                           const uint8_t *    hash);

bool               shim_data_reg_has(struct shim_data * data,
                                     const uint8_t *    hash);

int                shim_data_dir_add_entry(struct shim_data * data,
                                           const uint8_t *    hash,
                                           uint64_t           addr);

int                shim_data_dir_del_entry(struct shim_data * data,
                                           const uint8_t *    hash,
                                           uint64_t           addr);

bool               shim_data_dir_has(struct shim_data * data,
                                     const uint8_t *    hash);

uint64_t           shim_data_dir_get_addr(struct shim_data * data,
                                          const uint8_t *    hash);

struct dir_query * shim_data_dir_query_create(const uint8_t * hash);

void               shim_data_dir_query_respond(struct dir_query * query);

void               shim_data_dir_query_destroy(struct dir_query * query);

int                shim_data_dir_query_wait(struct dir_query *      query,
                                            const struct timespec * timeout);
#endif /* IPCPD_SHIM_DATA_H */
