/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * IPC process utilities
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

#include <ouroboros/config.h>
#include <ouroboros/list.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>

#include "shim-data.h"
#include "ipcp.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

struct reg_entry {
        struct list_head list;
        char *           name;
};

struct dir_entry {
        struct list_head list;
        char *           name;
        uint64_t         addr;
};

static struct reg_entry * reg_entry_create(char * name)
{
        struct reg_entry * entry = malloc(sizeof(*entry));
        if (entry == NULL)
                return NULL;

        assert(name);

        entry->name = name;
        if (entry->name == NULL)
                return NULL;

        return entry;
}

static void reg_entry_destroy(struct reg_entry * entry)
{
        assert(entry);

        if (entry->name != NULL)
                free(entry->name);

        free(entry);
}

static struct dir_entry * dir_entry_create(char *   name,
                                           uint64_t addr)
{
        struct dir_entry * entry = malloc(sizeof(*entry));
        if (entry == NULL)
                return NULL;

        assert(name);

        entry->addr    = addr;
        entry->name = name;
        if (entry->name == NULL)
                return NULL;

        return entry;
}

static void dir_entry_destroy(struct dir_entry * entry)
{
        assert(entry);

        if (entry->name != NULL)
                free(entry->name);

        free(entry);
}

struct shim_data * shim_data_create()
{
        struct shim_data * sd = malloc(sizeof(*sd));
        if (sd == NULL)
                return NULL;

        /* init the lists */
        list_head_init(&sd->registry);
        list_head_init(&sd->directory);
        list_head_init(&sd->dir_queries);

        /* init the locks */
        pthread_rwlock_init(&sd->reg_lock, NULL);
        pthread_rwlock_init(&sd->dir_lock, NULL);
        pthread_mutex_init(&sd->dir_queries_lock, NULL);

        return sd;
}

static void clear_registry(struct shim_data * data)
{
        struct list_head * h;
        struct list_head * t;

        assert(data);

        list_for_each_safe(h, t, &data->registry) {
                struct reg_entry * e = list_entry(h, struct reg_entry, list);
                list_del(&e->list);
                reg_entry_destroy(e);
        }
}

static void clear_directory(struct shim_data * data)
{
        struct list_head * h;
        struct list_head * t;

        assert(data);

        list_for_each_safe(h, t, &data->directory) {
                struct dir_entry * e = list_entry(h, struct dir_entry, list);
                list_del(&e->list);
                dir_entry_destroy(e);
        }
}

static void clear_dir_queries(struct shim_data * data)
{
        struct list_head * h;
        struct list_head * t;

        assert(data);

        list_for_each_safe(h, t, &data->dir_queries) {
                struct dir_query * e = list_entry(h, struct dir_query, next);
                list_del(&e->next);
                shim_data_dir_query_destroy(e);
        }
}

void shim_data_destroy(struct shim_data * data)
{
        if (data == NULL)
                return;

        /* clear the lists */
        pthread_rwlock_wrlock(&data->reg_lock);
        clear_registry(data);
        pthread_rwlock_unlock(&data->reg_lock);

        pthread_rwlock_wrlock(&data->dir_lock);
        clear_directory(data);
        pthread_rwlock_unlock(&data->dir_lock);

        pthread_mutex_lock(&data->dir_queries_lock);
        clear_dir_queries(data);
        pthread_mutex_unlock(&data->dir_queries_lock);

        pthread_rwlock_destroy(&data->dir_lock);
        pthread_rwlock_destroy(&data->reg_lock);
        pthread_mutex_destroy(&data->dir_queries_lock);

        free(data);
}

static struct reg_entry * find_reg_entry_by_name(struct shim_data * data,
                                                 const char *       name)
{
        struct list_head * h;

        assert(data);
        assert(name);

        list_for_each(h, &data->registry) {
                struct reg_entry * e = list_entry(h, struct reg_entry, list);
                if (!strcmp(e->name, name))
                        return e;
        }

        return NULL;
}

static struct dir_entry * find_dir_entry(struct shim_data * data,
                                         const char *       name,
                                         uint64_t           addr)
{
        struct list_head * h;
        list_for_each(h, &data->directory) {
                struct dir_entry * e = list_entry(h, struct dir_entry, list);
                if (e->addr == addr && !strcmp(e->name, name))
                        return e;
        }

        return NULL;
}

static struct dir_entry * find_dir_entry_any(struct shim_data * data,
                                             const char *       name)
{
        struct list_head * h;
        list_for_each(h, &data->directory) {
                struct dir_entry * e = list_entry(h, struct dir_entry, list);
                if (!strcmp(e->name, name))
                        return e;
        }

        return NULL;
}

int shim_data_reg_add_entry(struct shim_data * data,
                            char *             name)
{
        struct reg_entry * entry;

        if (data == NULL || name == NULL)
                return -1;

        pthread_rwlock_wrlock(&data->reg_lock);

        if (find_reg_entry_by_name(data, name)) {
                pthread_rwlock_unlock(&data->reg_lock);
                return -1;
        }

        entry = reg_entry_create(name);
        if (entry == NULL) {
                pthread_rwlock_unlock(&data->reg_lock);
                return -1;
        }

        list_add(&entry->list, &data->registry);

        pthread_rwlock_unlock(&data->reg_lock);

        return 0;
}

int shim_data_reg_del_entry(struct shim_data * data,
                            const char *       name)
{
        struct reg_entry * e;
        if (data == NULL)
                return -1;

        pthread_rwlock_wrlock(&data->reg_lock);

        e = find_reg_entry_by_name(data, name);
        if (e == NULL) {
                pthread_rwlock_unlock(&data->reg_lock);
                return 0; /* nothing to do */
        }

        list_del(&e->list);

        pthread_rwlock_unlock(&data->reg_lock);

        reg_entry_destroy(e);

        return 0;
}

bool shim_data_reg_has(struct shim_data * data,
                       const char *       name)
{
        bool ret = false;

        if (data == NULL || name == NULL)
                return false;

        pthread_rwlock_rdlock(&data->reg_lock);

        ret = (find_reg_entry_by_name(data, name) != NULL);

        pthread_rwlock_unlock(&data->reg_lock);

        return ret;
}

int shim_data_dir_add_entry(struct shim_data * data,
                            char *             name,
                            uint64_t           addr)
{
        struct dir_entry * entry;
        char * entry_name;

        if (data == NULL || name == NULL)
                return -1;

        pthread_rwlock_wrlock(&data->dir_lock);

        if (find_dir_entry(data, name, addr) != NULL) {
                pthread_rwlock_unlock(&data->dir_lock);
                return -1;
        }

        entry_name = strdup(name);
        if (entry_name == NULL) {
                pthread_rwlock_unlock(&data->dir_lock);
                return -1;
        }

        entry = dir_entry_create(entry_name, addr);
        if (entry == NULL) {
                pthread_rwlock_unlock(&data->dir_lock);
                return -1;
        }

        list_add(&entry->list,&data->directory);

        pthread_rwlock_unlock(&data->dir_lock);

        return 0;
}

int shim_data_dir_del_entry(struct shim_data * data,
                            const char *       name,
                            uint64_t           addr)
{
        struct dir_entry * e;
        if (data == NULL)
                return -1;

        pthread_rwlock_wrlock(&data->dir_lock);

        e = find_dir_entry(data, name, addr);
        if (e == NULL) {
                pthread_rwlock_unlock(&data->dir_lock);
                return 0; /* nothing to do */
        }

        list_del(&e->list);

        pthread_rwlock_unlock(&data->dir_lock);

        dir_entry_destroy(e);

        return 0;
}

bool shim_data_dir_has(struct shim_data * data,
                       const char *       name)
{
        bool ret = false;

        pthread_rwlock_rdlock(&data->dir_lock);

        ret = (find_dir_entry_any(data, name) != NULL);

        pthread_rwlock_unlock(&data->dir_lock);

        return ret;
}

uint64_t shim_data_dir_get_addr(struct shim_data * data,
                                const char *       name)
{
        struct dir_entry * entry;
        uint64_t           addr;

        pthread_rwlock_rdlock(&data->dir_lock);

        entry = find_dir_entry_any(data, name);

        if (entry == NULL) {
                pthread_rwlock_unlock(&data->dir_lock);
                return 0; /* undefined behaviour, 0 may be a valid address */
        }

        addr = entry->addr;

        pthread_rwlock_unlock(&data->dir_lock);

        return addr;
}

struct dir_query * shim_data_dir_query_create(char * name)
{
        struct dir_query * query;
        pthread_condattr_t cattr;

        query = malloc(sizeof(*query));
        if (query == NULL)
                return NULL;

        query->name = strdup(name);
        if (query->name == NULL) {
                free(query);
                return NULL;
        }

        query->state = QUERY_INIT;

        pthread_condattr_init(&cattr);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        pthread_cond_init(&query->cond, &cattr);
        pthread_mutex_init(&query->lock, NULL);

        list_head_init(&query->next);

        return query;
}

void shim_data_dir_query_respond(struct dir_query * query)
{
        assert(query);

        pthread_mutex_lock(&query->lock);

        if (query->state != QUERY_PENDING) {
                pthread_mutex_unlock(&query->lock);
                return;
        }

        query->state = QUERY_RESPONSE;
        pthread_cond_broadcast(&query->cond);

        while (query->state == QUERY_RESPONSE)
                pthread_cond_wait(&query->cond, &query->lock);

        pthread_mutex_unlock(&query->lock);
}

void shim_data_dir_query_destroy(struct dir_query * query)
{
        assert(query);

        pthread_mutex_lock(&query->lock);

        if (query->state == QUERY_DESTROY) {
                pthread_mutex_unlock(&query->lock);
                return;
        }

        if (query->state == QUERY_INIT)
                query->state = QUERY_DONE;

        if (query->state == QUERY_PENDING) {
                query->state = QUERY_DESTROY;
                pthread_cond_broadcast(&query->cond);
        }

        while (query->state != QUERY_DONE)
                pthread_cond_wait(&query->cond, &query->lock);

        pthread_mutex_unlock(&query->lock);

        pthread_cond_destroy(&query->cond);
        pthread_mutex_destroy(&query->lock);

        free(query->name);
        free(query);
}

int shim_data_dir_query_wait(struct dir_query *      query,
                             const struct timespec * timeout)
{
        struct timespec abstime;
        int ret = 0;

        assert(query);
        assert(timeout);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, timeout, &abstime);

        pthread_mutex_lock(&query->lock);

        if (query->state != QUERY_INIT) {
                pthread_mutex_unlock(&query->lock);
                return -EINVAL;
        }

        query->state = QUERY_PENDING;

        while (query->state == QUERY_PENDING && ret != -ETIMEDOUT)
                ret = -pthread_cond_timedwait(&query->cond,
                                              &query->lock,
                                              &abstime);

        if (query->state == QUERY_DESTROY)
                ret = -1;

        query->state = QUERY_DONE;
        pthread_cond_broadcast(&query->cond);

        pthread_mutex_unlock(&query->lock);

        return ret;
}
