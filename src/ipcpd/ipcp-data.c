/*
 * Ouroboros - Copyright (C) 2016
 *
 * IPC process utilities
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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
#include <ouroboros/shm_du_map.h>
#include <ouroboros/list.h>

#define OUROBOROS_PREFIX "ipcp-utils"

#include <ouroboros/logs.h>

#include "ipcp-data.h"

#include <string.h>
#include <stdlib.h>

struct reg_entry {
        struct list_head list;
        char *           name;
};

struct dir_entry {
        struct list_head list;
        char *     ap_name;
        uint64_t   addr;
};

static struct reg_entry * reg_entry_create(char * name)
{
        struct reg_entry * entry = malloc(sizeof(*entry));
        if (entry == NULL)
                return NULL;

        entry->name = name;
        if (entry->name == NULL)
                return NULL;

        return entry;
}

static void reg_entry_destroy(struct reg_entry * entry)
{
        if (entry == NULL)
                return;

        if (entry->name != NULL)
                free(entry->name);
        free(entry);
}

static struct dir_entry * dir_entry_create(char *   ap_name,
                                           uint64_t addr)
{
        struct dir_entry * entry = malloc(sizeof(*entry));
        if (entry == NULL)
                return NULL;

        entry->addr    = addr;
        entry->ap_name = ap_name;
        if (entry->ap_name == NULL)
                return NULL;

        return entry;
}

static void dir_entry_destroy(struct dir_entry * entry)
{
        if (entry == NULL)
                return;

        if (entry->ap_name != NULL)
                free(entry->ap_name);
        free(entry);
}

struct ipcp_data * ipcp_data_create()
{
        struct ipcp_data * data = malloc(sizeof(*data));
        if (data == NULL)
                return NULL;

        data->type = 0;

        return data;
}

struct ipcp_data * ipcp_data_init(struct ipcp_data * dst,
                                  enum ipcp_type     ipcp_type)
{
        if (dst == NULL)
                return NULL;

        dst->type  = ipcp_type;
        dst->dif_name = NULL;

        /* init the lists */
        INIT_LIST_HEAD(&dst->registry);
        INIT_LIST_HEAD(&dst->directory);

        /* init the mutexes */
        pthread_mutex_init(&dst->reg_lock, NULL);
        pthread_mutex_init(&dst->dir_lock, NULL);

        return dst;
}

static void clear_registry(struct ipcp_data * data)
{
        struct list_head * h;
        struct list_head * t;
        list_for_each_safe(h, t, &data->registry) {
                struct reg_entry * e = list_entry(h, struct reg_entry, list);
                list_del(&e->list);
                reg_entry_destroy(e);
        }
}

static void clear_directory(struct ipcp_data * data)
{
        struct list_head * h;
        struct list_head * t;
        list_for_each_safe(h, t, &data->directory) {
                struct dir_entry * e = list_entry(h, struct dir_entry, list);
                list_del(&e->list);
                dir_entry_destroy(e);
        }
}

void ipcp_data_destroy(struct ipcp_data * data)
{
        if (data == NULL)
                return;

        pthread_mutex_lock(&data->reg_lock);
        pthread_mutex_lock(&data->dir_lock);

        /* clear the lists */
        clear_registry(data);
        clear_directory(data);

        if (data->dif_name != NULL)
                free(data->dif_name);

        pthread_mutex_unlock(&data->dir_lock);
        pthread_mutex_unlock(&data->reg_lock);

        pthread_mutex_destroy(&data->dir_lock);
        pthread_mutex_destroy(&data->reg_lock);

        free(data);
}



static struct reg_entry * find_reg_entry_by_name(struct ipcp_data * data,
                                                 const char *       name)
{
        struct list_head * h;
        list_for_each(h, &data->registry) {
                struct reg_entry * e = list_entry(h, struct reg_entry, list);
                if (!strcmp(e->name, name))
                        return e;
        }

        return NULL;
}

static struct dir_entry * find_dir_entry(struct ipcp_data * data,
                                         const char *       ap_name,
                                         uint64_t           addr)
{
        struct list_head * h;
        list_for_each(h, &data->directory) {
                struct dir_entry * e = list_entry(h, struct dir_entry, list);
                if (e->addr == addr && !strcmp(e->ap_name, ap_name))
                        return e;
        }

        return NULL;
}

static struct dir_entry * find_dir_entry_any(struct ipcp_data * data,
                                             const char *       ap_name)
{
        struct list_head * h;
        list_for_each(h, &data->directory) {
                struct dir_entry * e = list_entry(h, struct dir_entry, list);
                if (!strcmp(e->ap_name, ap_name))
                        return e;
        }

        return NULL;
}

bool ipcp_data_is_in_directory(struct ipcp_data * data,
                               const char *       ap_name)
{
        return find_dir_entry_any(data, ap_name) != NULL;
}

int ipcp_data_del_reg_entry(struct ipcp_data * data,
                            const char *       name)
{
        struct reg_entry * e;
        if (data == NULL)
                return -1;

        pthread_mutex_lock(&data->reg_lock);

        e = find_reg_entry_by_name(data, name);
        if (e == NULL) {
                pthread_mutex_unlock(&data->reg_lock);
                return 0; /* nothing to do */
        }

        list_del(&e->list);

        reg_entry_destroy(e);

        pthread_mutex_unlock(&data->reg_lock);

        return 0;
}

int ipcp_data_del_dir_entry(struct ipcp_data * data,
                            const char *       ap_name,
                            uint64_t           addr)
{
        struct dir_entry * e;
        if (data == NULL)
                return -1;

        pthread_mutex_lock(&data->dir_lock);

        e = find_dir_entry(data, ap_name, addr);
        if (e == NULL) {
                pthread_mutex_unlock(&data->dir_lock);
                return 0; /* nothing to do */
        }

        list_del(&e->list);

        dir_entry_destroy(e);

        pthread_mutex_unlock(&data->dir_lock);

        return 0;
}

int ipcp_data_add_reg_entry(struct ipcp_data * data,
                            char *             name)
{
        struct reg_entry * entry;

        if (data == NULL || name == NULL)
                return -1;

        pthread_mutex_lock(&data->reg_lock);

        if (find_reg_entry_by_name(data, name)) {
                pthread_mutex_unlock(&data->reg_lock);
                return -2;
        }

        entry = reg_entry_create(name);
        if (entry == NULL) {
                pthread_mutex_unlock(&data->reg_lock);
                return -1;
        }

        list_add(&entry->list, &data->registry);

        pthread_mutex_unlock(&data->reg_lock);

        return 0;
}

int ipcp_data_add_dir_entry(struct ipcp_data * data,
                            char *             ap_name,
                            uint64_t           addr)
{
        struct dir_entry * entry;

        if (data == NULL || ap_name == NULL)
                return -1;

        pthread_mutex_lock(&data->dir_lock);

        if (find_dir_entry(data, ap_name, addr) != NULL) {
                pthread_mutex_unlock(&data->dir_lock);
                return -2;
        }

        entry = dir_entry_create(ap_name, addr);
        if (entry == NULL) {
                pthread_mutex_unlock(&data->dir_lock);
                return -1;
        }

        list_add(&entry->list,&data->directory);

        pthread_mutex_unlock(&data->dir_lock);

        return 0;
}

bool ipcp_data_is_in_registry(struct ipcp_data * data,
                              const char *       ap_name)
{
        return find_reg_entry_by_name(data, ap_name) != NULL;
}

uint64_t ipcp_data_get_addr(struct ipcp_data * data,
                            const char *       ap_name)
{
        struct dir_entry * entry;
        uint64_t           addr;

        pthread_mutex_lock(&data->dir_lock);

        entry = find_dir_entry_any(data, ap_name);

        if (entry == NULL) {
                pthread_mutex_unlock(&data->dir_lock);
                return 0; /* undefined behaviour, 0 may be a valid address */
        }

        addr = entry->addr;

        pthread_mutex_unlock(&data->dir_lock);

        return addr;
}
