/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Hash table with separate chaining on collisions
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#endif

#include <ouroboros/hashtable.h>
#include <ouroboros/list.h>
#include <ouroboros/errno.h>
#include <ouroboros/hash.h>

#include <assert.h>
#include <string.h>

struct htable_entry {
        struct list_head next;
        uint64_t         key;
        void *           val;
        size_t           len;
};

struct htable {
        struct list_head * buckets;
        bool               hash_key;
        uint64_t           buckets_size;
};

struct htable * htable_create(uint64_t buckets,
                              bool     hash_key)
{
        struct htable * tmp;
        unsigned int i;

        if (buckets == 0)
                return NULL;

        buckets--;
        buckets |= buckets >> 1;
        buckets |= buckets >> 2;
        buckets |= buckets >> 4;
        buckets |= buckets >> 8;
        buckets |= buckets >> 16;
        buckets |= buckets >> 32;
        buckets++;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        tmp->hash_key = hash_key;
        tmp->buckets_size = buckets;

        tmp->buckets = malloc(buckets * sizeof(*tmp->buckets));
        if (tmp->buckets == NULL) {
                free(tmp);
                return NULL;
        }

        for (i = 0; i < buckets; i++)
                list_head_init(&(tmp->buckets[i]));

        return tmp;
}

void htable_destroy(struct htable * table)
{
        assert(table);
        assert(table->buckets);

        htable_flush(table);
        free(table->buckets);
        free(table);
}

void htable_flush(struct htable * table)
{
        unsigned int          i;
        struct list_head *    pos = NULL;
        struct list_head *    n = NULL;
        struct htable_entry * entry;

        assert(table);

        for (i = 0; i < table->buckets_size; i++) {
                list_for_each_safe(pos, n, &(table->buckets[i])) {
                        entry = list_entry(pos, struct htable_entry, next);
                        list_del(&entry->next);
                        free(entry->val);
                        free(entry);
                }
        }
}

static uint64_t hash(uint64_t key)
{
        void *   res;
        uint64_t ret;
        uint8_t  keys[4];

        memcpy(keys, &key, 4);

        mem_hash(HASH_MD5, &res, keys, 4);

        ret = (* (uint64_t *) res);

        free(res);

        return ret;
}

static uint64_t calc_key(struct htable * table,
                         uint64_t        key)
{
        if (table->hash_key)
                key = hash(key);

        return (key & (table->buckets_size - 1));
}

int htable_insert(struct htable * table,
                  uint64_t        key,
                  void *          val,
                  size_t          len)
{
        struct htable_entry * entry;
        uint64_t              lookup_key;
        struct list_head *    pos = NULL;

        assert(table);

        lookup_key = calc_key(table, key);

        list_for_each(pos, &(table->buckets[lookup_key])) {
                entry = list_entry(pos, struct htable_entry, next);
                if (entry->key == key)
                        return -1;
        }

        entry = malloc(sizeof(*entry));
        if (entry == NULL)
                return -ENOMEM;

        entry->key = key;
        entry->val = val;
        entry->len = len;
        list_head_init(&entry->next);

        list_add(&entry->next, &(table->buckets[lookup_key]));

        return 0;
}

int htable_lookup(struct htable * table,
                  uint64_t        key,
                  void **         val,
                  size_t *        len)
{
        struct htable_entry * entry;
        struct list_head *    pos = NULL;
        uint64_t              lookup_key;

        assert(table);

        lookup_key = calc_key(table, key);

        list_for_each(pos, &(table->buckets[lookup_key])) {
                entry = list_entry(pos, struct htable_entry, next);
                if (entry->key == key) {
                        *val = entry->val;
                        *len = entry->len;
                        return 0;
                }
        }

        return -1;
}

int htable_delete(struct htable * table,
                  uint64_t        key)
{
        struct htable_entry * entry;
        uint64_t              lookup_key;
        struct list_head *    pos = NULL;
        struct list_head *    n = NULL;

        assert(table);

        lookup_key = calc_key(table, key);

        list_for_each_safe(pos, n, &(table->buckets[lookup_key])) {
                entry = list_entry(pos, struct htable_entry, next);
                if (entry->key == key) {
                        list_del(&entry->next);
                        free(entry->val);
                        free(entry);
                        return 0;
                }
        }

        return -1;
}
