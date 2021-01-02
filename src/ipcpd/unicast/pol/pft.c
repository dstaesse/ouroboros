/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Packet forwarding table (PFT) with chaining on collisions
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#endif

#include <ouroboros/list.h>
#include <ouroboros/errno.h>
#include <ouroboros/hash.h>

#include "pft.h"

#include <assert.h>
#include <string.h>

/* store <len> output fds for dst addr */
struct pft_entry {
        struct list_head next;
        uint64_t         dst;
        int *            fds;
        size_t           len;
};

struct pft {
        struct list_head * buckets;
        bool               hash_key;
        uint64_t           buckets_size;
};

struct pft * pft_create(uint64_t buckets,
                        bool     hash_key)
{
        struct pft * tmp;
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

void pft_destroy(struct pft * pft)
{
        assert(pft);
        assert(pft->buckets);

        pft_flush(pft);
        free(pft->buckets);
        free(pft);
}

void pft_flush(struct pft * pft)
{
        unsigned int       i;
        struct list_head * p;
        struct list_head * h;
        struct pft_entry * entry;

        assert(pft);

        for (i = 0; i < pft->buckets_size; i++) {
                list_for_each_safe(p, h, &(pft->buckets[i])) {
                        entry = list_entry(p, struct pft_entry, next);
                        list_del(&entry->next);
                        free(entry->fds);
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

static uint64_t calc_key(struct pft * pft,
                         uint64_t     dst)
{
        if (pft->hash_key)
                dst = hash(dst);

        return (dst & (pft->buckets_size - 1));
}

int pft_insert(struct pft * pft,
               uint64_t     dst,
               int *        fds,
               size_t       len)
{
        struct pft_entry * entry;
        uint64_t           lookup_key;
        struct list_head * p;

        assert(pft);
        assert(len > 0);

        lookup_key = calc_key(pft, dst);

        list_for_each(p, &(pft->buckets[lookup_key])) {
                entry = list_entry(p, struct pft_entry, next);
                if (entry->dst == dst)
                        return -EPERM;
        }

        entry = malloc(sizeof(*entry));
        if (entry == NULL)
                return -ENOMEM;

        entry->dst = dst;
        entry->fds = fds;
        entry->len = len;

        list_add(&entry->next, &(pft->buckets[lookup_key]));

        return 0;
}

int pft_lookup(struct pft * pft,
               uint64_t     dst,
               int **       fds,
               size_t *     len)
{
        struct pft_entry * entry;
        struct list_head * p;
        uint64_t           lookup_key;

        assert(pft);

        lookup_key = calc_key(pft, dst);

        list_for_each(p, &(pft->buckets[lookup_key])) {
                entry = list_entry(p, struct pft_entry, next);
                if (entry->dst == dst) {
                        *fds = entry->fds;
                        *len = entry->len;
                        return 0;
                }
        }

        return -1;
}

int pft_delete(struct pft * pft,
               uint64_t     dst)
{
        struct pft_entry * entry;
        uint64_t           lookup_key;
        struct list_head * p;
        struct list_head * h;

        assert(pft);

        lookup_key = calc_key(pft, dst);

        list_for_each_safe(p, h, &(pft->buckets[lookup_key])) {
                entry = list_entry(p, struct pft_entry, next);
                if (entry->dst == dst) {
                        list_del(&entry->next);
                        free(entry->fds);
                        free(entry);
                        return 0;
                }
        }

        return -1;
}
