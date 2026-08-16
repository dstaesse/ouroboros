/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Names registered with the local IPCP
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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
#else
#define _POSIX_C_SOURCE 200112L
#endif

#define OUROBOROS_PREFIX "local-reg"

#include <ouroboros/hash.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>

#include "reg.h"
#include "ipcp.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct reg_entry {
        struct list_head list;
        uint8_t *        hash;
};

struct reg {
        struct list_head names;
        pthread_rwlock_t lock;
};

static struct reg_entry * reg_entry_create(uint8_t * hash)
{
        struct reg_entry * entry;

        entry = malloc(sizeof(*entry));
        if (entry == NULL)
                return NULL;

        list_head_init(&entry->list);

        entry->hash = hash;

        return entry;
}

static void reg_entry_destroy(struct reg_entry * entry)
{
        assert(entry);

        free(entry->hash);
        free(entry);
}

/* Call with the lock held. */
static struct reg_entry * reg_find(struct reg *    reg,
                                   const uint8_t * hash)
{
        struct list_head * p;

        list_for_each(p, &reg->names) {
                struct reg_entry * e;

                e = list_entry(p, struct reg_entry, list);
                if (memcmp(e->hash, hash, ipcp_dir_hash_len()) == 0)
                        return e;
        }

        return NULL;
}

struct reg * reg_create(void)
{
        struct reg * reg;

        reg = malloc(sizeof(*reg));
        if (reg == NULL)
                goto fail_malloc;

        list_head_init(&reg->names);

        if (pthread_rwlock_init(&reg->lock, NULL) < 0)
                goto fail_lock;

        return reg;

 fail_lock:
        free(reg);
 fail_malloc:
        return NULL;
}

void reg_destroy(struct reg * reg)
{
        if (reg == NULL)
                return;

        pthread_rwlock_wrlock(&reg->lock);

        while (!list_is_empty(&reg->names)) {
                struct reg_entry * e;

                e = list_first_entry(&reg->names, struct reg_entry, list);

                list_del(&e->list);

                reg_entry_destroy(e);
        }

        pthread_rwlock_unlock(&reg->lock);

        pthread_rwlock_destroy(&reg->lock);

        free(reg);
}

int reg_add(struct reg *    reg,
            const uint8_t * hash)
{
        struct reg_entry * entry;
        uint8_t *          dup;

        assert(reg);
        assert(hash);

        pthread_rwlock_wrlock(&reg->lock);

        if (reg_find(reg, hash) != NULL) {
                pthread_rwlock_unlock(&reg->lock);
                log_dbg(HASH_FMT32 " was already registered.",
                        HASH_VAL32(hash));
                return 0;
        }

        dup = ipcp_hash_dup(hash);
        if (dup == NULL)
                goto fail;

        entry = reg_entry_create(dup);
        if (entry == NULL) {
                free(dup);
                goto fail;
        }

        list_add(&entry->list, &reg->names);

        pthread_rwlock_unlock(&reg->lock);

        return 0;

 fail:
        pthread_rwlock_unlock(&reg->lock);
        return -1;
}

int reg_del(struct reg *    reg,
            const uint8_t * hash)
{
        struct reg_entry * e;

        if (reg == NULL)
                return -1;

        pthread_rwlock_wrlock(&reg->lock);

        e = reg_find(reg, hash);
        if (e == NULL) {
                pthread_rwlock_unlock(&reg->lock);
                return 0; /* nothing to do */
        }

        list_del(&e->list);

        pthread_rwlock_unlock(&reg->lock);

        reg_entry_destroy(e);

        return 0;
}

bool reg_has(struct reg *    reg,
             const uint8_t * hash)
{
        bool ret;

        assert(reg);
        assert(hash);

        pthread_rwlock_rdlock(&reg->lock);

        ret = reg_find(reg, hash) != NULL;

        pthread_rwlock_unlock(&reg->lock);

        return ret;
}
