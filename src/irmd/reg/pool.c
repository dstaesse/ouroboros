/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * The IPC Resource Manager - Registry - Per-User Pools
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

#define _POSIX_C_SOURCE 200809L

#define OUROBOROS_PREFIX "reg/pool"

#include <ouroboros/logs.h>
#include <ouroboros/ssm_pool.h>

#include "pool.h"

#include <assert.h>
#include <stdlib.h>

struct reg_pool * reg_pool_create(uid_t uid,
                                  gid_t gid)
{
        struct reg_pool * pool;

        pool = malloc(sizeof(*pool));
        if (pool == NULL) {
                log_err("Failed to malloc pool.");
                goto fail_malloc;
        }

        pool->ssm = ssm_pool_create(uid, gid);
        if (pool->ssm == NULL) {
                log_err("Failed to create PUP for uid %d.", uid);
                goto fail_ssm;
        }

        list_head_init(&pool->next);
        pool->uid      = uid;
        pool->gid      = gid;
        pool->refcount = 1;

        log_dbg("Created PUP for uid %d gid %d.", uid, gid);

        return pool;

 fail_ssm:
        free(pool);
 fail_malloc:
        return NULL;
}

void reg_pool_destroy(struct reg_pool * pool)
{
        assert(pool != NULL);
        assert(pool->refcount == 0);

        log_dbg("Destroying PUP for uid %d.", pool->uid);

        ssm_pool_destroy(pool->ssm);

        assert(list_is_empty(&pool->next));

        free(pool);
}

void reg_pool_ref(struct reg_pool * pool)
{
        assert(pool != NULL);
        assert(pool->refcount > 0);

        pool->refcount++;

        log_dbg("PUP uid %d refcount++ -> %zu.", pool->uid, pool->refcount);
}

int reg_pool_unref(struct reg_pool * pool)
{
        assert(pool != NULL);
        assert(pool->refcount > 0);

        pool->refcount--;

        log_dbg("PUP uid %d refcount-- -> %zu.", pool->uid, pool->refcount);

        return pool->refcount == 0 ? 0 : 1;
}
