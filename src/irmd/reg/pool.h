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

#ifndef OUROBOROS_IRMD_REG_POOL_H
#define OUROBOROS_IRMD_REG_POOL_H

#include <ouroboros/list.h>
#include <ouroboros/ssm_pool.h>

#include <sys/types.h>

struct reg_pool {
        struct list_head    next;
        uid_t               uid;
        gid_t               gid;
        size_t              refcount;
        struct ssm_pool *   ssm;
};

struct reg_pool * reg_pool_create(uid_t uid,
                                  gid_t gid);

void              reg_pool_destroy(struct reg_pool * pool);

void              reg_pool_ref(struct reg_pool * pool);

int               reg_pool_unref(struct reg_pool * pool);

#endif /* OUROBOROS_IRMD_REG_POOL_H */
