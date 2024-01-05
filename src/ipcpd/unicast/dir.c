/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Directory Management
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

#define OUROBOROS_PREFIX "directory"

#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/utils.h>

#include "dir.h"
#include "dir/pol.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <limits.h>

struct {
        struct dir_ops * ops;
        void *           dir;
} dirmgr;

int dir_init(void)
{
        dirmgr.ops = &dht_dir_ops;

        dirmgr.dir = dirmgr.ops->create();
        if (dirmgr.dir == NULL) {
                dirmgr.ops = NULL;
                return -ENOMEM;
        }

        return 0;
}

void dir_fini(void)
{
        dirmgr.ops->destroy(dirmgr.dir);
        dirmgr.ops = NULL;
        dirmgr.dir = NULL;
}

int dir_bootstrap(void)
{
        return dirmgr.ops->bootstrap(dirmgr.dir);
}

int dir_reg(const uint8_t * hash)
{
        return dirmgr.ops->reg(dirmgr.dir, hash);
}

int dir_unreg(const uint8_t * hash)
{
        return dirmgr.ops->unreg(dirmgr.dir, hash);
}

uint64_t dir_query(const uint8_t * hash)
{
        return dirmgr.ops->query(dirmgr.dir, hash);
}

int dir_wait_running(void)
{
        return dirmgr.ops->wait_running(dirmgr.dir);
}
