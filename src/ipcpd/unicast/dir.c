/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Directory
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
#include "dir/ops.h"
#include "dir/dht.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <limits.h>

struct {
        struct dir_ops * ops;
} dir;

int dir_init(void)
{
        dir.ops = &dht_dir_ops;

        if (dir.ops->init() < 0) {
                dir.ops = NULL;
                return -ENOMEM;
        }

        return 0;
}

void dir_fini(void)
{
        dir.ops->fini();
        dir.ops = NULL;
}

int dir_bootstrap(void)
{
        return dir.ops->bootstrap();
}

int dir_reg(const uint8_t * hash)
{
        return dir.ops->reg(hash);
}

int dir_unreg(const uint8_t * hash)
{
        return dir.ops->unreg(hash);
}

uint64_t dir_query(const uint8_t * hash)
{
        return dir.ops->query(hash);
}

int dir_wait_running(void)
{
        return dir.ops->wait_running();
}
