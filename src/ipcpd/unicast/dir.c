/*
 * Ouroboros - Copyright (C) 2016 - 2026
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
} dir;

int dir_init(struct dir_config * conf)
{
        void * cfg;

        assert(conf != NULL);

        switch (conf->pol) {
        case DIR_DHT:
                log_info("Using DHT policy.");
                dir.ops = &dht_dir_ops;
                cfg = &conf->dht;
                break;
        default: /* DIR_INVALID */
                log_err("Invalid directory policy %d.", conf->pol);
                return -EINVAL;
        }

        assert(dir.ops->init != NULL);

        return dir.ops->init(cfg);
}

void dir_fini(void)
{
        dir.ops->fini();
        dir.ops = NULL;
}

int dir_start(void)
{
        return dir.ops->start();
}

void dir_stop(void)
{
        dir.ops->stop();
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
