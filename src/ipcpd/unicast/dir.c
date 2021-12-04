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
#include "dht.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <limits.h>

int dir_init(void)
{
        if (dht_init() < 0)
                return -ENOMEM;

        return 0;
}

void dir_fini(void)
{
        dht_fini();
}

int dir_bootstrap(void) {
        log_dbg("Bootstrapping directory.");

        if (dht_bootstrap()) {
                dht_fini();
                return -ENOMEM;
        }

        log_info("Directory bootstrapped.");

        return 0;
}

int dir_reg(const uint8_t * hash)
{
        return dht_reg(hash);
}

int dir_unreg(const uint8_t * hash)
{
        return dht_unreg(hash);
}

uint64_t dir_query(const uint8_t * hash)
{
        return dht_query(hash);
}

int dir_wait_running(void)
{
        if (dht_wait_running()) {
                log_warn("Directory did not bootstrap.");
                return -1;
        }

        return 0;
}
