/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Directory
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

#define _POSIX_C_SOURCE 200112L

#define OUROBOROS_PREFIX "directory"

#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/utils.h>

#include "dir.h"
#include "dht.h"
#include "ipcp.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#define KAD_B (hash_len(ipcpi.dir_hash_algo) * CHAR_BIT)

struct dht * dht;

int dir_init(void)
{
        dht = dht_create(ipcpi.dt_addr);
        if (dht == NULL)
                return -ENOMEM;

        return 0;
}

void dir_fini(void)
{
        dht_destroy(dht);
}

int dir_bootstrap(void) {
        log_dbg("Bootstrapping directory.");

        /* TODO: get parameters for bootstrap from IRM tool. */
        if (dht_bootstrap(dht, KAD_B, 86400)) {
                dht_destroy(dht);
                return -ENOMEM;
        }

        log_info("Directory bootstrapped.");

        return 0;
}

int dir_reg(const uint8_t * hash)
{
        return dht_reg(dht, hash);
}

int dir_unreg(const uint8_t * hash)
{
        return dht_unreg(dht, hash);
}

uint64_t dir_query(const uint8_t * hash)
{
        return dht_query(dht, hash);
}
