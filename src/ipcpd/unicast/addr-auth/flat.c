/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Policy for flat addresses in a distributed way
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

#define OUROBOROS_PREFIX "flat-addr-auth"

#include <ouroboros/logs.h>
#include <ouroboros/random.h>

#include "addr-auth.h"
#include "ipcp.h"
#include "flat.h"

#define NAME_LEN        8
#define INVALID_ADDRESS 0

struct {
        uint8_t  addr_size;
        uint32_t addr;
} flat;

struct addr_auth_ops flat_ops = {
        .init    = flat_init,
        .fini    = flat_fini,
        .address = flat_address
};

int flat_init(const void * info)
{
        flat.addr_size = *((uint8_t *) info);

        if (flat.addr_size != 4) {
                log_err("Flat address policy mandates 4 byte addresses.");
                return -1;
        }

#if defined (CONFIG_OUROBOROS_DEBUG) && defined (IPCP_DEBUG_LOCAL)
        flat.addr = getpid();
#else
        while (flat.addr == INVALID_ADDRESS)
                random_buffer(&flat.addr,sizeof(flat.addr));
#endif
        log_dbg("Flat address initialized to " ADDR_FMT32 ".",
                ADDR_VAL32((uint8_t *) &flat.addr));

        return 0;
}

int flat_fini(void)
{
        return 0;
}

uint64_t flat_address(void)
{
        return (uint64_t) flat.addr;
}
