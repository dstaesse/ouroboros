/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Policy for flat addresses in a distributed way
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

#define OUROBOROS_PREFIX "flat-addr-auth"

#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/utils.h>

#include "ipcp.h"

#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <assert.h>

#define NAME_LEN 8
#define REC_DIF_SIZE 10000

struct {
        uint8_t addr_size;
} flat;

#define INVALID_ADDRESS 0

int flat_init(const void * info)
{
        flat.addr_size = *((uint8_t *) info);

        if (flat.addr_size != 4) {
                log_err("Flat address policy mandates 4 byte addresses.");
                return -1;
        }

        return 0;
}

int flat_fini(void)
{
        return 0;
}

uint64_t flat_address(void)
{
        struct timespec t;
        uint32_t        addr;

        clock_gettime(CLOCK_REALTIME, &t);
        srand(t.tv_nsec);

        addr = (rand() % (RAND_MAX - 1) + 1) & 0xFFFFFFFF;

        return addr;
}
