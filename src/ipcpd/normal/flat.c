/*
 * Ouroboros - Copyright (C) 2016
 *
 * Policy for flat addresses in a distributed way
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "flat-addr-auth"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>

#include <time.h>
#include <stdlib.h>
#include <math.h>

#include "shm_pci.h"
#include "ribmgr.h"

int flat_init(void)
{
        srand(time(NULL));

        return 0;
}

int flat_fini(void)
{
        return 0;
}

uint64_t flat_address(void)
{
        uint64_t addr;
        uint64_t max_addr;
        struct dt_const * dtc;

        dtc = ribmgr_dt_const();
        if (dtc == NULL)
                return INVALID_ADDR;

        max_addr = (1 << (8 * dtc->addr_size)) - 1;
        addr = (rand() % (max_addr - 1)) + 1;

        /* FIXME: Add check for uniqueness of address */

        return addr;
}
