/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Address authority
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

#define OUROBOROS_PREFIX "addr_auth"

#include <ouroboros/logs.h>

#include "addr-auth.h"
#include "addr-auth/pol.h"

#include <stdlib.h>

struct addr_auth_ops * ops;

int addr_auth_init(enum pol_addr_auth type,
                   const void *       info)
{
        switch (type) {
        case ADDR_AUTH_FLAT_RANDOM:
                ops = &flat_ops;
                break;
        default:
                log_err("Unknown address authority type.");
                return -1;
        }

        return ops->init(info);
}

uint64_t addr_auth_address(void)
{
        return ops->address();
}

int addr_auth_fini(void)
{
        return ops->fini();
}
