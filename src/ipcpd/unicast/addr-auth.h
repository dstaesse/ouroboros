/*
 * Ouroboros - Copyright (C) 2016 - 2026
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

#ifndef OUROBOROS_IPCPD_UNICAST_ADDR_AUTH_H
#define OUROBOROS_IPCPD_UNICAST_ADDR_AUTH_H

#include <ouroboros/ipcp.h>

#include <stdint.h>

#define ADDR_FMT32 "%02x.%02x.%02x.%02x"
#define ADDR_VAL32(a) \
        ((uint8_t *) a)[0], ((uint8_t *) a)[1], \
        ((uint8_t *) a)[2], ((uint8_t *) a)[3]

#define ADDR_FMT64 ADDR_FMT32 "." ADDR_FMT32
#define ADDR_VAL64(a) ADDR_VAL32(a), ADDR_VAL32(a + 4)

int      addr_auth_init(enum pol_addr_auth type,
                        const void *       info);

int      addr_auth_fini(void);

uint64_t addr_auth_address(void);

#endif /* OUROBOROS_IPCPD_UNICAST_ADDR_AUTH_H */
