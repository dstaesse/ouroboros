/*
 * Ouroboros - Copyright (C) 2016
 *
 * Address authority
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

#ifndef OUROBOROS_IPCPD_NORMAL_ADDR_AUTH_H
#define OUROBOROS_IPCPD_NORMAL_ADDR_AUTH_H

#include <ouroboros/irm_config.h>

#include <stdint.h>

struct addr_auth {
        enum pol_addr_auth type;
        uint64_t (* address)(void);
};

struct addr_auth * addr_auth_create(enum pol_addr_auth type);

int                addr_auth_destroy(struct addr_auth * instance);

#endif /* OUROBOROS_IPCPD_NORMAL_ADDR_AUTH_H */
