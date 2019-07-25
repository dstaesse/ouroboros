/*
 * Ouroboros - Copyright (C) 2016 - 2019
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

#ifndef OUROBOROS_IPCPD_UNICAST_FLAT_H
#define OUROBOROS_IPCPD_UNICAST_FLAT_H

#include "pol-addr-auth-ops.h"

int      flat_init(const void * info);

int      flat_fini(void);

uint64_t flat_address(void);

struct pol_addr_auth_ops flat_ops;

#endif /* OUROBOROS_IPCPD_UNICAST_FLAT_H */
