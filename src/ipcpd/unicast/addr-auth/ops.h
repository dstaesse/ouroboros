/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Address authority policy ops
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

#ifndef OUROBOROS_IPCPD_UNICAST_ADDR_AUTH_OPS_H
#define OUROBOROS_IPCPD_UNICAST_ADDR_AUTH_OPS_H

struct addr_auth_ops {
        int      (* init)(const void * info);

        int      (* fini)(void);

        uint64_t (* address)(void);
};

#endif /* OUROBOROS_IPCPD_UNICAST_ADDR_AUTH_OPS_H */
