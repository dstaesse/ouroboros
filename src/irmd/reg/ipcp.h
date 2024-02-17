/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - IPCPs
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

#ifndef OUROBOROS_IRMD_REG_IPCP_H
#define OUROBOROS_IRMD_REG_IPCP_H

#include <ouroboros/list.h>
#include <ouroboros/ipcp.h>

struct reg_ipcp {
        struct list_head next;

        struct ipcp_info info;

        struct layer_info layer;
};

struct reg_ipcp * reg_ipcp_create(const struct ipcp_info * info);

void              reg_ipcp_destroy(struct reg_ipcp * ipcp);

void              reg_ipcp_update(struct reg_ipcp *        ipcp,
                                  const struct ipcp_info * info);

void              reg_ipcp_set_layer(struct reg_ipcp *         ipcp,
                                     const struct layer_info * info);

#endif /* OUROBOROS_IRMD_REG_IPCP_H */
