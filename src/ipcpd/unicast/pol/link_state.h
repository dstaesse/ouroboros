/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Link state routing policy
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

#ifndef OUROBOROS_IPCPD_UNICAST_POL_LINK_STATE_H
#define OUROBOROS_IPCPD_UNICAST_POL_LINK_STATE_H

#define LS_COMP  "Management"
#define LS_PROTO "LSP"

#include "pol-routing-ops.h"

int                link_state_init(enum pol_routing pr);

void               link_state_fini(void);

struct routing_i * link_state_routing_i_create(struct pff * pff);

void               link_state_routing_i_destroy(struct routing_i * instance);

extern struct pol_routing_ops link_state_ops;

#endif /* OUROBOROS_IPCPD_UNICAST_POL_LINK_STATE_H */
