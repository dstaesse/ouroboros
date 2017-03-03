/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Routing component of the IPCP
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef OUROBOROS_IPCPD_NORMAL_ROUTING_H
#define OUROBOROS_IPCPD_NORMAL_ROUTING_H

#include <ouroboros/qos.h>

#include "pff.h"
#include "neighbors.h"

#include <stdint.h>

/*
 * Routing will take a type in the future,
 * to allow different policies.
 */
struct routing * routing_create(struct pff * pff,
                                struct nbs * nbs);

void             routing_destroy(struct routing * instance);

#endif /* OUROBOROS_IPCPD_NORMAL_ROUTING_H */
