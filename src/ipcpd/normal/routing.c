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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200112L

#include <ouroboros/errno.h>

#include "routing.h"
#include "pol/link_state.h"

struct pol_routing_ops * r_ops;

int routing_init(enum pol_routing pr)
{
        switch (pr) {
        case ROUTING_LINK_STATE:
                r_ops = &link_state_ops;
                break;
        default:
                return -ENOTSUP;
        }

        return r_ops->init();
}

struct routing_i * routing_i_create(struct pff * pff)
{
        return r_ops->routing_i_create(pff);
}

void routing_i_destroy(struct routing_i * instance)
{
        return r_ops->routing_i_destroy(instance);
}

void routing_fini(void)
{
        r_ops->fini();
}
