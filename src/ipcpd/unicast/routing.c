/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Routing component of the IPCP
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

#define _POSIX_C_SOURCE 200112L

#include <ouroboros/errno.h>

#include "pff.h"
#include "routing.h"
#include "pol/link_state.h"

struct pol_routing_ops * r_ops;

int routing_init(enum pol_routing pr)
{
        enum pol_pff pff_type;

        switch (pr) {
        case ROUTING_LINK_STATE:
                pff_type = PFF_SIMPLE;
                r_ops = &link_state_ops;
                break;
        case ROUTING_LINK_STATE_LFA:
                pff_type = PFF_ALTERNATE;
                r_ops = &link_state_ops;
                break;
        case ROUTING_LINK_STATE_ECMP:
                pff_type=PFF_MULTIPATH;
                r_ops = &link_state_ops;
                break;
        default:
                return -ENOTSUP;
        }

        if (r_ops->init(pr))
                return -1;

        return pff_type;
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
