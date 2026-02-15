/*
 * Ouroboros - Copyright (C) 2016 - 2026
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
#include "routing/pol.h"

struct routing_ops * r_ops;

int routing_init(struct routing_config * conf,
                 enum pol_pff *          pff_type)
{
        void * cfg;

        switch (conf->pol) {
        case ROUTING_LINK_STATE:
                r_ops = &link_state_ops;
                cfg = &conf->ls;
                break;
        default:
                return -ENOTSUP;
        }

        return r_ops->init(cfg, pff_type);
}

int routing_start(void)
{
        return r_ops->start();
}

struct routing_i * routing_i_create(struct pff * pff)
{
        return r_ops->routing_i_create(pff);
}

void routing_i_destroy(struct routing_i * instance)
{
        return r_ops->routing_i_destroy(instance);
}

void routing_stop(void)
{
        r_ops->stop();
}

void routing_fini(void)
{
        r_ops->fini();
}
