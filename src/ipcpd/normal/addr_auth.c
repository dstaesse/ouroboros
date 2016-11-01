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

#define OUROBOROS_PREFIX "addr_auth"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>

#include "addr_auth.h"
#include "flat.h"

#include <stdlib.h>
#include <assert.h>

struct addr_auth * addr_auth_create(enum pol_addr_auth type)
{
        struct addr_auth * tmp;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        switch (type) {
        case FLAT_RANDOM:
                if (flat_init()) {
                        free(tmp);
                        return NULL;
                }

                tmp->address = flat_address;
                tmp->type = type;
                break;
        default:
                LOG_ERR("Unknown address authority type.");
                free(tmp);
                return NULL;
        }

        return tmp;
}

int addr_auth_destroy(struct addr_auth * instance)
{
        assert(instance);

        switch (instance->type) {
        case FLAT_RANDOM:
                if (flat_fini()) {
                        return -1;
                }
                break;
        default:
                LOG_ERR("Unknown address authority type.");
        }

        free(instance);

        return 0;
}
