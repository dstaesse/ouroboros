/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Address authority
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "addr_auth"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>

#include "addr_auth.h"
#include "pol/flat.h"

#include <stdlib.h>
#include <assert.h>

struct addr_auth * addr_auth_create(enum pol_addr_auth type)
{
        struct addr_auth * tmp;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL) {
                LOG_ERR("Failed to malloc addr auth.");
                return NULL;
        }

        switch (type) {
        case FLAT_RANDOM:
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
                break;
        default:
                LOG_ERR("Unknown address authority type.");
        }

        free(instance);

        return 0;
}
