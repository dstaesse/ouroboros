/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Flow and Retransmission control component
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

#define OUROBOROS_PREFIX "flow-rtx-control"

#include <ouroboros/logs.h>

#include "frct.h"

struct frct_i {

};

int frct_init(struct dt_const * dt_const)
{
        LOG_MISSING;

        return 0;
}

int frct_fini()
{
        LOG_MISSING;

        return 0;
}

struct frct_i * frct_i_create(int port_id,
                              enum qos_cube cube)
{
        LOG_MISSING;

        return NULL;
}

int frct_i_destroy(struct frct_i * instance)
{
        LOG_MISSING;

        return -1;
}

int frct_dt_flow(int fd)
{
        LOG_MISSING;

        return -1;
}
