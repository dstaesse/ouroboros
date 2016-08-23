/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Relaying and Multiplexing task
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

#define OUROBOROS_PREFIX "flow-manager"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>

#include "rmt.h"

struct rmt {
};

int rmt_init(struct dt_const * dtc)
{
        LOG_MISSING;

        return -1;
}

int rmt_fini()
{
        LOG_MISSING;

        return -1;
}

int rmt_frct_post()
{
        LOG_MISSING;

        return -1;
}
