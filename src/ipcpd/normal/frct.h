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

#ifndef OUROBOROS_IPCP_FRCT_H
#define OUROBOROS_IPCP_FRCT_H

#include <ouroboros/shared.h>

#include "dt_const.h"

struct frct_i;

int             frct_init(struct dt_const * dt_const);
int             frct_fini();

struct frct_i * frct_i_create(int port_id,
                              enum qos_cube cube);
int             frct_i_destroy(struct frct_i * instance);

int             frct_dt_flow(int fd);

#endif
