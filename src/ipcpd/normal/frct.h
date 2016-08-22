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
#include <ouroboros/common.h>

#include "dt_const.h"

struct frct_i;

int             frct_init(struct dt_const * dtc,
                          uint32_t address);
int             frct_fini();

int             frct_dt_flow(int fd,
                             enum qos_cube qos);
/*
 * FIXME: Will take the index in the DU map,
 * possibly cep-ids and address
 */
int             frct_rmt_post();

struct frct_i * frct_i_create(uint32_t      address,
                              buffer_t *    buf,
                              enum qos_cube cube);
/* FIXME: Hand QoS cube here too? We received it in the flow alloc message. */
int             frct_i_accept(struct frct_i * instance,
                              buffer_t *      buf);
int             frct_i_destroy(struct frct_i * instance,
                               buffer_t *      buf);

/* FIXME: Add read/write ops for frct instances */

#endif
