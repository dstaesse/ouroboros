/*
 * Ouroboros - Copyright (C) 2016
 *
 * A select call for flows
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#ifndef OUROBOROS_SELECT_H
#define OUROBOROS_SELECT_H

#include <stdbool.h>
#include <time.h>

struct flow_set;

struct flow_set * flow_set_create();

void              flow_set_destroy(struct flow_set * set);

void              flow_set_zero(struct flow_set * set);

void              flow_set_add(struct flow_set * set,
                               int               fd);

void              flow_set_del(struct flow_set * set,
                               int               fd);

bool              flow_set_has(struct flow_set * set,
                               int               fd);

int               flow_select(struct flow_set *       set,
                              const struct timespec * timeout);

#endif /* OUROBOROS_SELECT_H */
