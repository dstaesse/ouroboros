/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API to consult the DIF Allocator
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

#ifndef OUROBOROS_DA_H
#define OUROBOROS_DA_H

#include "common.h"
#include "rina_name.h"

rina_name_t * da_resolve_daf(char * daf_name);
/*
 * n_1_difs is an out parameter
 * The amount of n_1_difs is returned
 */
ssize_t       da_resolve_dap(rina_name_t * name,
                             char ** n_1_difs);

#endif
