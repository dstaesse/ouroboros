/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Sets up a complete graph
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#ifndef OUROBOROS_IPCPD_NORMAL_POL_COMPLETE_H
#define OUROBOROS_IPCPD_NORMAL_POL_COMPLETE_H

#include <ouroboros/ipcp.h>
#include <ouroboros/qos.h>

#include "pol-gam-ops.h"

void * complete_create(struct nbs * nbs,
                       struct ae *  ae);

void   complete_destroy(void * ops_o);

struct pol_gam_ops complete_ops = {
        .create   = complete_create,
        .destroy  = complete_destroy
};

#endif /* OUROBOROS_IPCPD_NORMAL_POL_COMPLETE_H */
