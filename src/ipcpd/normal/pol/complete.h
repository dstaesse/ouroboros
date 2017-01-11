/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Graph adjacency manager for IPC Process components
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#include "gam.h"
#include "pol-gam-ops.h"

void * complete_create(struct gam * instance);

void   complete_destroy(void * o);

int    complete_accept_new_flow(void * o);

int    complete_accept_flow(void *                    o,
                            qosspec_t                 qs,
                            const struct cacep_info * info);

struct pol_gam_ops complete_ops = {
        .create          = complete_create,
        .destroy         = complete_destroy,
        .accept_new_flow = complete_accept_new_flow,
        .accept_flow     = complete_accept_flow
};

#endif /* OUROBOROS_IPCPD_NORMAL_POL_COMPLETE_H */
