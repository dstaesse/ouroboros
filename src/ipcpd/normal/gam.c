/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 *  Data transfer graph adjacency manager
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200112L

#define OUROBOROS_PREFIX "dt-gam"

#include <ouroboros/cdap.h>
#include <ouroboros/dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/list.h>
#include <ouroboros/errno.h>
#include <ouroboros/rib.h>

#include "ipcp.h"
#include "gam.h"
#include "pol-gam-ops.h"
#include "pol/complete.h"

#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

struct gam {
        struct pol_gam_ops * ops;
        void *               ops_o;
};

struct gam * gam_create(enum pol_gam gam_type,
                        struct nbs * nbs,
                        struct ae *  ae)
{
        struct gam * gam;

        gam = malloc(sizeof(*gam));
        if (gam == NULL)
                return NULL;

        switch (gam_type) {
        case COMPLETE:
                gam->ops = &complete_ops;
                break;
        default:
                log_err("Unknown gam policy: %d.", gam_type);
                return NULL;
        }

        gam->ops_o = gam->ops->create(nbs, ae);
        if (gam->ops_o == NULL) {
                free(gam);
                return NULL;
        }

        return gam;
}

void gam_destroy(struct gam * gam)
{
        assert(gam);

        gam->ops->destroy(gam->ops_o);
        free(gam);
}
