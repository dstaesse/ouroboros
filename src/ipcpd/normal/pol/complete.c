/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Sets up a complete graph
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

#define OUROBOROS_PREFIX "complete"

#include <ouroboros/config.h>
#include <ouroboros/shared.h>
#include <ouroboros/rib.h>
#include <ouroboros/dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/cacep.h>

#include "neighbors.h"
#include "frct.h"
#include "ribconfig.h"
#include "ipcp.h"
#include "ae.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

struct complete {
        struct nbs * nbs;
        struct ae *  ae;
        pthread_t    allocator;
        pthread_t    listener;
};

static void * listener(void * o)
{
        struct complete * complete;
        struct conn       conn;

        complete = (struct complete *) o;

        while (true) {
                if (connmgr_wait(complete->ae, &conn)) {
                        log_err("Error while getting next connection.");
                        continue;
                }

                if (nbs_add(complete->nbs, conn)) {
                        log_err("Failed to add neighbor.");
                        continue;
                }
        }

        return (void *) 0;
}

static void * allocator(void * o)
{
        qosspec_t         qs;
        ssize_t           len;
        char **           children;
        ssize_t           i;
        struct complete * complete;
        struct conn       conn;

        complete = (struct complete *) o;

        qs.delay = 0;
        qs.jitter = 0;

        /* FIXME: subscribe to members to keep the graph complete. */
        len = rib_children("/" MEMBERS_NAME, &children);
        for (i = 0; i < len; ++i) {
                if (strcmp(children[i], ipcpi.name) < 0) {
                        if (connmgr_alloc(complete->ae,
                                          children[i],
                                          &qs,
                                          &conn)) {
                                log_warn("Failed to get a conn to neighbor.");
                                free(children[i]);
                                continue;
                        }

                        if (nbs_add(complete->nbs, conn)) {
                                log_err("Failed to add neighbor.");
                                free(children[i]);
                                continue;
                        }

                }
                free(children[i]);
        }

        if (len > 0)
                free(children);

        return (void *) 0;
}

void * complete_create(struct nbs * nbs,
                       struct ae *  ae)
{
        struct complete * complete;

        complete = malloc(sizeof(*complete));
        if (complete == NULL)
                return NULL;

        complete->nbs = nbs;
        complete->ae = ae;

        if (pthread_create(&complete->allocator, NULL,
                           allocator, (void *) complete))
                return NULL;

        if (pthread_create(&complete->listener, NULL,
                           listener, (void *) complete))
                return NULL;

        return complete;
}

void complete_destroy(void * ops_o)
{
        struct complete * complete;

        assert(ops_o);

        complete = (struct complete *) ops_o;

        pthread_cancel(complete->allocator);
        pthread_cancel(complete->listener);
        pthread_join(complete->allocator, NULL);
        pthread_join(complete->listener, NULL);

        free(complete);
}
