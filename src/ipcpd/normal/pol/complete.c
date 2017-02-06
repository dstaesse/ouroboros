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

#define OUROBOROS_PREFIX "complete-graph-adjacency-manager"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/list.h>
#include <ouroboros/qos.h>
#include <ouroboros/rib.h>

#include "ipcp.h"
#include "gam.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

struct neighbor {
        struct list_head next;
        char *           neighbor;
};

struct complete {
        struct list_head neighbors;
        pthread_mutex_t  neighbors_lock;

        pthread_t        allocator;

        struct gam *     gam;
};

static void * allocator(void * o)
{
        qosspec_t         qs;
        ssize_t           len;
        char **           children;
        ssize_t           i;
        struct complete * complete = (struct complete *) o;

        assert(complete);
        assert(complete->gam);

        qs.delay = 0;
        qs.jitter = 0;

        /* FIXME: subscribe to members to keep the graph complete. */
        len = rib_children("/" MEMBERS_NAME, &children);
        for (i = 0; i < len; ++i) {
                if (strcmp(children[i], ipcpi.name) < 0)
                        gam_flow_alloc(complete->gam, children[i], qs);
                free(children[i]);
        }

        if (len > 0)
                free(children);

        return (void *) 0;
}

void * complete_create(struct gam * gam)
{
        struct complete * complete;

        assert(gam);

        complete = malloc(sizeof(*complete));
        if (complete == NULL)
                return NULL;

        list_head_init(&complete->neighbors);
        complete->gam = gam;

        if (pthread_mutex_init(&complete->neighbors_lock, NULL)) {
                free(complete);
                return NULL;
        }

        return (void *) complete;
}

int complete_start(void * o)
{
        struct complete * complete = (struct complete *) o;

        assert(complete);
        assert(complete->gam);

        if (pthread_create(&complete->allocator, NULL,
                           allocator, (void *) complete)) {
                pthread_mutex_destroy(&complete->neighbors_lock);
                free(complete);
                return -1;
        }

        /* FIXME: Handle flooding of the flow allocator before detaching.*/
        pthread_join(complete->allocator, NULL);

        return 0;
}

int complete_stop(void * o)
{
        (void) o;

        return 0;
}

void complete_destroy(void * o)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;
        struct complete * complete = (struct complete *) o;

        list_for_each_safe(p, n, &complete->neighbors) {
                struct neighbor * e = list_entry(p, struct neighbor, next);
                list_del(&e->next);
                free(e->neighbor);
                free(e);
        }

        pthread_mutex_destroy(&complete->neighbors_lock);

        free(complete);
}

int complete_accept_new_flow(void * o)
{
        (void) o;

        return 0;
}

int complete_accept_flow(void *                    o,
                         qosspec_t                 qs,
                         const struct cacep_info * info)
{
        struct list_head * pos = NULL;
        struct neighbor * n;
        struct complete * complete = (struct complete *) o;

        (void) qs;

        assert(complete);

        pthread_mutex_lock(&complete->neighbors_lock);

        list_for_each(pos, &complete->neighbors) {
                struct neighbor * e = list_entry(pos, struct neighbor, next);
                if (strcmp(e->neighbor, info->name) == 0) {
                        pthread_mutex_unlock(&complete->neighbors_lock);
                        return -1;
                }

                assert(complete);
                assert(&complete->neighbors_lock);
                assert(pos->nxt);
        }

        n = malloc(sizeof(*n));
        if (n == NULL) {
                pthread_mutex_unlock(&complete->neighbors_lock);
                return -1;
        }

        list_head_init(&n->next);

        n->neighbor = strdup(info->name);
        if (n->neighbor == NULL) {
                pthread_mutex_unlock(&complete->neighbors_lock);
                free(n);
                return -1;
        }

        list_add(&n->next, &complete->neighbors);

        pthread_mutex_unlock(&complete->neighbors_lock);

        return 0;
}
