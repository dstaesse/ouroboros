/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Data transfer neighbors
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

#define OUROBOROS_PREFIX "neighbors"

#include <ouroboros/config.h>
#include <ouroboros/shared.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>

#include "neighbors.h"

#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

static void notify_listeners(enum nb_event event,
                             struct nb *   nb,
                             struct nbs *  nbs)
{
        struct list_head * p = NULL;

        list_for_each(p, &nbs->notifiers) {
                struct nb_notifier * e =
                        list_entry(p, struct nb_notifier, next);
                if (e->notify_call(event, nb->conn))
                        log_err("Listener reported an error.");
        }
}

struct nbs * nbs_create(void)
{
        struct nbs * nbs;

        nbs = malloc(sizeof(*nbs));
        if (nbs == NULL)
                return NULL;

        list_head_init(&nbs->list);
        list_head_init(&nbs->notifiers);

        if (pthread_mutex_init(&nbs->list_lock, NULL))
                return NULL;

        if (pthread_mutex_init(&nbs->notifiers_lock, NULL)) {
                pthread_mutex_destroy(&nbs->list_lock);
                return NULL;
        }

        return nbs;
}

void nbs_destroy(struct nbs * nbs)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        assert(nbs);

        pthread_mutex_lock(&nbs->list_lock);

        list_for_each_safe(p, n, &nbs->list) {
                struct nb * e = list_entry(p, struct nb, next);
                list_del(&e->next);
                free(e);
        }

        pthread_mutex_unlock(&nbs->list_lock);

        pthread_mutex_destroy(&nbs->list_lock);
        pthread_mutex_destroy(&nbs->notifiers_lock);
}

int nbs_add(struct nbs * nbs,
            struct conn  conn)
{
        struct nb * nb;

        assert(nbs);

        nb = malloc(sizeof(*nb));
        if (nb == NULL)
                return -ENOMEM;

        nb->conn = conn;

        list_head_init(&nb->next);

        pthread_mutex_lock(&nbs->list_lock);

        list_add(&nb->next, &nbs->list);

        notify_listeners(NEIGHBOR_ADDED, nb, nbs);

        pthread_mutex_unlock(&nbs->list_lock);

        log_info("Added neighbor with address %" PRIu64 " to list.",
                 conn.conn_info.addr);

        return 0;
}

int nbs_update_qos(struct nbs * nbs,
                   int          fd,
                   qosspec_t    qs)
{
        struct list_head * p = NULL;

        assert(nbs);

        pthread_mutex_lock(&nbs->list_lock);

        list_for_each(p, &nbs->list) {
                struct nb * e = list_entry(p, struct nb, next);
                if (e->conn.flow_info.fd == fd) {
                        e->conn.flow_info.qs = qs;

                        notify_listeners(NEIGHBOR_QOS_CHANGE, e, nbs);

                        pthread_mutex_unlock(&nbs->list_lock);
                        return 0;
                }
        }

        pthread_mutex_unlock(&nbs->list_lock);

        return -1;
}

int nbs_del(struct nbs * nbs,
            int          fd)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        assert(nbs);

        pthread_mutex_lock(&nbs->list_lock);

        list_for_each_safe(p, n, &nbs->list) {
                struct nb * e = list_entry(p, struct nb, next);
                if (e->conn.flow_info.fd == fd) {
                        notify_listeners(NEIGHBOR_REMOVED, e, nbs);
                        list_del(&e->next);
                        free(e);
                        pthread_mutex_unlock(&nbs->list_lock);
                        return 0;
                }
        }

        pthread_mutex_unlock(&nbs->list_lock);

        return -1;
}

int nbs_reg_notifier(struct nbs *         nbs,
                     struct nb_notifier * notify)
{
        assert(nbs);
        assert(notify);

        pthread_mutex_lock(&nbs->notifiers_lock);

        list_head_init(&notify->next);
        list_add(&notify->next, &nbs->notifiers);

        pthread_mutex_unlock(&nbs->notifiers_lock);

        return 0;
}

int nbs_unreg_notifier(struct nbs *         nbs,
                       struct nb_notifier * notify)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        pthread_mutex_lock(&nbs->notifiers_lock);

        list_for_each_safe(p, n, &nbs->notifiers) {
                struct nb_notifier * e =
                        list_entry(p, struct nb_notifier, next);
                if (e == notify) {
                        list_del(&e->next);
                        pthread_mutex_unlock(&nbs->notifiers_lock);
                        return 0;
                }
        }

        pthread_mutex_unlock(&nbs->notifiers_lock);

        return -1;
}
