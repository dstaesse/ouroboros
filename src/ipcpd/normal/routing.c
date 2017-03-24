/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Routing component of the IPCP
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

#define OUROBOROS_PREFIX "routing"

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>
#include <ouroboros/rib.h>
#include <ouroboros/rqueue.h>
#include <ouroboros/utils.h>

#include "routing.h"
#include "ribmgr.h"
#include "ribconfig.h"
#include "ipcp.h"
#include "graph.h"
#include "neighbors.h"

#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "fso.pb-c.h"
typedef Fso fso_t;

#define BUF_SIZE 256
#define RECALC_TIME 4

struct routing_i {
        struct pff * pff;
        pthread_t    calculator;
};

struct {
        struct nbs *       nbs;
        struct nb_notifier nb_notifier;

        struct graph *     graph;

        ro_set_t *         set;
        rqueue_t *         queue;
        pthread_t          rib_listener;
} routing;

/* Take under neighbors lock */
static int addr_to_fd(uint64_t addr)
{
        struct list_head * p = NULL;

        list_for_each(p, &routing.nbs->list) {
                struct nb * e = list_entry(p, struct nb, next);
                if (e->conn.conn_info.addr == addr)
                        return e->conn.flow_info.fd;
        }

        return -1;
}

static void * calculate_pff(void * o)
{
        struct routing_i *      instance;
        struct routing_table ** table;
        ssize_t                 n_table;
        int                     i;
        int                     fd;

        instance = (struct routing_i *) o;

        while (true) {
                table = NULL;
                n_table = graph_routing_table(routing.graph,
                                              ipcpi.dt_addr, &table);
                if (table == NULL) {
                        sleep(RECALC_TIME);
                        continue;
                }

                pthread_mutex_lock(&routing.nbs->list_lock);
                pff_lock(instance->pff);

                pff_flush(instance->pff);

                for (i = 0; i < n_table; i++) {
                        fd = addr_to_fd(table[i]->nhop);
                        if (fd == -1)
                                continue;

                        pff_add(instance->pff, table[i]->dst, fd);
                }

                pff_unlock(instance->pff);
                pthread_mutex_unlock(&routing.nbs->list_lock);

                freepp(struct routing_table, table, n_table);
                sleep(RECALC_TIME);
        }

        return (void *) 0;
}

struct routing_i * routing_i_create(struct pff * pff)
{
        struct routing_i * tmp;

        assert(pff);

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        tmp->pff = pff;

        pthread_create(&tmp->calculator, NULL, calculate_pff, (void *) tmp);

        return tmp;
}

void routing_i_destroy(struct routing_i * instance)
{
        assert(instance);

        pthread_cancel(instance->calculator);

        pthread_join(instance->calculator, NULL);

        free(instance);
}

static int routing_neighbor_event(enum nb_event event,
                                  struct conn   conn)
{
        char      path[RIB_MAX_PATH_LEN + 1];
        char      fso_name[RIB_MAX_PATH_LEN + 1];
        fso_t     fso = FSO__INIT;
        size_t    len;
        uint8_t * data;

        path[0] = '\0';
        sprintf(fso_name, "%" PRIu64 "-%" PRIu64,
                ipcpi.dt_addr, conn.conn_info.addr);
        rib_path_append(rib_path_append(path, ROUTING_NAME), fso_name);

        switch (event) {
        case NEIGHBOR_ADDED:
                fso.s_addr = ipcpi.dt_addr;
                fso.d_addr = conn.conn_info.addr;

                len = fso__get_packed_size(&fso);
                if (len == 0)
                        return -1;

                data = malloc(len);
                if (data == NULL)
                        return -1;

                fso__pack(&fso, data);

                if (rib_add(ROUTING_PATH, fso_name)) {
                        log_err("Failed to add FSO.");
                        free(data);
                        return -1;
                }

                if (rib_put(path, data, len)) {
                        log_err("Failed to put FSO in RIB.");
                        rib_del(path);
                        free(data);
                        return -1;
                }

                log_dbg("Added %s to RIB.", path);

                break;
        case NEIGHBOR_REMOVED:
                if (rib_del(path)) {
                        log_err("Failed to remove FSO.");
                        return -1;
                }

                log_dbg("Removed %s from RIB.", path);

                break;
        case NEIGHBOR_QOS_CHANGE:
                log_info("Not currently supported.");
                break;
        default:
                log_info("Unsupported event for routing.");
                break;
        }

        return 0;
}

static int read_fso(char *  path,
                    int32_t flag)
{
        ssize_t   len;
        uint8_t   ro[BUF_SIZE];
        fso_t *   fso;
        qosspec_t qs;

        memset(&qs, 0, sizeof(qs));

        len = rib_read(path, ro, BUF_SIZE);
        if (len < 0) {
                log_err("Failed to read FSO.");
                return -1;
        }

        fso = fso__unpack(NULL, len, ro);
        if (fso == NULL) {
                log_err("Failed to unpack.");
                return -1;
        }

        if (flag & RO_CREATE) {
                if (graph_add_edge(routing.graph,
                                   fso->s_addr, fso->d_addr, qs)) {
                        log_err("Failed to add edge to graph.");
                        fso__free_unpacked(fso, NULL);
                        return -1;
                }
        } else if (flag & RO_MODIFY) {
                if (graph_update_edge(routing.graph,
                                      fso->s_addr, fso->d_addr, qs)) {
                        log_err("Failed to update edge of graph.");
                        fso__free_unpacked(fso, NULL);
                        return -1;
                }
        } else if (flag & RO_DELETE) {
                if (graph_del_edge(routing.graph, fso->s_addr, fso->d_addr)) {
                        log_err("Failed to del edge of graph.");
                        fso__free_unpacked(fso, NULL);
                        return -1;
                }
        }

        fso__free_unpacked(fso, NULL);

        return 0;
}

static void * rib_listener(void * o)
{
        int32_t flag;
        char    path[RIB_MAX_PATH_LEN + 1];
        char ** children;
        ssize_t len;
        int     i;

        (void) o;

        if (ro_set_add(routing.set, ROUTING_PATH,
                       RO_MODIFY | RO_CREATE | RO_DELETE)) {
                log_err("Failed to add to RO set");
                return (void * ) -1;
        }

        len = rib_children(ROUTING_PATH, &children);
        if (len < 0) {
                log_err("Failed to retrieve children.");
                return (void *) -1;
        }

        for (i = 0; i < len; i++) {
                if (read_fso(children[i], RO_CREATE)) {
                        log_err("Failed to parse FSO.");
                        continue;
                }
        }

        while (rib_event_wait(routing.set, routing.queue, NULL)) {
                flag = rqueue_next(routing.queue, path);
                if (flag < 0)
                        continue;

                if (read_fso(children[i], flag)) {
                        log_err("Failed to parse FSO.");
                        continue;
                }
        }

        return (void *) 0;
}

int routing_init(struct nbs * nbs)
{
        routing.graph = graph_create();
        if (routing.graph == NULL)
                return -1;

        if (rib_add(RIB_ROOT, ROUTING_NAME)) {
                graph_destroy(routing.graph);
                return -1;
        }

        routing.nbs = nbs;

        routing.nb_notifier.notify_call = routing_neighbor_event;
        if (nbs_reg_notifier(routing.nbs, &routing.nb_notifier)) {
                graph_destroy(routing.graph);
                rib_del(ROUTING_PATH);
                return -1;
        }

        routing.set = ro_set_create();
        if (routing.set == NULL) {
                nbs_unreg_notifier(routing.nbs, &routing.nb_notifier);
                graph_destroy(routing.graph);
                rib_del(ROUTING_PATH);
                return -1;
        }

        routing.queue = rqueue_create();
        if (routing.queue == NULL) {
                ro_set_destroy(routing.set);
                nbs_unreg_notifier(routing.nbs, &routing.nb_notifier);
                graph_destroy(routing.graph);
                rib_del(ROUTING_PATH);
                return -1;
        }

        pthread_create(&routing.rib_listener, NULL, rib_listener, NULL);

        return 0;
}

void routing_fini(void)
{
        pthread_cancel(routing.rib_listener);

        pthread_join(routing.rib_listener, NULL);

        rqueue_destroy(routing.queue);

        ro_set_destroy(routing.set);

        graph_destroy(routing.graph);

        rib_del(ROUTING_PATH);

        nbs_unreg_notifier(routing.nbs, &routing.nb_notifier);
}
