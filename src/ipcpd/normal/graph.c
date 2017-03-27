/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Graph structure
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

#define OUROBOROS_PREFIX "graph"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>

#include "graph.h"
#include "ipcp.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <limits.h>

struct edge {
        struct list_head next;
        struct vertex *  nb;
        qosspec_t        qs;
};

struct vertex {
        struct list_head next;
        uint64_t         addr;
        struct list_head edges;
};

struct graph {
        size_t           nr_vertices;
        struct list_head vertices;
        pthread_mutex_t  lock;
};

static struct edge * find_edge_by_addr(struct vertex * vertex,
                                       uint64_t        dst_addr)
{
        struct list_head * p = NULL;

        list_for_each(p, &vertex->edges) {
                struct edge * e = list_entry(p, struct edge, next);
                if (e->nb->addr == dst_addr)
                        return e;
        }

        return NULL;
}

static struct vertex * find_vertex_by_addr(struct graph * graph,
                                           uint64_t       addr)
{
        struct list_head * p = NULL;

        list_for_each(p, &graph->vertices) {
                struct vertex * e = list_entry(p, struct vertex, next);
                if (e->addr == addr)
                        return e;
        }

        return NULL;
}

static struct edge * add_edge(struct vertex * vertex,
                              struct vertex * nb)
{
        struct edge * edge;

        edge = malloc(sizeof(*edge));
        if (edge == NULL)
                return NULL;

        list_head_init(&edge->next);
        edge->nb = nb;

        list_add(&edge->next, &vertex->edges);

        log_dbg("Added a new edge to the graph.");

        return edge;
}

static void del_edge(struct edge * edge)
{
       list_del(&edge->next);
       free(edge);

       log_dbg("Removed an edge of the graph.");
}

static struct vertex * add_vertex(struct graph * graph,
                                  uint64_t       addr)
{
        struct vertex *    vertex;
        struct list_head * p;

        vertex = malloc(sizeof(*vertex));
        if (vertex == NULL)
                return NULL;

        list_head_init(&vertex->next);
        list_head_init(&vertex->edges);
        vertex->addr = addr;

        list_for_each(p, &graph->vertices) {
                struct vertex * v = list_entry(p, struct vertex, next);
                if (v->addr > addr)
                        break;
        }

        list_add_tail(&vertex->next, p);

        graph->nr_vertices++;

        log_dbg("Added new vertex.");

        return vertex;
}

static void del_vertex(struct graph * graph,
                       struct vertex * vertex)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        list_del(&vertex->next);

        list_for_each_safe(p, n, &vertex->edges) {
                struct edge * e = list_entry(p, struct edge, next);
                del_edge(e);
        }

        free(vertex);

        log_dbg("Removed a vertex from the graph.");

        graph->nr_vertices--;
}

struct graph * graph_create(void)
{
        struct graph * graph;

        graph = malloc(sizeof(*graph));
        if (graph == NULL)
                return NULL;

        if (pthread_mutex_init(&graph->lock, NULL)) {
                free(graph);
                return NULL;
        }

        graph->nr_vertices = 0;
        list_head_init(&graph->vertices);

        return graph;
}

void graph_destroy(struct graph * graph)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        assert(graph);

        pthread_mutex_lock(&graph->lock);

        list_for_each_safe(p, n, &graph->vertices) {
                struct vertex * e = list_entry(p, struct vertex, next);
                del_vertex(graph, e);
        }

        pthread_mutex_unlock(&graph->lock);

        pthread_mutex_destroy(&graph->lock);

        free(graph);
}

int graph_update_edge(struct graph * graph,
                      uint64_t       s_addr,
                      uint64_t       d_addr,
                      qosspec_t      qs)
{
        struct vertex * v;
        struct edge *   e;
        struct vertex * nb;

        assert(graph);

        pthread_mutex_lock(&graph->lock);

        v = find_vertex_by_addr(graph, s_addr);
        if (v == NULL) {
                v = add_vertex(graph, s_addr);
                if (v == NULL) {
                        pthread_mutex_unlock(&graph->lock);
                        log_err("Failed to add vertex.");
                        return -ENOMEM;
                }
        }

        nb = find_vertex_by_addr(graph, d_addr);
        if (nb == NULL) {
                nb = add_vertex(graph, d_addr);
                if (nb == NULL) {
                        if (list_is_empty(&v->edges))
                                del_vertex(graph, v);
                        pthread_mutex_unlock(&graph->lock);
                        log_err("Failed to add vertex.");
                        return -ENOMEM;
                }
        }

        e = find_edge_by_addr(v, d_addr);
        if (e == NULL) {
                e = add_edge(v, nb);
                if (e == NULL) {
                        if (list_is_empty(&v->edges))
                                del_vertex(graph, v);
                        if (list_is_empty(&nb->edges))
                                del_vertex(graph, v);
                        pthread_mutex_unlock(&graph->lock);
                        log_err("Failed to add edge.");
                        return -ENOMEM;
                }
        }

        e->qs = qs;

        pthread_mutex_unlock(&graph->lock);

        return 0;
}

int graph_del_edge(struct graph * graph,
                   uint64_t       s_addr,
                   uint64_t       d_addr)
{
        struct vertex * v;
        struct edge *   e;
        struct vertex * nb;

        assert(graph);

        pthread_mutex_lock(&graph->lock);

        v = find_vertex_by_addr(graph, s_addr);
        if (v == NULL) {
                pthread_mutex_unlock(&graph->lock);
                log_err("No such vertex.");
                return -1;
        }

        nb = find_vertex_by_addr(graph, d_addr);
        if (nb == NULL) {
                pthread_mutex_unlock(&graph->lock);
                log_err("No such vertex.");
                return -1;
        }

        e = find_edge_by_addr(v, d_addr);
        if (e == NULL) {
                pthread_mutex_unlock(&graph->lock);
                log_err("No such edge.");
                return -1;
        }

        del_edge(e);

        /* Removing vertex if it was the last edge */
        if (list_is_empty(&v->edges))
               del_vertex(graph, v);

        if (list_is_empty(&nb->edges))
               del_vertex(graph, v);

        pthread_mutex_unlock(&graph->lock);

        return 0;
}

static int get_min_vertex(struct vertex ** vertices,
                          int              nr_vertices,
                          int *            dist,
                          struct vertex ** v)
{
        int min = INT_MAX;
        int index = -1;
        int i;

        *v = NULL;

        for (i = 0; i < nr_vertices; i++) {
                if (vertices[i] == NULL)
                        continue;

                if (dist[i] < min) {
                        *v = vertices[i];
                        min = dist[i];
                        index = i;
                }
        }

        if (index != -1)
                vertices[index] = NULL;

        return index;
}

static int get_vertex_number(struct vertex ** vertices,
                             int              nr_vertices,
                             struct vertex *  v)

{
        int i;

        for (i = 0; i < nr_vertices; i++) {
                if (vertices[i] == v)
                        return i;
        }

        return -1;
}

static int get_vertex_index(struct graph *  graph,
                            struct vertex * v)

{
        struct list_head * p = NULL;
        struct vertex *    vertex;
        int                i = 0;

        list_for_each(p, &graph->vertices) {
                vertex = list_entry(p, struct vertex, next);
                if (vertex == v)
                        return i;
                i++;
        }

        return -1;
}

static struct vertex ** dijkstra(struct graph * graph,
                                 uint64_t       src)
{
        int                dist[graph->nr_vertices];
        struct vertex *    vertices[graph->nr_vertices];
        struct list_head * p = NULL;
        int                i = 0;
        int                j = 0;
        struct vertex *    v = NULL;
        struct edge *      e = NULL;
        int                alt;
        struct vertex **   prev;

        prev = malloc(sizeof(*prev) * graph->nr_vertices);
        if (prev == NULL)
                return NULL;

        /* Init the data structures */
        list_for_each(p, &graph->vertices) {
                v = list_entry(p, struct vertex, next);
                vertices[i] = v;
                if (v->addr == src)
                        dist[i] = 0;
                else
                        dist[i] = INT_MAX;
                prev[i] = NULL;
                i++;
        }

        /* Perform actual Dijkstra */
        i = get_min_vertex(vertices, graph->nr_vertices, dist, &v);
        while (v != NULL) {
                list_for_each(p, &v->edges) {
                        e = list_entry(p, struct edge, next);

                        j = get_vertex_number(vertices,
                                              graph->nr_vertices,
                                              e->nb);
                        if (j == -1)
                                continue;

                        /*
                         * NOTE: Current weight is just hop count.
                         * Method could be extended to use a different
                         * weight for a different QoS cube.
                         */
                        alt = dist[i] + 1;
                        if (alt < dist[j]) {
                                dist[j] = alt;
                                prev[j] = v;
                        }
                }
                i = get_min_vertex(vertices, graph->nr_vertices, dist, &v);
        }

        return prev;
}

ssize_t graph_routing_table(struct graph *           graph,
                            uint64_t                 s_addr,
                            struct routing_table *** table)
{
        struct vertex **   prevs;
        struct list_head * p = NULL;
        int                i = 0;
        int                index = 0;
        int                j = 0;
        int                k = 0;
        struct vertex *    prev;
        struct vertex *    nhop;
        struct vertex *    v;

        pthread_mutex_lock(&graph->lock);

        if (graph->nr_vertices == 0) {
                pthread_mutex_unlock(&graph->lock);
                return 0;
        }

        prevs = dijkstra(graph, s_addr);
        if (prevs == NULL) {
                pthread_mutex_unlock(&graph->lock);
                return -1;
        }

        *table = malloc(sizeof(**table) * (graph->nr_vertices - 1));
        if (*table == NULL) {
                pthread_mutex_unlock(&graph->lock);
                free(prevs);
                return -1;
        }

        /*
         * Now loop through the list of predecessors
         * to construct the routing table
         */
        list_for_each(p, &graph->vertices) {
                v = list_entry(p, struct vertex, next);
                prev = prevs[i];
                nhop = v;

                /* This is the src */
                if (prev == NULL) {
                        i++;
                        continue;
                }

                index = get_vertex_index(graph, prev);
                while (prevs[index] != NULL) {
                        nhop = prev;
                        prev = prevs[index];
                        index = get_vertex_index(graph, prev);
                }

                (*table)[++j] = malloc(sizeof(***table));
                if ((*table)[j] == NULL) {
                        pthread_mutex_unlock(&graph->lock);
                        for (k = 0; k < j; ++k)
                                free((*table)[k]);
                        free(*table);
                        free(prevs);
                        return -1;
                }

                (*table)[j]->dst = v->addr;
                (*table)[j]->nhop = nhop->addr;

                i++;
        }

        pthread_mutex_unlock(&graph->lock);

        free(prevs);

        return j;
}
