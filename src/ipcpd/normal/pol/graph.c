/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Undirected graph structure
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

#define OUROBOROS_PREFIX "graph"

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

        return edge;
}

static void del_edge(struct edge * edge)
{
       list_del(&edge->next);
       free(edge);
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

        /* Keep them ordered on address. */
        list_for_each(p, &graph->vertices) {
                struct vertex * v = list_entry(p, struct vertex, next);
                if (v->addr > addr)
                        break;
        }

        list_add_tail(&vertex->next, p);

        graph->nr_vertices++;

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
        struct edge *   nb_e;

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
                                del_vertex(graph, nb);
                        pthread_mutex_unlock(&graph->lock);
                        log_err("Failed to add edge.");
                        return -ENOMEM;
                }
        }

        e->qs = qs;

        nb_e = find_edge_by_addr(nb, s_addr);
        if (nb_e == NULL) {
                nb_e = add_edge(nb, v);
                if (nb_e == NULL) {
                        del_edge(e);
                        if (list_is_empty(&v->edges))
                                del_vertex(graph, v);
                        if (list_is_empty(&nb->edges))
                                del_vertex(graph, nb);
                        pthread_mutex_unlock(&graph->lock);
                        log_err("Failed to add edge.");
                        return -ENOMEM;
                }
        }

        nb_e->qs = qs;

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
        struct edge *   nb_e;

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

        nb_e = find_edge_by_addr(nb, s_addr);
        if (nb_e == NULL) {
                pthread_mutex_unlock(&graph->lock);
                log_err("No such edge.");
                return -1;
        }

        del_edge(e);
        del_edge(nb_e);

        /* Removing vertex if it was the last edge */
        if (list_is_empty(&v->edges))
                del_vertex(graph, v);
        if (list_is_empty(&nb->edges))
                del_vertex(graph, nb);

        pthread_mutex_unlock(&graph->lock);

        return 0;
}

static int get_min_vertex(struct graph *   graph,
                          int *            dist,
                          bool *           used,
                          struct vertex ** v)
{
        int                min = INT_MAX;
        int                index = -1;
        int                i = 0;
        struct list_head * p = NULL;

        *v = NULL;

        list_for_each(p, &graph->vertices) {
                if (used[i] == true) {
                        i++;
                        continue;
                }

                if (dist[i] < min) {
                        min = dist[i];
                        index = i;
                        *v = list_entry(p, struct vertex, next);
                }

                i++;
        }

        if (index != -1)
                used[index] = true;

        return index;
}

static int get_vertex_number(struct graph *  graph,
                             struct vertex * v)

{
        int                i = 0;
        struct list_head * p = NULL;

        list_for_each(p, &graph->vertices) {
                struct vertex * vertex = list_entry(p, struct vertex, next);
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
        bool               used[graph->nr_vertices];
        struct list_head * p = NULL;
        int                i = 0;
        int                j = 0;
        struct vertex *    v = NULL;
        struct edge *      e = NULL;
        int                alt;
        struct vertex **   nhop;

        nhop = malloc(sizeof(*nhop) * graph->nr_vertices);
        if (nhop == NULL)
                return NULL;

        /* Init the data structures */
        list_for_each(p, &graph->vertices) {
                v = list_entry(p, struct vertex, next);
                if (v->addr == src)
                        dist[i] = 0;
                else
                        dist[i] = INT_MAX;

                nhop[i] = NULL;
                used[i] = false;
                i++;
        }

        /* Perform actual Dijkstra */
        i = get_min_vertex(graph, dist, used, &v);
        while (v != NULL) {
                list_for_each(p, &v->edges) {
                        e = list_entry(p, struct edge, next);

                        j = get_vertex_number(graph, e->nb);
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
                                if (v->addr == src)
                                        nhop[j] = e->nb;
                                else
                                        nhop[j] = nhop[i];
                        }
                }
                i = get_min_vertex(graph, dist, used, &v);
        }

        return nhop;
}

static void free_routing_table(struct list_head * table)
{
        struct list_head * h;
        struct list_head * p;
        struct list_head * q;
        struct list_head * i;

        list_for_each_safe(p, h, table) {
                struct routing_table * t =
                        list_entry(p, struct routing_table, next);
                list_for_each_safe(q, i, &t->nhops) {
                        struct nhop * n =
                                list_entry(q, struct nhop, next);
                        list_del(&n->next);
                        free(n);
                }
                list_del(&t->next);
                free(t);
        }
}

void graph_free_routing_table(struct graph *     graph,
                              struct list_head * table)
{
        assert(table);

        pthread_mutex_lock(&graph->lock);

        free_routing_table(table);

        pthread_mutex_unlock(&graph->lock);
}

int graph_routing_table(struct graph *     graph,
                        uint64_t           s_addr,
                        struct list_head * table)
{
        struct vertex **       nhops;
        struct list_head *     p;
        int                    i = 0;
        struct vertex *        v;
        struct routing_table * t;
        struct nhop *          n;

        pthread_mutex_lock(&graph->lock);

        /* We need at least 2 vertices for a table */
        if (graph->nr_vertices < 2)
                goto fail_vertices;

        nhops = dijkstra(graph, s_addr);
        if (nhops == NULL)
                goto fail_vertices;

        list_head_init(table);

        /*
         * Now loop through the list of predecessors
         * to construct the routing table
         */
        list_for_each(p, &graph->vertices) {
                v = list_entry(p, struct vertex, next);

                /* This is the src */
                if (nhops[i] == NULL) {
                        i++;
                        continue;
                }

                t = malloc(sizeof(*t));
                if (t == NULL)
                        goto fail_t;

                list_head_init(&t->nhops);

                n = malloc(sizeof(*n));
                if (n == NULL)
                        goto fail_n;

                t->dst = v->addr;
                n->nhop =  nhops[i]->addr;

                list_add(&n->next, &t->nhops);
                list_add(&t->next, table);

                i++;
        }

        pthread_mutex_unlock(&graph->lock);

        free(nhops);

        return 0;

 fail_n:
        free(t);
 fail_t:
        free_routing_table(table);
        free(nhops);
 fail_vertices:
        pthread_mutex_unlock(&graph->lock);
        return -1;
}
