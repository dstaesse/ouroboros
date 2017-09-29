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
        int              announced;
};

struct vertex {
        struct list_head next;
        uint64_t         addr;
        struct list_head edges;
        int              index;
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
        edge->announced = 0;

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
        int                i = 0;

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
                i++;
        }

        vertex->index = i;

        list_add_tail(&vertex->next, p);

        /* Increase the index of the vertices to the right. */
        list_for_each(p, &graph->vertices) {
                struct vertex * v = list_entry(p, struct vertex, next);
                if (v->addr > addr)
                        v->index++;
        }

        graph->nr_vertices++;

        return vertex;
}

static void del_vertex(struct graph * graph,
                       struct vertex * vertex)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        list_del(&vertex->next);

        /* Decrease the index of the vertices to the right. */
        list_for_each(p, &graph->vertices) {
                struct vertex * v = list_entry(p, struct vertex, next);
                if (v->addr > vertex->addr)
                        v->index--;
        }

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

        e->announced++;
        e->qs = qs;

        nb_e = find_edge_by_addr(nb, s_addr);
        if (nb_e == NULL) {
                nb_e = add_edge(nb, v);
                if (nb_e == NULL) {
                        if (--e->announced == 0)
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

        nb_e->announced++;
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
                log_err("No such source vertex.");
                return -1;
        }

        nb = find_vertex_by_addr(graph, d_addr);
        if (nb == NULL) {
                pthread_mutex_unlock(&graph->lock);
                log_err("No such destination vertex.");
                return -1;
        }

        e = find_edge_by_addr(v, d_addr);
        if (e == NULL) {
                pthread_mutex_unlock(&graph->lock);
                log_err("No such source edge.");
                return -1;
        }

        nb_e = find_edge_by_addr(nb, s_addr);
        if (nb_e == NULL) {
                pthread_mutex_unlock(&graph->lock);
                log_err("No such destination edge.");
                return -1;
        }

        if (--e->announced == 0)
                del_edge(e);
        if (--nb_e->announced == 0)
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

static int dijkstra(struct graph *    graph,
                    uint64_t          src,
                    struct vertex *** nhops,
                    int **            dist)
{
        bool               used[graph->nr_vertices];
        struct list_head * p = NULL;
        int                i = 0;
        struct vertex *    v = NULL;
        struct edge *      e = NULL;
        int                alt;

        *nhops = malloc(sizeof(**nhops) * graph->nr_vertices);
        if (*nhops == NULL)
                return -1;

        *dist = malloc(sizeof(**dist) * graph->nr_vertices);
        if (*dist == NULL) {
                free(*nhops);
                return -1;
        }

        /* Init the data structures */
        list_for_each(p, &graph->vertices) {
                v = list_entry(p, struct vertex, next);
                if (v->addr == src)
                        (*dist)[i] = 0;
                else
                        (*dist)[i] = INT_MAX;

                (*nhops)[i] = NULL;
                used[i] = false;
                i++;
        }

        /* Perform actual Dijkstra */
        i = get_min_vertex(graph, *dist, used, &v);
        while (v != NULL) {
                list_for_each(p, &v->edges) {
                        e = list_entry(p, struct edge, next);

                        /* Only include it if both sides announced it. */
                        if (e->announced != 2)
                                continue;

                        /*
                         * NOTE: Current weight is just hop count.
                         * Method could be extended to use a different
                         * weight for a different QoS cube.
                         */
                        alt = (*dist)[i] + 1;
                        if (alt < (*dist)[e->nb->index]) {
                                (*dist)[e->nb->index] = alt;
                                if (v->addr == src)
                                        (*nhops)[e->nb->index] = e->nb;
                                else
                                        (*nhops)[e->nb->index] = (*nhops)[i];
                        }
                }
                i = get_min_vertex(graph, *dist, used, &v);
        }

        return 0;
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

static int graph_routing_table_simple(struct graph *     graph,
                                      uint64_t           s_addr,
                                      struct list_head * table,
                                      int **             dist)
{
        struct vertex **       nhops;
        struct list_head *     p;
        int                    i = 0;
        struct vertex *        v;
        struct routing_table * t;
        struct nhop *          n;

        /* We need at least 2 vertices for a table */
        if (graph->nr_vertices < 2)
                goto fail_vertices;

        if (dijkstra(graph, s_addr, &nhops, dist))
                goto fail_vertices;

        list_head_init(table);

        /* Now construct the routing table from the nhops. */
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
                n->nhop = nhops[i]->addr;

                list_add(&n->next, &t->nhops);
                list_add(&t->next, table);

                i++;
        }

        free(nhops);

        return 0;

 fail_n:
        free(t);
 fail_t:
        free_routing_table(table);
        free(nhops);
 fail_vertices:
        return -1;
}

int graph_routing_table(struct graph *     graph,
                        uint64_t           s_addr,
                        struct list_head * table)
{
        int   ret = 0;
        int * dist;

        assert(graph);
        assert(table);

        pthread_mutex_lock(&graph->lock);

        ret = graph_routing_table_simple(graph, s_addr, table, &dist);

        free(dist);

        pthread_mutex_unlock(&graph->lock);

        return ret;
}

static int add_lfa_to_table(struct list_head * table,
                            uint64_t           addr,
                            uint64_t           lfa)
{
        struct list_head * p = NULL;
        struct nhop *      n;

        n = malloc(sizeof(*n));
        if (n == NULL)
                return -1;

        n->nhop = lfa;

        list_for_each(p, table) {
                struct routing_table * t =
                        list_entry(p, struct routing_table, next);
                if (t->dst == addr) {
                        list_add_tail(&n->next, &t->nhops);
                        return 0;
                }
        }

        return -1;
}

int graph_routing_table_lfa(struct graph *     graph,
                            uint64_t           s_addr,
                            struct list_head * table)
{
        int *              s_dist;
        int *              n_dist[AP_MAX_FLOWS];
        uint64_t           addrs[AP_MAX_FLOWS];
        int                n_index[AP_MAX_FLOWS];
        struct list_head * p;
        struct list_head * q;
        struct vertex *    v;
        struct edge *      e;
        struct vertex **   nhops;
        int                i = 0;
        int                j = 0;
        int                k;

        assert(graph);
        assert(table);

        pthread_mutex_lock(&graph->lock);

        for (j = 0; j < AP_MAX_FLOWS; j++) {
                n_dist[i] = NULL;
                n_index[i] = -1;
                addrs[i] = -1;
        }

        /* Get the normal next hops routing table. */
        if (graph_routing_table_simple(graph, s_addr, table, &s_dist))
                goto fail_table_simple;

        list_for_each(p, &graph->vertices) {
                v = list_entry(p, struct vertex, next);

                if (v->addr != s_addr)
                        continue;

                /* Get the distances for every neighbor of the source. */
                list_for_each(q, &v->edges) {
                        e = list_entry(q, struct edge, next);

                        addrs[i] = e->nb->addr;
                        n_index[i] = e->nb->index;
                        if (dijkstra(graph, e->nb->addr,
                                     &nhops, &(n_dist[i++])))
                                goto fail_dijkstra;

                        free(nhops);
                }

                break;
        }

        /* Loop though all nodes to see if we have a LFA for them. */
        list_for_each(p, &graph->vertices) {
                v = list_entry(p, struct vertex, next);

                if (v->addr == s_addr)
                        continue;

                /*
                 * Check for every neighbor if dist(neighbor, destination) <
                 * dist(neighbor, source) + dist(source, destination).
                 */
                for (j = 0; j < i; j++) {
                        /* Exclude ourselves. */
                        if (addrs[j] == v->addr)
                                continue;

                        if (n_dist[j][v->index] <
                            s_dist[n_index[j]] + s_dist[v->index]) {
                                if (add_lfa_to_table(table, v->addr, addrs[j]))
                                        goto fail_add_lfa;
                        }

                        free(n_dist[j]);
                }
        }

        pthread_mutex_unlock(&graph->lock);

        free(s_dist);

        return 0;

 fail_add_lfa:
        for (k = j; k < i; k++)
                free(n_dist[k]);
 fail_dijkstra:
        free_routing_table(table);
        free(s_dist);
 fail_table_simple:
        pthread_mutex_unlock(&graph->lock);

        return -1;
}
