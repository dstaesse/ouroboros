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

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>

static struct edge * find_edge_by_addr(struct vertex * vertex,
                                       uint64_t        dst_addr)
{
        struct list_head * p = NULL;

        list_for_each(p, &vertex->edges) {
                struct edge * e = list_entry(p, struct edge, next);
                if (e->dst_addr == dst_addr)
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

static int add_edge(struct vertex * vertex,
                    uint64_t        dst_addr,
                    qosspec_t       qs)
{
        struct edge * edge;

        edge = malloc(sizeof(*edge));
        if (edge == NULL)
                return -ENOMEM;

        list_head_init(&edge->next);
        edge->dst_addr = dst_addr;
        edge->qs = qs;

        list_add(&edge->next, &vertex->edges);

        return 0;
}

static void del_edge(struct edge * edge)
{
       list_del(&edge->next);
       free(edge);
}

static int add_vertex(struct graph * graph,
                      uint64_t       addr)
{
        struct vertex *    vertex;
        struct list_head * p;

        vertex = malloc(sizeof(*vertex));
        if (vertex == NULL)
                return -1;

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

        return 0;
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

int graph_add_edge(struct graph * graph,
                   uint64_t       s_addr,
                   uint64_t       d_addr,
                   qosspec_t      qs)
{
        struct vertex * v;
        struct edge * e;

        assert(graph);

        pthread_mutex_lock(&graph->lock);

        v = find_vertex_by_addr(graph, s_addr);
        if (v == NULL) {
                if (add_vertex(graph, s_addr)) {
                        pthread_mutex_unlock(&graph->lock);
                        return -ENOMEM;
                }
        }

        e = find_edge_by_addr(v, d_addr);
        if (e != NULL) {
                pthread_mutex_unlock(&graph->lock);
                log_err("Edge already exists.");
                return -1;
        }

        if (add_edge(v, d_addr, qs)) {
                pthread_mutex_unlock(&graph->lock);
                log_err("Failed to add edge.");
                return -1;
        }

        pthread_mutex_unlock(&graph->lock);

        return 0;
}

int graph_update_edge(struct graph * graph,
                      uint64_t       s_addr,
                      uint64_t       d_addr,
                      qosspec_t      qs)
{
        struct vertex * v;
        struct edge * e;

        assert(graph);

        pthread_mutex_lock(&graph->lock);

        v = find_vertex_by_addr(graph, s_addr);
        if (v == NULL) {
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

        e->qs = qs;

        pthread_mutex_unlock(&graph->lock);

        return 0;
}

int graph_del_edge(struct graph * graph,
                   uint64_t       s_addr,
                   uint64_t       d_addr)
{
        struct vertex * v;
        struct edge * e;

        assert(graph);

        pthread_mutex_lock(&graph->lock);

        v = find_vertex_by_addr(graph, s_addr);
        if (v == NULL) {
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

        pthread_mutex_unlock(&graph->lock);

        return 0;
}
