/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Test of the graph structure
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

#include <ouroboros/utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "graph.c"

struct graph *   graph;
struct list_head table;
qosspec_t        qs;

int graph_test_entries(int entries)
{
        struct list_head * p;
        int                i = 0;

        if (graph_routing_table(graph, 1, &table)) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table)
                i++;

        if (i != entries) {
                printf("Wrong number of entries.\n");
                graph_free_routing_table(graph, &table);
                return -1;
        }

        graph_free_routing_table(graph, &table);

        return 0;
}

int graph_test_double_link(void)
{
        struct list_head * p;
        int                i = 0;

        if (graph_routing_table(graph, 1, &table)) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table)
                i++;

        if (i != 2) {
                printf("Wrong number of entries.\n");
                graph_free_routing_table(graph, &table);
                return -1;
        }

        list_for_each(p, &table) {
                struct routing_table * t =
                        list_entry(p, struct routing_table, next);
                struct nhop *          n =
                        list_first_entry(&t->nhops, struct nhop, next);

                if ((t->dst != 2 && n->nhop != 2) ||
                    (t->dst != 3 && n->nhop != 2)) {
                        printf("Wrong routing entry.\n");
                        graph_free_routing_table(graph, &table);
                        return -1;
                }
        }

        graph_free_routing_table(graph, &table);

        return 0;
}

int graph_test_single_link(void)
{
        struct list_head * p;
        int                i = 0;

        if (graph_routing_table(graph, 1, &table)) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table)
                i++;

        if (i != 1) {
                printf("Wrong number of entries.\n");
                graph_free_routing_table(graph, &table);
                return -1;
        }

        list_for_each(p, &table) {
                struct routing_table * t =
                        list_entry(p, struct routing_table, next);
                struct nhop *          n =
                        list_first_entry(&t->nhops, struct nhop, next);

                if (t->dst != 2 && n->nhop != 2) {
                        printf("Wrong routing entry.\n");
                        graph_free_routing_table(graph, &table);
                        return -1;
                }
        }

        graph_free_routing_table(graph, &table);

        return 0;
}

int graph_test(int     argc,
               char ** argv)
{
        int                nhop;
        int                dst;
        struct list_head * p;

        (void) argc;
        (void) argv;

        memset(&qs, 0, sizeof(qs));

        graph = graph_create();
        if (graph == NULL) {
                printf("Failed to create graph.\n");
                return -1;
        }

        graph_destroy(graph);

        graph = graph_create();
        if (graph == NULL) {
                printf("Failed to create graph.\n");
                return -1;
        }

        if (graph_update_edge(graph, 1, 2, qs)) {
                printf("Failed to add edge.\n");
                graph_destroy(graph);
                return -1;
        }

        if (graph_update_edge(graph, 2, 1, qs)) {
                printf("Failed to add edge.\n");
                graph_destroy(graph);
                return -1;
        }

        if (graph_test_single_link()) {
                graph_destroy(graph);
                return -1;
        }

        if (graph_update_edge(graph, 2, 3, qs)) {
                printf("Failed to add edge.\n");
                graph_destroy(graph);
                return -1;
        }

        if (graph_update_edge(graph, 3, 2, qs)) {
                printf("Failed to add edge.\n");
                graph_destroy(graph);
                return -1;
        }


        if (graph_test_double_link()) {
                graph_destroy(graph);
                return -1;
        }

        if (graph_del_edge(graph, 2, 3)) {
                printf("Failed to delete edge.\n");
                graph_destroy(graph);
                return -1;
        }

        if (graph_del_edge(graph, 3, 2)) {
                printf("Failed to delete edge.\n");
                graph_destroy(graph);
                return -1;
        }

        if (graph_test_single_link()) {
                graph_destroy(graph);
                return -1;
        }

        graph_update_edge(graph, 2, 3, qs);
        graph_update_edge(graph, 3, 2, qs);
        graph_update_edge(graph, 1, 3, qs);
        graph_update_edge(graph, 3, 1, qs);

        if (graph_test_entries(2)) {
                graph_destroy(graph);
                return -1;
        }

        graph_update_edge(graph, 3, 4, qs);
        graph_update_edge(graph, 4, 3, qs);
        graph_update_edge(graph, 4, 5, qs);
        graph_update_edge(graph, 5, 4, qs);

        if (graph_test_entries(4)) {
                graph_destroy(graph);
                return -1;
        }

        graph_update_edge(graph, 2, 6, qs);
        graph_update_edge(graph, 6, 2, qs);
        graph_update_edge(graph, 6, 7, qs);
        graph_update_edge(graph, 7, 6, qs);
        graph_update_edge(graph, 3, 7, qs);
        graph_update_edge(graph, 7, 3, qs);

        if (graph_test_entries(6)) {
                graph_destroy(graph);
                return -1;
        }

        if (graph_routing_table(graph, 1, &table)) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table) {
                struct routing_table * t =
                        list_entry(p, struct routing_table, next);
                struct nhop *          n =
                        list_first_entry(&t->nhops, struct nhop, next);

                dst = t->dst;
                nhop = n->nhop;

                if (dst == 3 && nhop != 3) {
                        printf("Wrong entry.");
                        graph_free_routing_table(graph, &table);
                        return -1;
                }

                if (dst == 2 && nhop != 2) {
                        printf("Wrong entry.");
                        graph_free_routing_table(graph, &table);
                        return -1;
                }

                if (dst == 6 && nhop != 2) {
                        printf("Wrong entry.");
                        graph_free_routing_table(graph, &table);
                        return -1;
                }

                if (dst == 4 && nhop != 3) {
                        printf("Wrong entry.");
                        graph_free_routing_table(graph, &table);
                        return -1;
                }

                if (dst == 5 && nhop != 3) {
                        printf("Wrong entry.");
                        graph_free_routing_table(graph, &table);
                        return -1;
                }

                if (dst == 7 && nhop != 3) {
                        printf("Wrong entry.");
                        graph_free_routing_table(graph, &table);
                        return -1;
                }
        }

        graph_free_routing_table(graph, &table);

        return 0;
}
