/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the graph structure
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#include <test/test.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "graph.c"

struct graph *   graph;
struct list_head table;
qosspec_t        qs;

static const struct {
        enum routing_algo algo;
        const char *      name;
} algos[] = {
        { ROUTING_SIMPLE, "simple" },
        { ROUTING_LFA,    "lfa"    },
        { ROUTING_ECMP,   "ecmp"   }
};

/* The topology distance_check() expects: every link transit, both ways. */
static const struct {
        uint64_t s;
        uint64_t d;
} sym_links[] = {
        { 1, 2 }, { 2, 3 }, { 1, 3 }, { 3, 4 },
        { 4, 5 }, { 2, 6 }, { 6, 7 }, { 3, 7 }
};

static int announce(uint64_t s,
                    uint64_t d,
                    bool     transit)
{
        return graph_announce_link(graph, s, d, transit, qs);
}

static int withdraw(uint64_t s,
                    uint64_t d)
{
        return graph_withdraw_link(graph, s, d);
}

static int check_entries(int entries)
{
        struct list_head * p;
        int                i = 0;

        if (graph_routing_table(graph, ROUTING_SIMPLE, 1, &table) < 0) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table)
                i++;

        if (i != entries) {
                printf("Wrong number of entries.\n");
                goto fail;
        }

        graph_free_routing_table(graph, &table);

        return 0;
 fail:
        graph_free_routing_table(graph, &table);
        return -1;
}

static int check_double_link(void)
{
        struct list_head * p;
        int                i = 0;

        if (graph_routing_table(graph, ROUTING_SIMPLE, 1, &table) < 0) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table)
                i++;

        if (i != 2) {
                printf("Wrong number of entries.\n");
                goto fail;
        }

        list_for_each(p, &table) {
                struct routing_table * t =
                        list_entry(p, struct routing_table, next);
                struct nhop *          n =
                        list_first_entry(&t->nhops, struct nhop, next);

                if (n->nhop != 2 || (t->dst != 2 && t->dst != 3)) {
                        printf("Wrong routing entry.\n");
                        goto fail;
                }
        }

        graph_free_routing_table(graph, &table);

        return 0;
 fail:
        graph_free_routing_table(graph, &table);
        return -1;
}

static int check_single_link(void)
{
        struct list_head * p;
        int                i = 0;

        if (graph_routing_table(graph, ROUTING_SIMPLE, 1, &table) < 0) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table)
                i++;

        if (i != 1) {
                printf("Wrong number of entries.\n");
                goto fail;
        }

        list_for_each(p, &table) {
                struct routing_table * t =
                        list_entry(p, struct routing_table, next);
                struct nhop *          n =
                        list_first_entry(&t->nhops, struct nhop, next);

                if (t->dst != 2 || n->nhop != 2) {
                        printf("Wrong routing entry.\n");
                        goto fail;
                }
        }

        graph_free_routing_table(graph, &table);

        return 0;
 fail:
        graph_free_routing_table(graph, &table);
        return -1;
}

/* Distances are algorithm-independent on this topology. */
static int distance_check(int               dst,
                          int               nhop,
                          enum routing_algo algo)
{
        (void) algo;

        if (dst == 2 && nhop != 2) {
                printf("Wrong entry: 2.\n");
                return -1;
        }

        if (dst == 3 && nhop != 3) {
                printf("Wrong entry: 3.\n");
                return -1;
        }

        if (dst == 4 && nhop != 3) {
                printf("Wrong entry: 4.\n");
                return -1;
        }

        if (dst == 5 && nhop != 3) {
                printf("Wrong entry: 5.\n");
                return -1;
        }

        if (dst == 6 && nhop != 2) {
                printf("Wrong entry: 6.\n");
                return -1;
        }

        if (dst == 7 && nhop != 3) {
                printf("Wrong entry: 7.\n");
                return -1;
        }

        return 0;
}

static int routing_check(enum routing_algo algo)
{
        struct list_head * p;

        if (graph_routing_table(graph, algo, 1, &table) < 0) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table) {
                struct routing_table * t;
                struct nhop *          n;

                t = list_entry(p, struct routing_table, next);
                n = list_first_entry(&t->nhops, struct nhop, next);
                if (distance_check(t->dst, n->nhop, algo) < 0)
                        goto fail;
        }

        graph_free_routing_table(graph, &table);

        return 0;
 fail:
        graph_free_routing_table(graph, &table);
        return -1;
}

static int build_symmetric_graph(void)
{
        size_t i;

        for (i = 0; i < sizeof(sym_links) / sizeof(*sym_links); ++i) {
                if (announce(sym_links[i].s, sym_links[i].d, true) < 0)
                        return -1;

                if (announce(sym_links[i].d, sym_links[i].s, true) < 0)
                        return -1;
        }

        return 0;
}

static int transit_check(enum routing_algo algo)
{
        struct list_head * p;
        struct list_head * q;
        int                dsts = 0;
        int                ret  = 0;

        if (graph_routing_table(graph, algo, 1, &table) < 0) {
                printf("Failed to get routing table.\n");
                return -1;
        }

        list_for_each(p, &table) {
                struct routing_table * t;
                struct nhop *          n;

                t = list_entry(p, struct routing_table, next);
                n = list_first_entry(&t->nhops, struct nhop, next);
                dsts++;

                if (t->dst == 4 && n->nhop != 2) {
                        printf("Wrong next hop for 4.\n");

                        ret = -1;
                }

                list_for_each(q, &t->nhops) {
                        struct nhop * h;

                        h = list_entry(q, struct nhop, next);
                        if (h->nhop == 3 && t->dst != 3) {
                                printf("Next hop via non-transit node.\n");

                                ret = -1;
                        }
                }

                if (t->dst == 6) {
                        printf("Routed to a node behind a non-transit.\n");

                        ret = -1;
                }
        }

        if (dsts != 4) {
                printf("Wrong number of entries: %d.\n", dsts);

                ret = -1;
        }

        graph_free_routing_table(graph, &table);

        return ret;
}

/*
 * Node 3 links 1 and 4 but is non-transit, and 6 hangs off 3 alone,
 * so 1 - 2 - 5 - 4 is the only usable path to 4 and 6 is unreachable.
 */
static int test_graph_non_transit(enum routing_algo algo,
                                  const char *      name)
{
        TEST_START("(%s)", name);

        graph = graph_create();
        if (graph == NULL) {
                printf("Failed to create graph.\n");
                goto fail;
        }

        announce(1, 3, true);
        announce(3, 1, false);
        announce(3, 4, false);
        announce(4, 3, true);

        announce(3, 6, false);
        announce(6, 3, true);

        announce(1, 2, true);
        announce(2, 1, true);
        announce(2, 5, true);
        announce(5, 2, true);
        announce(5, 4, true);
        announce(4, 5, true);

        if (transit_check(algo) < 0)
                goto fail_graph;

        graph_destroy(graph);

        TEST_SUCCESS("(%s)", name);

        return TEST_RC_SUCCESS;
 fail_graph:
        graph_destroy(graph);
 fail:
        TEST_FAIL("(%s)", name);
        return TEST_RC_FAIL;
}

static int test_graph_non_transit_all(void)
{
        size_t i;
        int    ret = 0;

        for (i = 0; i < sizeof(algos) / sizeof(*algos); ++i)
                ret |= test_graph_non_transit(algos[i].algo, algos[i].name);

        return ret;
}

static int test_graph_link_lifecycle(void)
{
        TEST_START();

        graph = graph_create();
        if (graph == NULL) {
                printf("Failed to create graph.\n");
                goto fail;
        }

        graph_destroy(graph);

        graph = graph_create();
        if (graph == NULL) {
                printf("Failed to create graph.\n");
                goto fail;
        }

        if (announce(1, 2, true) < 0) {
                printf("Failed to add edge.\n");
                goto fail_graph;
        }

        if (announce(2, 1, true) < 0) {
                printf("Failed to add edge.\n");
                goto fail_graph;
        }

        if (check_single_link() < 0)
                goto fail_graph;

        if (announce(2, 3, true) < 0) {
                printf("Failed to add edge.\n");
                goto fail_graph;
        }

        if (announce(3, 2, true) < 0) {
                printf("Failed to add edge.\n");
                goto fail_graph;
        }

        if (check_double_link() < 0)
                goto fail_graph;

        if (withdraw(2, 3) < 0) {
                printf("Failed to delete edge.\n");
                goto fail_graph;
        }

        if (withdraw(3, 2) < 0) {
                printf("Failed to delete edge.\n");
                goto fail_graph;
        }

        if (check_single_link() < 0)
                goto fail_graph;

        announce(2, 3, true);
        announce(3, 2, true);
        announce(1, 3, true);
        announce(3, 1, true);

        if (check_entries(2) < 0)
                goto fail_graph;

        announce(3, 4, true);
        announce(4, 3, true);
        announce(4, 5, true);
        announce(5, 4, true);

        if (check_entries(4) < 0)
                goto fail_graph;

        announce(2, 6, true);
        announce(6, 2, true);
        announce(6, 7, true);
        announce(7, 6, true);
        announce(3, 7, true);
        announce(7, 3, true);

        if (check_entries(6) < 0)
                goto fail_graph;

        graph_destroy(graph);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_graph:
        graph_destroy(graph);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_graph_routing(enum routing_algo algo,
                              const char *      name)
{
        TEST_START("(%s)", name);

        graph = graph_create();
        if (graph == NULL) {
                printf("Failed to create graph.\n");
                goto fail;
        }

        if (build_symmetric_graph() < 0) {
                printf("Failed to build graph.\n");
                goto fail_graph;
        }

        if (routing_check(algo) < 0) {
                printf("Routing check failed for %s.\n", name);
                goto fail_graph;
        }

        graph_destroy(graph);

        TEST_SUCCESS("(%s)", name);

        return TEST_RC_SUCCESS;
 fail_graph:
        graph_destroy(graph);
 fail:
        TEST_FAIL("(%s)", name);
        return TEST_RC_FAIL;
}

static int test_graph_routing_all(void)
{
        size_t i;
        int    ret = 0;

        for (i = 0; i < sizeof(algos) / sizeof(*algos); ++i)
                ret |= test_graph_routing(algos[i].algo, algos[i].name);

        return ret;
}

/*
 * 6 announces links to 1 and 2, which never announce back.
 * Withdrawing 6 - 1 leaves 6 without edges while 2 still points at it.
 */
static int test_graph_vertex_in_use(void)
{
        TEST_START();

        graph = graph_create();
        if (graph == NULL) {
                printf("Failed to create graph.\n");
                goto fail;
        }

        announce(1, 2, true);
        announce(2, 1, true);

        announce(6, 1, false);
        announce(6, 2, false);

        if (graph->vertices.len != 3) {
                printf("Expected 3 vertices, got %zu.\n", graph->vertices.len);
                goto fail_graph;
        }

        withdraw(6, 1);

        if (graph->vertices.len != 3) {
                printf("Vertex dropped while still referenced.\n");
                goto fail_graph;
        }

        if (graph_routing_table(graph, ROUTING_SIMPLE, 1, &table) < 0) {
                printf("Failed to get routing table.\n");
                goto fail_graph;
        }

        graph_free_routing_table(graph, &table);

        graph_destroy(graph);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_graph:
        graph_destroy(graph);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int graph_test(int     argc,
               char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        memset(&qs, 0, sizeof(qs));

        ret |= test_graph_link_lifecycle();
        ret |= test_graph_vertex_in_use();
        ret |= test_graph_routing_all();
        ret |= test_graph_non_transit_all();

        return ret;
}
