/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Test of the B-tree implementation
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


#include <ouroboros/btree.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BTREE_KEY 10000

int btree_test(int     argc,
               char ** argv)
{
        struct btree * tree;

        int vals[MAX_BTREE_KEY];
        int i;
        int j;

        (void) argc;
        (void) argv;

        memset(vals, 0, MAX_BTREE_KEY * sizeof(int));

        tree = btree_create(32);
        if (tree == NULL)
                return -1;

        if (btree_search(tree, 8) != NULL) {
                btree_destroy(tree);
                return -1;
        }

        for (i = 0; i < MAX_BTREE_KEY; ++i)
                if (btree_insert(tree, i, &argv)) {
                        printf("Failed to add element.\n");
                        btree_destroy(tree);
                        return -1;
                }

        for (i = 0; i < MAX_BTREE_KEY; ++i)
                if (btree_search(tree, rand() % MAX_BTREE_KEY) != &argv) {
                        printf("Added element not in tree.\n");
                        btree_destroy(tree);
                        return -1;
                }

        for (i = 0; i < MAX_BTREE_KEY; ++i)
                if (btree_remove(tree, i)) {
                        printf("Failed to remove element %d.\n", i);
                        btree_destroy(tree);
                        return -1;
                }

        for (i = 0; i < MAX_BTREE_KEY / 10; ++i)
                if (btree_search(tree, rand() % MAX_BTREE_KEY / 10) != NULL) {
                        printf("Removed element found in tree.\n");
                        btree_destroy(tree);
                        return -1;
                }

        for (i = 0; i < MAX_BTREE_KEY; ++i)
                if (btree_insert(tree, i, &argv)) {
                        printf("Failed to add element.\n");
                        btree_destroy(tree);
                        return -1;
                }

        for (i = 0; i < MAX_BTREE_KEY; ++i) {
                j = rand() % MAX_BTREE_KEY;
                if (vals[j] != -1) {
                        if (btree_remove(tree, j)) {
                                printf("Failed to remove element %d.\n", j);
                                btree_destroy(tree);
                                return -1;
                        }
                }
                vals[j] = -1;
        }

        btree_destroy(tree);

        return 0;
}
