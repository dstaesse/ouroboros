/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Test of the B-tree implementation
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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


#include "btree.h"

#include <stdio.h>
#include <stdlib.h>

#define MAX_BTREE_KEY 10000

int btree_test(int     argc,
               char ** argv)
{
        struct btree * tree;

        int i;

        (void) argc;
        (void) argv;

        tree = btree_create(32);
        if (tree == NULL)
                return -1;

        if (btree_search(tree, 8) != NULL) {
                btree_destroy(tree);
                return -1;
        }

        for(i = 0; i < MAX_BTREE_KEY; ++i)
                if (btree_insert(tree, i, &argv)) {
                        printf("Failed to add element.\n");
                        btree_destroy(tree);
                        return -1;
                }

        for (i = 0; i < MAX_BTREE_KEY / 10; ++i)
                if (btree_search(tree, rand() % MAX_BTREE_KEY) != &argv) {
                        printf("Added element not in tree.\n");
                        btree_destroy(tree);
                        return -1;
                }

        for (i = 0; i < MAX_BTREE_KEY / 10; ++i)
                if (btree_remove(tree, i)) {
                        printf("Failed to remove element.\n");
                        btree_destroy(tree);
                        return -1;
                }

        for (i = 0; i < MAX_BTREE_KEY / 10; ++i)
                if (btree_search(tree, rand() % MAX_BTREE_KEY / 10) != &argv) {
                        printf("Removed element found in tree.\n");
                        btree_destroy(tree);
                        return -1;
                }

        btree_destroy(tree);

        return 0;
}
