/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Test of the hash table
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

#include "pft.c"

#include <stdio.h>

#define TBL_SIZE 256
#define INT_TEST 4

int pft_test(int     argc,
             char ** argv)
{
        struct pft * pft;
        int          i;
        int *        j;
        size_t       len;

        (void) argc;
        (void) argv;

        pft = pft_create(TBL_SIZE, true);
        if (pft == NULL) {
                printf("Failed to create.\n");
                return -1;
        }

        pft_destroy(pft);

        pft = pft_create(TBL_SIZE, false);
        if (pft == NULL) {
                printf("Failed to create.\n");
                return -1;
        }

        for (i = 0; i < TBL_SIZE + INT_TEST + 2; i++) {
                j = malloc(sizeof(*j));
                if (j == NULL) {
                        printf("Failed to malloc.\n");
                        pft_destroy(pft);
                        return -1;
                }
                *j = i;

                if (pft_insert(pft, i, j, 1)) {
                        printf("Failed to insert.\n");
                        pft_destroy(pft);
                        free(j);
                        return -1;
                }
        }

        if (pft_lookup(pft, INT_TEST, &j, &len)) {
                printf("Failed to lookup.\n");
                pft_destroy(pft);
                return -1;
        }

        if (*j != INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       INT_TEST, *j);
                pft_destroy(pft);
                return -1;
        }

        if (pft_lookup(pft, TBL_SIZE + INT_TEST, &j, &len)) {
                printf("Failed to lookup.\n");
                pft_destroy(pft);
                return -1;
        }

        if (*j != TBL_SIZE + INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       INT_TEST, *j);
                pft_destroy(pft);
                return -1;
        }

        if (pft_delete(pft, INT_TEST)) {
                printf("Failed to delete.\n");
                pft_destroy(pft);
                return -1;
        }

        if (pft_lookup(pft, INT_TEST, &j, &len) == 0) {
                printf("Failed to delete properly.\n");
                pft_destroy(pft);
                return -1;
        }

        if (pft_lookup(pft, TBL_SIZE + INT_TEST, &j, &len)) {
                printf("Failed to lookup after deletion.\n");
                pft_destroy(pft);
                return -1;
        }

        if (*j != TBL_SIZE + INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       INT_TEST, *j);
                pft_destroy(pft);
                return -1;
        }

        pft_destroy(pft);

        return 0;
}
