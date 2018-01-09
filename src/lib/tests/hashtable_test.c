/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Test of the hash table
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

#include "hashtable.c"

#include <stdio.h>

#define HASHTABLE_SIZE 256
#define INT_TEST 4

int hashtable_test(int argc, char ** argv)
{
        struct htable * table;
        int             i;
        int *           j;
        void *          el;
        size_t          len;

        (void) argc;
        (void) argv;

        table = htable_create(HASHTABLE_SIZE, true);
        if (table == NULL) {
                printf("Failed to create.\n");
                return -1;
        }

        htable_destroy(table);

        table = htable_create(HASHTABLE_SIZE, false);
        if (table == NULL) {
                printf("Failed to create.\n");
                return -1;
        }

        for (i = 0; i < HASHTABLE_SIZE + INT_TEST + 2; i++) {
                j = malloc(sizeof(*j));
                if (j == NULL) {
                        printf("Failed to malloc.\n");
                        htable_destroy(table);
                        return -1;
                }
                *j = i;

                if (htable_insert(table, i, (void *) j, 1)) {
                        printf("Failed to insert.\n");
                        htable_destroy(table);
                        return -1;
                }
        }

        if (htable_lookup(table, INT_TEST, &el, &len)) {
                printf("Failed to lookup.\n");
                htable_destroy(table);
                return -1;
        }

        j = (int *) el;
        if (*j != INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       INT_TEST, *j);
                htable_destroy(table);
                return -1;
        }

        if (htable_lookup(table, HASHTABLE_SIZE + INT_TEST, &el, &len)) {
                printf("Failed to lookup.\n");
                htable_destroy(table);
                return -1;
        }

        j = (int *) el;
        if (*j != HASHTABLE_SIZE + INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       INT_TEST, *j);
                htable_destroy(table);
                return -1;
        }

        if (htable_delete(table, INT_TEST)) {
                printf("Failed to delete.\n");
                htable_destroy(table);
                return -1;
        }

        if (htable_lookup(table, INT_TEST, &el, &len) == 0) {
                printf("Failed to delete properly.\n");
                htable_destroy(table);
                return -1;
        }

        if (htable_lookup(table, HASHTABLE_SIZE + INT_TEST, &el, &len)) {
                printf("Failed to lookup after deletion.\n");
                htable_destroy(table);
                return -1;
        }

        j = (int *) el;
        if (*j != HASHTABLE_SIZE + INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       INT_TEST, *j);
                htable_destroy(table);
                return -1;
        }

        htable_destroy(table);

        return 0;
}
