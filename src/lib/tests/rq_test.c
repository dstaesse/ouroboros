/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Reordering queue test
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#include "rq.h"

#include <stdio.h>

#define Q_SIZE 5

int rq_test(int     argc,
            char ** argv)
{
        struct rq * q;
        int         i;

        (void) argc;
        (void) argv;

        q = rq_create(Q_SIZE);
        if (q == NULL) {
                printf("Failed to create.\n");
                return -1;
        }

        if (rq_push(q, 1, 1)) {
                printf("Failed to insert.\n");
                return -1;
        }

        if (!rq_has(q, 1)) {
                printf("Inserted item not present.\n");
                return -1;
        }

        if (rq_peek(q) != 1) {
                printf("Inserted item not present.\n");
                return -1;
        }

        if (rq_pop(q) != 1) {
                printf("Bad pop.\n");
                return -1;
        }

        if (rq_push(q, 3, 5)) {
                printf("Failed to insert.\n");
                return -1;
        }

        if (rq_push(q, 1, 3)) {
                printf("Failed to insert.\n");
                return -1;
        }

        if (rq_push(q, 2, 7)) {
                printf("Failed to insert.\n");
                return -1;
        }

        if (!rq_has(q, 3)) {
                printf("Inserted item not present.\n");
                return -1;
        }

        if (rq_has(q, 4)) {
                printf("Item present that was not inserted.\n");
                return -1;
        }

        if (rq_peek(q) != 1) {
                printf("Inserted item not present.\n");
                return -1;
        }

        if (rq_pop(q) != 3) {
                printf("Bad pop.\n");
                return -1;
        }

        if (rq_peek(q) != 2) {
                printf("Inserted item not present.\n");
                return -1;
        }

        if (rq_pop(q) != 7) {
                printf("Bad pop.\n");
                return -1;
        }

        for (i = 0; i < Q_SIZE + 1; i++)
                rq_push(q, i, i);

        rq_destroy(q);

        return 0;
}
