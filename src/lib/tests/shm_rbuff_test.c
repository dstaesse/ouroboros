/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Test of the shm_rbuff
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

#include "config.h"

#include <ouroboros/shm_rbuff.h>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int shm_rbuff_test(int     argc,
                   char ** argv)
{
        struct shm_rbuff * rb;
        size_t             i;

        (void) argc;
        (void) argv;

        printf("Test: create rbuff...");

        rb = shm_rbuff_create(getpid(), 1);
        if (rb == NULL)
                goto err;

        printf("success.\n\n");
        printf("Test: write a value...");

        if (shm_rbuff_write(rb, 1) < 0)
                goto error;

        printf("success.\n\n");
        printf("Test: check queue length is 1...");

        if (shm_rbuff_queued(rb) != 1)
                goto error;

        printf("success.\n\n");
        printf("Test: read a value...");

        if (shm_rbuff_read(rb) != 1)
                goto error;

        printf("success.\n\n");
        printf("Test: check queue is empty...");

        if (shm_rbuff_read(rb) != -EAGAIN)
                goto error;

        printf("success.\n\n");
        printf("Test: fill the queue...");

        for (i = 0; i < SHM_RBUFF_SIZE - 1; ++i) {
                if (shm_rbuff_queued(rb) != i)
                        goto error;
                if (shm_rbuff_write(rb, 1) < 0)
                        goto error;
        }

        printf("success.\n\n");
        printf("Test: check queue is full...");

        if (shm_rbuff_queued(rb) != SHM_RBUFF_SIZE - 1)
                goto error;

        printf("success [%zd entries].\n\n", shm_rbuff_queued(rb));

        printf("Test: check queue is full by writing value...");
        if (!(shm_rbuff_write(rb, 1) < 0))
                goto error;

        printf("success [%zd entries].\n\n", shm_rbuff_queued(rb));

        /* empty the rbuff */
        while (shm_rbuff_read(rb) >= 0)
                ;

        shm_rbuff_destroy(rb);

        return 0;

 error:
        /* empty the rbuff */
        while (shm_rbuff_read(rb) >= 0)
                ;

        shm_rbuff_destroy(rb);
 err:
        printf("failed.\n\n");
        return -1;
}
