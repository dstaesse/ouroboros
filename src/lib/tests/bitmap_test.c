/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Test of the bitmap
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

#include "bitmap.c"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#define BITMAP_SIZE 200

int bitmap_test(int     argc,
                char ** argv)
{
        struct bmp * bmp;
        ssize_t bits = BITMAP_SIZE;
        ssize_t id;
        int i;
        ssize_t r;
        ssize_t offset = 100;

        (void) argc;
        (void) argv;

        srand(time(NULL));

        bmp = bmp_create(bits, offset);
        if (bmp == NULL) {
                printf("Failed to create bmp.\n");
                return -1;
        }

        bmp_destroy(bmp);

        bmp = bmp_create(bits, offset);
        if (bmp == NULL) {
                printf("Failed to re-create bmp.\n");
                return -1;
        }

        for (i = offset; i < BITMAP_SIZE + 5 + offset; i++) {
                id = bmp_allocate(bmp);
                if (!bmp_is_id_valid(bmp, id)) {
                        if (i < BITMAP_SIZE + offset) {
                                printf("Failed valid ID %d (%zd).\n", i, id);
                                goto fail;
                        }
                        if (id >= offset && id < bits + offset) {
                                printf("Valid ID %zd returned invalid.\n", id);
                                goto fail;
                        }
                        continue;
                }

                if (!bmp_is_id_used(bmp, id)) {
                        printf("ID not marked in use.\n");
                        goto fail;
                }

                if (id != i) {
                        printf("Wrong ID returned.\n");
                        goto fail;
                }
        }

        for (i = 0; i < BITMAP_SIZE + 5; i++) {
                r = (ssize_t) (rand() % BITMAP_SIZE) + offset;

                if (bmp_release(bmp, r)) {
                        printf("Failed to release ID.\n");
                        goto fail;
                }

                id = bmp_allocate(bmp);
                if (!bmp_is_id_valid(bmp, id))
                        continue;

                if (id != r) {
                        printf("Wrong prev ID returned.\n");
                        goto fail;
                }
        }

        bmp_destroy(bmp);

        return 0;

 fail:
        bmp_destroy(bmp);
        return -1;
}
