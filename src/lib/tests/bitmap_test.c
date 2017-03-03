/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Test of the bitmap
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

#include "bitmap.c"
#include <time.h>
#include <stdlib.h>

#define BITMAP_SIZE 200

int bitmap_test(int argc, char ** argv)
{
        struct bmp * bmp;
        size_t bits = BITMAP_SIZE;
        ssize_t id;
        int i;
        ssize_t r;
        ssize_t offset = 100;

        (void) argc;
        (void) argv;

        srand(time(NULL));

        bmp = bmp_create(bits, offset);
        if (bmp == NULL)
                return -1;

        if (bmp_destroy(bmp))
                return -1;

        bmp = bmp_create(bits, offset);
        if (bmp == NULL)
                return -1;

        for (i = offset; i < BITMAP_SIZE + 5 + offset; i++) {
                id = bmp_allocate(bmp);
                if (!bmp_is_id_valid(bmp, id))
                        continue;

                if (id != i)
                        return -1;
        }

        for (i = 0; i < BITMAP_SIZE + 5; i++) {
                r = (ssize_t) (rand() % BITMAP_SIZE) + offset;

                if (bmp_release(bmp, r))
                        return -1;

                id = bmp_allocate(bmp);
                if (!bmp_is_id_valid(bmp, id))
                        continue;
                if (id != r)
                        return -1;
        }

        if (bmp_destroy(bmp))
                return -1;

        return 0;
}
