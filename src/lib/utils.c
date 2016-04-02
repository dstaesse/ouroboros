/*
 * Ouroboros - Copyright (C) 2016
 *
 * Handy utilities
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include <stdlib.h>
#include <string.h>

int n_digits(unsigned i)
{
    int n = 1;

    while (i > 9) {
        n++;
        i /= 10;
    }

    return n;
}

char * strdup(const char * src)
{
        int len = 0;
        char * dst = NULL;

        if (src == NULL)
                return NULL;

        len = strlen(src) + 1;

        dst = malloc(len);
        if (dst == NULL)
                return NULL;

        memcpy(dst, src, len);

        return dst;
}
