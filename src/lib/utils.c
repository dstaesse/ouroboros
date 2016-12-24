/*
 * Ouroboros - Copyright (C) 2016
 *
 * Handy utilities
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#include <stdlib.h>
#include <string.h>

int n_digits(unsigned i)
{
    int n = 1;

    while (i > 9) {
        ++n;
        i /= 10;
    }

    return n;
}

char * path_strip(char * src)
{
        char * dst = NULL;

        if (src == NULL)
                return NULL;

        dst = src + strlen(src);

        while (dst > src && *dst != '/')
                --dst;

        if (*dst == '/')
                ++dst;

        return dst;
}
