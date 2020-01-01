/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Handy utilities
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
