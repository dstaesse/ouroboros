/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Handy utilities
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_UTILS_H
#define OUROBOROS_UTILS_H

#include <stdint.h>
#include <unistd.h>

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

typedef struct {
        uint8_t * data;
        size_t    len;
} buffer_t;

/*
 * Returns the number of characters a uint would
 * need when represented as a string
 */
int n_digits(unsigned i);

/* Returns a copy of the source string */
char * strdup(const char * src);

/* gets the application name */
char * path_strip(char * src);

#endif /* OUROBOROS_UTILS_H */
