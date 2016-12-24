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
