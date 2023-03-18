/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Handy utilities
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#ifndef OUROBOROS_UTILS_H
#define OUROBOROS_UTILS_H

#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define ABS(a)   ((a) > 0 ? (a) : -(a))
#define clrbuf(buf) do { memset(&(buf), 0, sizeof(buf)); } while (0);
#define freebuf(buf) do { free((buf).data); clrbuf(buf); } while (0);

typedef struct {
        uint8_t * data;
        size_t    len;
} buffer_t;

/*
 * Returns the number of characters a uint would
 * need when represented as a string
 */
int n_digits(unsigned i);

/* gets the application name */
char * path_strip(const char * src);

/* destroy a ** */
#define freepp(type, ptr, len)                          \
        do {                                            \
                if (len == 0)                           \
                        break;                          \
                while (len > 0)                         \
                        free(((type **) ptr)[--len]);   \
                free(ptr);                              \
        } while (0);

#endif /* OUROBOROS_UTILS_H */
