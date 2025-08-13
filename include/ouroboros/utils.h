/*
 * Ouroboros - Copyright (C) 2016 - 2024
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

#ifndef OUROBOROS_LIB_UTILS_H
#define OUROBOROS_LIB_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define ABS(a)   ((a) > 0 ? (a) : -(a))
#define clrbuf(buf) do { memset(&(buf), 0, sizeof(buf)); } while (0);
#define freebuf(buf) do { free((buf).data); clrbuf(buf); } while (0);
#define BUF_INIT { 0, NULL }
#define BUF_IS_EMPTY(buf) ((buf)->data == NULL && (buf)->len == 0)

typedef struct {
        size_t    len;
        uint8_t * data;
} buffer_t;

int bufcmp(const buffer_t * a,
           const buffer_t * b);

/*
 * Returns the number of characters a uint would
 * need when represented as a string
 */
int n_digits(unsigned i);

/* gets the application name */
char * path_strip(const char * src);

/* functions for copying and destroying arguments list */
size_t  argvlen(const char ** argv);

char ** argvdup(char ** argv);

void    argvfree(char ** argv);

/* destroy a ** */
#define freepp(type, ptr, len)                          \
        do {                                            \
                while (len-- > 0)                       \
                        free(((type **) ptr)[len]);     \
                free(ptr);                              \
        } while (0)

/* destroys an array of buffers */
#define freebufs(ptr, len)                              \
        do {                                            \
                while ((len)-- > 0)                     \
                        freebuf((ptr)[len]);            \
                free(ptr);                              \
        } while (0)

#endif /* OUROBOROS_LIB_UTILS_H */
