/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Resource Information Base
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#ifndef OUROBOROS_LIB_RIB_H
#define OUROBOROS_LIB_RIB_H

#include <sys/types.h>
#include <stdbool.h>

#define RIB_ROOT ""

int     rib_init(void);

void    rib_fini(void);

int     rib_add(const char * parent,
                const char * name);

int     rib_del(char * path);

ssize_t rib_read(const char * path,
                 void *       data,
                 size_t       len);

int     rib_write(const char * path,
                  const void * data,
                  size_t       len);

int     rib_put(const char * path,
                void *       data,
                size_t       len);

bool    rib_has(const char * path);

ssize_t rib_children(const char * path,
                     char ***     children);

char *  rib_path_append(char *       path,
                        const char * name);

char *  rib_name_gen(void * data,
                     size_t len);

#endif /* OUROBOROS_LIB_RIB_H */
