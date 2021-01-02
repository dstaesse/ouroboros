/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * RIB export using FUSE
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

#ifndef OUROBOROS_LIB_RIB_H
#define OUROBOROS_LIB_RIB_H

#define RIB_PATH_LEN 128

#include <sys/stat.h>
#include <sys/types.h>

struct rib;

struct rib_ops {
        int (* read)(const char * path,
                     char *       buf,
                     size_t       len);
        int (* readdir)(char *** entries);
        int (* getattr)(const char *  path,
                        struct stat * st);
};

int  rib_init(const char * prefix);

void rib_fini(void);

int  rib_reg(const char *     path,
             struct rib_ops * ops);

void rib_unreg(const char * path);

#endif /* OUROBOROS_LIB_RIB_H */
