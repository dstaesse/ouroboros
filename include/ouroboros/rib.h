/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * RIB export using FUSE
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

#ifndef OUROBOROS_LIB_RIB_H
#define OUROBOROS_LIB_RIB_H

#define RIB_PATH_LEN  128
#define RIB_SEPARATOR "/"

#include <sys/types.h>

struct rib;

struct rib_attr {
        size_t size;  /* Size of RIB document  */
        time_t mtime; /* Last modified time    */
};

struct rib_ops {
        int (* read)(const char * path,
                     char *       buf,
                     size_t       len);
        int (* readdir)(char *** entries);
        int (* getattr)(const char *      path,
                        struct rib_attr * attr);
};

int  rib_init(const char * prefix);

void rib_fini(void);

int  rib_reg(const char *     path,
             struct rib_ops * ops);

void rib_unreg(const char * path);

#endif /* OUROBOROS_LIB_RIB_H */
