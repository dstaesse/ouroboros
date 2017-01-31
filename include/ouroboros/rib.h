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
#include <stdint.h>
#include <stdbool.h>

#define RIB_ROOT ""

#define PACK_HASH_ROOT  0x0001
#define PACK_HASH_ALL   0x0002

#define UNPACK_CREATE   0x0001

int       rib_init(void);

void      rib_fini(void);

int       rib_add(const char * parent,
                  const char * name);

int       rib_del(char * path);

ssize_t   rib_read(const char * path,
                   void *       data,
                   size_t       len);

int       rib_write(const char * path,
                    const void * data,
                    size_t       len);

int       rib_put(const char * path,
                  void *       data,
                  size_t       len);

bool      rib_has(const char * path);

ssize_t   rib_children(const char * path,
                       char ***     children);

char *    rib_path_append(char *       path,
                          const char * name);

char *    rib_name_gen(void * data,
                       size_t len);

ssize_t   rib_pack(const char * path,
                   uint8_t **   buf,
                   uint32_t     flags);

int       rib_unpack(uint8_t * packed,
                     size_t    len,
                     uint32_t  flags);

#endif /* OUROBOROS_LIB_RIB_H */
