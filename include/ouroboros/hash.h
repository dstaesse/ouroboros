/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Hashing functions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_LIB_HASH_H
#define OUROBOROS_LIB_HASH_H

#include <ouroboros/endian.h>
#include <ouroboros/ipcp.h>

#include <ouroboros/crc32.h>
#include <ouroboros/md5.h>
#include <ouroboros/sha3.h>

#define HASH_FMT "%02x%02x%02x%02x"
#define HASH_VAL(hash)                                    \
        (betoh32(*(uint32_t *) hash) & 0xFF000000) >> 24, \
        (betoh32(*(uint32_t *) hash) & 0x00FF0000) >> 16, \
        (betoh32(*(uint32_t *) hash) & 0x0000FF00) >> 8,  \
        (betoh32(*(uint32_t *) hash) & 0x000000FF)

uint16_t hash_len(enum hash_algo algo);

void str_hash(enum hash_algo algo,
              void *         buf,
              const char *   str);

#endif /* OUROBOROS_LIB_HASH_H */
