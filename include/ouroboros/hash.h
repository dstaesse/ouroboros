/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Hashing functions
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

#ifndef OUROBOROS_LIB_HASH_H
#define OUROBOROS_LIB_HASH_H

#include "config.h"

#include <ouroboros/endian.h>
#include <ouroboros/ipcp.h>

#include <stdint.h>
#include <stddef.h>

/* Hash algorithms */
enum hash_algo {
        HASH_SHA3_224 = DIR_HASH_SHA3_224,
        HASH_SHA3_256 = DIR_HASH_SHA3_256,
        HASH_SHA3_384 = DIR_HASH_SHA3_384,
        HASH_SHA3_512 = DIR_HASH_SHA3_512,
        HASH_CRC32,
        HASH_MD5,
};

#define HASH_FMT "%02x%02x%02x%02x"
#define HASH_VAL(hash)                                    \
        (betoh32(*(uint32_t *) hash) & 0xFF000000) >> 24, \
        (betoh32(*(uint32_t *) hash) & 0x00FF0000) >> 16, \
        (betoh32(*(uint32_t *) hash) & 0x0000FF00) >> 8,  \
        (betoh32(*(uint32_t *) hash) & 0x000000FF)

uint16_t hash_len(enum hash_algo algo);

void mem_hash(enum hash_algo  algo,
              void *          dst,
              const uint8_t * buf,
              size_t          len);

void str_hash(enum hash_algo algo,
              void *         dst,
              const char *   str);

#endif /* OUROBOROS_LIB_HASH_H */
