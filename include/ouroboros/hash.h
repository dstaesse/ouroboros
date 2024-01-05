/*
 * Ouroboros - Copyright (C) 2016 - 2024
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

#define HASH_FMT32 "%02x%02x%02x%02x"
#define HASH_VAL32(hash)                                  \
        (hash)[0], (hash)[1], (hash)[2], (hash)[3]

#define HASH_FMT64 HASH_FMT32 HASH_FMT32
#define HASH_VAL64(hash64)                                \
        HASH_VAL32(hash64), HASH_VAL32(hash64 + 4)

#define HASH_FMT128 HASH_FMT64 HASH_FMT64
#define HASH_VAL128(hash128)                              \
        HASH_VAL64(hash128), HASH_VAL64(hash128 + 8)

#define HASH_FMT224 HASH_FMT128 HASH_FMT64 HASH_FMT32
#define HASH_VAL224(hash224)                              \
        HASH_VAL128(hash224), HASH_VAL64(hash224 + 16),   \
        HASH_VAL32(hash224 + 24)

#define HASH_FMT256 HASH_FMT128 HASH_FMT128
#define HASH_VAL256(hash256)                              \
        HASH_VAL128(hash256), HASH_VAL128(hash256 + 16)

#define HASH_FMT384 HASH_FMT256 HASH_FMT128
#define HASH_VAL384(hash384)                              \
        HASH_VAL256(hash384), HASH_VAL128(hash384 + 32)

#define HASH_FMT512 HASH_FMT256 HASH_FMT256
#define HASH_VAL512(hash512)                              \
        HASH_VAL256(hash512), HASH_VAL256(hash512 + 32)


uint16_t hash_len(enum hash_algo algo);

void mem_hash(enum hash_algo  algo,
              void *          dst,
              const uint8_t * buf,
              size_t          len);

void str_hash(enum hash_algo algo,
              void *         dst,
              const char *   str);

#endif /* OUROBOROS_LIB_HASH_H */
