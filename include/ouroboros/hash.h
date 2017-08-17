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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_HASH_H
#define OUROBOROS_LIB_HASH_H

#include <ouroboros/endian.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif
#include <stdint.h>
#include <stddef.h>

/* Hash algorithms */
enum hash_algo {
#ifdef HAVE_LIBGCRYPT
        HASH_CRC32    = GCRY_MD_CRC32,
        HASH_MD5      = GCRY_MD_MD5,
        HASH_SHA3_224 = GCRY_MD_SHA3_224,
        HASH_SHA3_256 = GCRY_MD_SHA3_256,
        HASH_SHA3_384 = GCRY_MD_SHA3_384,
        HASH_SHA3_512 = GCRY_MD_SHA3_512
#else
        HASH_CRC32 = 0,
        HASH_MD5,
        HASH_SHA3_224,
        HASH_SHA3_256,
        HASH_SHA3_384,
        HASH_SHA3_512
#endif
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
