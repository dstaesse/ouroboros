/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Hashing
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This implementation is adapted and redistributed from the RHASH
 * project
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#endif

#include "config.h"

#include <ouroboros/hash.h>

#ifndef HAVE_LIBGCRYPT
#include <ouroboros/crc32.h>
#include <ouroboros/md5.h>
#include <ouroboros/sha3.h>
#else
#include <gcrypt.h>
#endif
#include <string.h>
#include <assert.h>
#include <stdbool.h>

uint16_t hash_len(enum hash_algo algo)
{
#ifdef HAVE_LIBGCRYPT
        return (uint16_t) gcry_md_get_algo_dlen(algo);
#else
        switch (algo) {
        case HASH_CRC32:
                return CRC32_HASH_LEN;
        case HASH_MD5:
                return MD5_HASH_LEN;
        case HASH_SHA3_224:
                return SHA3_224_HASH_LEN;
        case HASH_SHA3_256:
                return SHA3_256_HASH_LEN;
        case HASH_SHA3_384:
                return SHA3_384_HASH_LEN;
        case HASH_SHA3_512:
                return SHA3_512_HASH_LEN;
        default:
                assert(false);
                break;
        }

        return 0;
#endif
}

void mem_hash(enum hash_algo  algo,
              void *          dst,
              const uint8_t * buf,
              size_t          len)
{
#ifdef HAVE_LIBGCRYPT
        gcry_md_hash_buffer(algo, dst, buf, len);
#else
        struct sha3_ctx sha3_ctx;
        struct md5_ctx md5_ctx;

        switch (algo) {
        case HASH_CRC32:
                memset(dst, 0, CRC32_HASH_LEN);
                crc32((uint32_t *) dst, buf, len);
                break;
        case HASH_MD5:
                rhash_md5_init(&md5_ctx);
                rhash_md5_update(&md5_ctx, buf, len);
                rhash_md5_final(&md5_ctx, (uint8_t *) dst);
                break;
        case HASH_SHA3_224:
                rhash_sha3_224_init(&sha3_ctx);
                rhash_sha3_update(&sha3_ctx, buf, len);
                rhash_sha3_final(&sha3_ctx, (uint8_t *) dst);
                break;
        case HASH_SHA3_256:
                rhash_sha3_256_init(&sha3_ctx);
                rhash_sha3_update(&sha3_ctx, buf, len);
                rhash_sha3_final(&sha3_ctx, (uint8_t *) dst);
                break;
        case HASH_SHA3_384:
                rhash_sha3_384_init(&sha3_ctx);
                rhash_sha3_update(&sha3_ctx, buf, len);
                rhash_sha3_final(&sha3_ctx, (uint8_t *) dst);
                break;
        case HASH_SHA3_512:
                rhash_sha3_512_init(&sha3_ctx);
                rhash_sha3_update(&sha3_ctx, buf, len);
                rhash_sha3_final(&sha3_ctx, (uint8_t *) dst);
                break;
        default:
                assert(false);
                break;
        }
#endif
}

void str_hash(enum hash_algo algo,
              void *         dst,
              const char *   str)
{
        return mem_hash(algo, dst, (const uint8_t *) str, strlen(str));
}
