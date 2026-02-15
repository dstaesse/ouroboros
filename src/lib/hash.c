/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Hashing
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#include <ouroboros/endian.h>
#include <ouroboros/hash.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#else
#include <ouroboros/crc32.h>
#include <ouroboros/md5.h>
#include <ouroboros/sha3.h>
#endif
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#ifdef HAVE_LIBGCRYPT
int gcry_algo_tbl [] = {
        /* DIR_HASH policies first */
        GCRY_MD_SHA3_224,
        GCRY_MD_SHA3_256,
        GCRY_MD_SHA3_384,
        GCRY_MD_SHA3_512,
        /* Below for internal use only */
        GCRY_MD_CRC32,
        GCRY_MD_MD5,
};
#else
int hash_len_tbl [] = {
        /* DIR_HASH policies first */
        SHA3_224_HASH_LEN,
        SHA3_256_HASH_LEN,
        SHA3_384_HASH_LEN,
        SHA3_512_HASH_LEN,
        /* Below for internal use only */
        CRC32_HASH_LEN,
        MD5_HASH_LEN
};
#endif

uint16_t hash_len(enum hash_algo algo)
{
#ifdef HAVE_LIBGCRYPT
        return (uint16_t) gcry_md_get_algo_dlen(gcry_algo_tbl[algo]);
#else
        return hash_len_tbl[algo];
#endif
}

void mem_hash(enum hash_algo  algo,
              void *          dst,
              const uint8_t * buf,
              size_t          len)
{
#ifdef HAVE_LIBGCRYPT
        gcry_md_hash_buffer(gcry_algo_tbl[algo], dst, buf, len);
#else
        struct sha3_ctx sha3_ctx;
        struct md5_ctx md5_ctx;

        switch (algo) {
        case HASH_CRC32:
                memset(dst, 0, CRC32_HASH_LEN);
                crc32((uint32_t *) dst, buf, len);
                *(uint32_t *) dst = htobe32(*(uint32_t *) dst);
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
