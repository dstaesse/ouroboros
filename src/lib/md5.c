/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * MD5 algorithm
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
 *
 *    -- original license
 *
 * md5.c - an implementation of the MD5 algorithm, based on RFC 1321.
 *
 * Copyright: 2007-2012 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#endif

#include <ouroboros/endian.h>
#include <ouroboros/md5.h>

#include <assert.h>
#include <string.h>

#define ROTL32(dword, n) ((dword) << (n) ^ ((dword) >> (32 - (n))))

void rhash_md5_init(struct md5_ctx *ctx)
{
        ctx->length = 0;

        /* initialize state */
        ctx->hash[0] = 0x67452301;
        ctx->hash[1] = 0xefcdab89;
        ctx->hash[2] = 0x98badcfe;
        ctx->hash[3] = 0x10325476;
}

#define MD5_F(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

/* transformations for rounds 1, 2, 3, and 4. */
#define MD5_ROUND1(a, b, c, d, x, s, ac) { \
        (a) += MD5_F((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
}

#define MD5_ROUND2(a, b, c, d, x, s, ac) {        \
        (a) += MD5_G((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
}

#define MD5_ROUND3(a, b, c, d, x, s, ac) {        \
        (a) += MD5_H((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
}

#define MD5_ROUND4(a, b, c, d, x, s, ac) {        \
        (a) += MD5_I((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
}

static void le32_copy(void *       to,
                      int          index,
                      const void * from,
                      size_t       length)
{
        const uint32_t * src = (const uint32_t *) from;
        const uint32_t * end = (const uint32_t *) ((const uint8_t *)
                                                   src + length);
        uint32_t * dst = (uint32_t *)((uint8_t *) to + index);
        while (src < end)
                *(dst++) = htole32(*(src++));
}

static void rhash_md5_process_block(uint32_t *       state,
                                    const unsigned * x)
{
        register uint32_t a = state[0];
        register uint32_t b = state[1];
        register uint32_t c = state[2];
        register uint32_t d = state[3];

        MD5_ROUND1(a, b, c, d, x[ 0],  7, 0xd76aa478);
        MD5_ROUND1(d, a, b, c, x[ 1], 12, 0xe8c7b756);
        MD5_ROUND1(c, d, a, b, x[ 2], 17, 0x242070db);
        MD5_ROUND1(b, c, d, a, x[ 3], 22, 0xc1bdceee);
        MD5_ROUND1(a, b, c, d, x[ 4],  7, 0xf57c0faf);
        MD5_ROUND1(d, a, b, c, x[ 5], 12, 0x4787c62a);
        MD5_ROUND1(c, d, a, b, x[ 6], 17, 0xa8304613);
        MD5_ROUND1(b, c, d, a, x[ 7], 22, 0xfd469501);
        MD5_ROUND1(a, b, c, d, x[ 8],  7, 0x698098d8);
        MD5_ROUND1(d, a, b, c, x[ 9], 12, 0x8b44f7af);
        MD5_ROUND1(c, d, a, b, x[10], 17, 0xffff5bb1);
        MD5_ROUND1(b, c, d, a, x[11], 22, 0x895cd7be);
        MD5_ROUND1(a, b, c, d, x[12],  7, 0x6b901122);
        MD5_ROUND1(d, a, b, c, x[13], 12, 0xfd987193);
        MD5_ROUND1(c, d, a, b, x[14], 17, 0xa679438e);
        MD5_ROUND1(b, c, d, a, x[15], 22, 0x49b40821);

        MD5_ROUND2(a, b, c, d, x[ 1],  5, 0xf61e2562);
        MD5_ROUND2(d, a, b, c, x[ 6],  9, 0xc040b340);
        MD5_ROUND2(c, d, a, b, x[11], 14, 0x265e5a51);
        MD5_ROUND2(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
        MD5_ROUND2(a, b, c, d, x[ 5],  5, 0xd62f105d);
        MD5_ROUND2(d, a, b, c, x[10],  9,  0x2441453);
        MD5_ROUND2(c, d, a, b, x[15], 14, 0xd8a1e681);
        MD5_ROUND2(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
        MD5_ROUND2(a, b, c, d, x[ 9],  5, 0x21e1cde6);
        MD5_ROUND2(d, a, b, c, x[14],  9, 0xc33707d6);
        MD5_ROUND2(c, d, a, b, x[ 3], 14, 0xf4d50d87);
        MD5_ROUND2(b, c, d, a, x[ 8], 20, 0x455a14ed);
        MD5_ROUND2(a, b, c, d, x[13],  5, 0xa9e3e905);
        MD5_ROUND2(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
        MD5_ROUND2(c, d, a, b, x[ 7], 14, 0x676f02d9);
        MD5_ROUND2(b, c, d, a, x[12], 20, 0x8d2a4c8a);

        MD5_ROUND3(a, b, c, d, x[ 5],  4, 0xfffa3942);
        MD5_ROUND3(d, a, b, c, x[ 8], 11, 0x8771f681);
        MD5_ROUND3(c, d, a, b, x[11], 16, 0x6d9d6122);
        MD5_ROUND3(b, c, d, a, x[14], 23, 0xfde5380c);
        MD5_ROUND3(a, b, c, d, x[ 1],  4, 0xa4beea44);
        MD5_ROUND3(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
        MD5_ROUND3(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
        MD5_ROUND3(b, c, d, a, x[10], 23, 0xbebfbc70);
        MD5_ROUND3(a, b, c, d, x[13],  4, 0x289b7ec6);
        MD5_ROUND3(d, a, b, c, x[ 0], 11, 0xeaa127fa);
        MD5_ROUND3(c, d, a, b, x[ 3], 16, 0xd4ef3085);
        MD5_ROUND3(b, c, d, a, x[ 6], 23,  0x4881d05);
        MD5_ROUND3(a, b, c, d, x[ 9],  4, 0xd9d4d039);
        MD5_ROUND3(d, a, b, c, x[12], 11, 0xe6db99e5);
        MD5_ROUND3(c, d, a, b, x[15], 16, 0x1fa27cf8);
        MD5_ROUND3(b, c, d, a, x[ 2], 23, 0xc4ac5665);

        MD5_ROUND4(a, b, c, d, x[ 0],  6, 0xf4292244);
        MD5_ROUND4(d, a, b, c, x[ 7], 10, 0x432aff97);
        MD5_ROUND4(c, d, a, b, x[14], 15, 0xab9423a7);
        MD5_ROUND4(b, c, d, a, x[ 5], 21, 0xfc93a039);
        MD5_ROUND4(a, b, c, d, x[12],  6, 0x655b59c3);
        MD5_ROUND4(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
        MD5_ROUND4(c, d, a, b, x[10], 15, 0xffeff47d);
        MD5_ROUND4(b, c, d, a, x[ 1], 21, 0x85845dd1);
        MD5_ROUND4(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
        MD5_ROUND4(d, a, b, c, x[15], 10, 0xfe2ce6e0);
        MD5_ROUND4(c, d, a, b, x[ 6], 15, 0xa3014314);
        MD5_ROUND4(b, c, d, a, x[13], 21, 0x4e0811a1);
        MD5_ROUND4(a, b, c, d, x[ 4],  6, 0xf7537e82);
        MD5_ROUND4(d, a, b, c, x[11], 10, 0xbd3af235);
        MD5_ROUND4(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
        MD5_ROUND4(b, c, d, a, x[ 9], 21, 0xeb86d391);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
}

void rhash_md5_update(struct md5_ctx * ctx,
                      const void *     pmsg,
                      size_t           size)
{
        uint8_t * msg   = (uint8_t *) pmsg;
        uint64_t  index = ctx->length & 63;

        ctx->length += size;

        /* fill partial block */
        if (index) {
                size_t left = MD5_BLOCK_SIZE - index;

                le32_copy((uint8_t *) ctx->message, index, msg,
                          (size < left ? size : left));

                if (size < left)
                        return;

                /* process partial block */
                rhash_md5_process_block(ctx->hash, ctx->message);
                msg  += left;
                size -= left;
        }

        while (size >= MD5_BLOCK_SIZE) {
                uint32_t * aligned_message_block;

                le32_copy(ctx->message, 0, msg, MD5_BLOCK_SIZE);
                aligned_message_block = ctx->message;

                rhash_md5_process_block(ctx->hash, aligned_message_block);
                msg  += MD5_BLOCK_SIZE;
                size -= MD5_BLOCK_SIZE;
        }

        if (size)
                /* save leftovers */
                le32_copy(ctx->message, 0, msg, size);
}

void rhash_md5_final(struct md5_ctx * ctx,
                     uint8_t *        result)
{
        uint64_t index = (ctx->length & 63) >> 2;
        uint64_t shift = (ctx->length & 3) * 8;

        ctx->message[index]   &= ~(0xFFFFFFFF << shift);
        ctx->message[index++] ^= 0x80 << shift;

        if (index > 14) {
                while (index < 16)
                        ctx->message[index++] = 0;

                rhash_md5_process_block(ctx->hash, ctx->message);
                index = 0;
        }

        while (index < 14)
                ctx->message[index++] = 0;

        ctx->message[14] = (uint32_t) (ctx->length << 3);
        ctx->message[15] = (uint32_t) (ctx->length >> 29);
        rhash_md5_process_block(ctx->hash, ctx->message);

        if (result)
                le32_copy(result, 0, &ctx->hash, 16);
}
