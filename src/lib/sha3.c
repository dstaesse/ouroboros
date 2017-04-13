/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * SHA3 algorithm
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/* sha3.c - an implementation of Secure Hash Algorithm 3 (Keccak).
 * based on the
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * Copyright: 2013 Aleksey Kravchenko <rhash.admin@gmail.com>
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

#include <ouroboros/endian.h>
#include <ouroboros/sha3.h>

#include <assert.h>
#include <string.h>

#define IS_ALIGNED_64(p) (0 == (7 & ((const uint8_t *) (p)      \
                                     - (const uint8_t *) 0)))
#define I64(x) x##LL
#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))

#define NumberOfRounds 24

/* SHA3 (Keccak) constants for 24 rounds */
static uint64_t keccak_round_constants[NumberOfRounds] = {
        I64(0x0000000000000001), I64(0x0000000000008082),
        I64(0x800000000000808A), I64(0x8000000080008000),
        I64(0x000000000000808B), I64(0x0000000080000001),
        I64(0x8000000080008081), I64(0x8000000000008009),
        I64(0x000000000000008A), I64(0x0000000000000088),
        I64(0x0000000080008009), I64(0x000000008000000A),
        I64(0x000000008000808B), I64(0x800000000000008B),
        I64(0x8000000000008089), I64(0x8000000000008003),
        I64(0x8000000000008002), I64(0x8000000000000080),
        I64(0x000000000000800A), I64(0x800000008000000A),
        I64(0x8000000080008081), I64(0x8000000000008080),
        I64(0x0000000080000001), I64(0x8000000080008008)
};

static void rhash_keccak_init(struct sha3_ctx * ctx,
                              unsigned          bits)
{
        /* NB: The Keccak capacity parameter = bits * 2 */
        unsigned rate = 1600 - bits * 2;

        memset(ctx, 0, sizeof(struct sha3_ctx));
        ctx->block_size = rate / 8;
        assert(rate <= 1600 && (rate % 64) == 0);
}

void rhash_sha3_224_init(struct sha3_ctx * ctx)
{
        rhash_keccak_init(ctx, 224);
}

void rhash_sha3_256_init(struct sha3_ctx * ctx)
{
        rhash_keccak_init(ctx, 256);
}
void rhash_sha3_384_init(struct sha3_ctx * ctx)
{
        rhash_keccak_init(ctx, 384);
}

void rhash_sha3_512_init(struct sha3_ctx * ctx)
{
        rhash_keccak_init(ctx, 512);
}

static void keccak_theta(uint64_t * A)
{
        unsigned int x;
        uint64_t C[5];
        uint64_t D[5];

        for (x = 0; x < 5; x++)
                C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];

        D[0] = ROTL64(C[1], 1) ^ C[4];
        D[1] = ROTL64(C[2], 1) ^ C[0];
        D[2] = ROTL64(C[3], 1) ^ C[1];
        D[3] = ROTL64(C[4], 1) ^ C[2];
        D[4] = ROTL64(C[0], 1) ^ C[3];

        for (x = 0; x < 5; x++) {
                A[x]      ^= D[x];
                A[x + 5]  ^= D[x];
                A[x + 10] ^= D[x];
                A[x + 15] ^= D[x];
                A[x + 20] ^= D[x];
        }
}

static void keccak_pi(uint64_t * A)
{
        uint64_t A1;
        A1 = A[1];
        A[ 1] = A[ 6];
        A[ 6] = A[ 9];
        A[ 9] = A[22];
        A[22] = A[14];
        A[14] = A[20];
        A[20] = A[ 2];
        A[ 2] = A[12];
        A[12] = A[13];
        A[13] = A[19];
        A[19] = A[23];
        A[23] = A[15];
        A[15] = A[ 4];
        A[ 4] = A[24];
        A[24] = A[21];
        A[21] = A[ 8];
        A[ 8] = A[16];
        A[16] = A[ 5];
        A[ 5] = A[ 3];
        A[ 3] = A[18];
        A[18] = A[17];
        A[17] = A[11];
        A[11] = A[ 7];
        A[ 7] = A[10];
        A[10] = A1;
        /* note: A[ 0] is left as is */
}

static void keccak_chi(uint64_t * A)
{
        int i;
        for (i = 0; i < 25; i += 5) {
                uint64_t A0 = A[0 + i];
                uint64_t A1 = A[1 + i];
                A[0 + i] ^= ~A1 & A[2 + i];
                A[1 + i] ^= ~A[2 + i] & A[3 + i];
                A[2 + i] ^= ~A[3 + i] & A[4 + i];
                A[3 + i] ^= ~A[4 + i] & A0;
                A[4 + i] ^= ~A0 & A1;
        }
}

static void rhash_sha3_permutation(uint64_t * state)
{
        int round;
        for (round = 0; round < NumberOfRounds; round++) {
                keccak_theta(state);
                /* apply Keccak rho() transformation */
                state[ 1] = ROTL64(state[ 1],  1);
                state[ 2] = ROTL64(state[ 2], 62);
                state[ 3] = ROTL64(state[ 3], 28);
                state[ 4] = ROTL64(state[ 4], 27);
                state[ 5] = ROTL64(state[ 5], 36);
                state[ 6] = ROTL64(state[ 6], 44);
                state[ 7] = ROTL64(state[ 7],  6);
                state[ 8] = ROTL64(state[ 8], 55);
                state[ 9] = ROTL64(state[ 9], 20);
                state[10] = ROTL64(state[10],  3);
                state[11] = ROTL64(state[11], 10);
                state[12] = ROTL64(state[12], 43);
                state[13] = ROTL64(state[13], 25);
                state[14] = ROTL64(state[14], 39);
                state[15] = ROTL64(state[15], 41);
                state[16] = ROTL64(state[16], 45);
                state[17] = ROTL64(state[17], 15);
                state[18] = ROTL64(state[18], 21);
                state[19] = ROTL64(state[19],  8);
                state[20] = ROTL64(state[20], 18);
                state[21] = ROTL64(state[21],  2);
                state[22] = ROTL64(state[22], 61);
                state[23] = ROTL64(state[23], 56);
                state[24] = ROTL64(state[24], 14);

                keccak_pi(state);
                keccak_chi(state);

                /* apply iota(state, round) */
                *state ^= keccak_round_constants[round];
        }
}

static void rhash_sha3_process_block(uint64_t         hash[25],
                                     const uint64_t * block,
                                     size_t           block_size)
{
        /* expanded loop */
        hash[ 0] ^= htole64(block[ 0]);
        hash[ 1] ^= htole64(block[ 1]);
        hash[ 2] ^= htole64(block[ 2]);
        hash[ 3] ^= htole64(block[ 3]);
        hash[ 4] ^= htole64(block[ 4]);
        hash[ 5] ^= htole64(block[ 5]);
        hash[ 6] ^= htole64(block[ 6]);
        hash[ 7] ^= htole64(block[ 7]);
        hash[ 8] ^= htole64(block[ 8]);
        /* if not sha3-512 */
        if (block_size > 72) {
                hash[ 9] ^= htole64(block[ 9]);
                hash[10] ^= htole64(block[10]);
                hash[11] ^= htole64(block[11]);
                hash[12] ^= htole64(block[12]);
                /* if not sha3-384 */
                if (block_size > 104) {
                        hash[13] ^= htole64(block[13]);
                        hash[14] ^= htole64(block[14]);
                        hash[15] ^= htole64(block[15]);
                        hash[16] ^= htole64(block[16]);
                        /* if not sha3-256 */
                        if (block_size > 136) {
                                hash[17] ^= htole64(block[17]);
#ifdef FULL_SHA3_FAMILY_SUPPORT
                                /* if not sha3-224 */
                                if (block_size > 144) {
                                        hash[18] ^= htole64(block[18]);
                                        hash[19] ^= htole64(block[19]);
                                        hash[20] ^= htole64(block[20]);
                                        hash[21] ^= htole64(block[21]);
                                        hash[22] ^= htole64(block[22]);
                                        hash[23] ^= htole64(block[23]);
                                        hash[24] ^= htole64(block[24]);
                                }
#endif
                        }
                }
        }
        /* make a permutation of the hash */
        rhash_sha3_permutation(hash);
}

#define SHA3_FINALIZED 0x80000000

void rhash_sha3_update(struct sha3_ctx * ctx,
                       const void *      pmsg,
                       size_t            size)
{
        size_t idx        = (size_t) ctx->rest;
        size_t block_size = (size_t) ctx->block_size;
        uint8_t * msg     = (uint8_t *) pmsg;

        if (ctx->rest & SHA3_FINALIZED) return;
        ctx->rest = (unsigned) ((ctx->rest + size) % block_size);

        /* fill partial block */
        if (idx) {
                size_t left = block_size - idx;
                memcpy((uint8_t *) ctx->message + idx, msg,
                       (size < left ? size : left));
                if (size < left) return;

                /* process partial block */
                rhash_sha3_process_block(ctx->hash, ctx->message, block_size);
                msg  += left;
                size -= left;
        }

        while (size >= block_size) {
                uint64_t * aligned_message_block;
                if (IS_ALIGNED_64(msg)) {
                        /*
                         * the most common case is processing of an already
                         * aligned message without copying it
                         */
                        aligned_message_block = (uint64_t *) msg;
                } else {
                        memcpy(ctx->message, msg, block_size);
                        aligned_message_block = ctx->message;
                }

                rhash_sha3_process_block(ctx->hash, aligned_message_block,
                                         block_size);
                msg  += block_size;
                size -= block_size;
        }

        if (size)
                memcpy(ctx->message, msg, size);
}

void rhash_sha3_final(struct sha3_ctx * ctx,
                      uint8_t *         res)
{
        size_t       digest_length = 100 - ctx->block_size / 2;
        size_t       digest_words  = digest_length / sizeof(uint64_t);
        const size_t block_size    = ctx->block_size;
        size_t i = 0;

        if (!(ctx->rest & SHA3_FINALIZED)) {
                /* clear the rest of the data queue */
                memset((uint8_t *) ctx->message + ctx->rest, 0,
                       block_size - ctx->rest);
                ((uint8_t *) ctx->message)[ctx->rest] |= 0x06;
                ((uint8_t *) ctx->message)[block_size - 1] |= 0x80;

                /* process final block */
                rhash_sha3_process_block(ctx->hash, ctx->message, block_size);
                ctx->rest = SHA3_FINALIZED;
        }

        assert(block_size > digest_length);

        if (res != NULL) {
                for (i = 0; i < digest_words; i++)
                        ctx->hash[i] = htole64(ctx->hash[i]);

                memcpy(res, ctx->hash, digest_length);
        }
}
