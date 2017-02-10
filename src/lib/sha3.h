/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * SHA3 algorithm
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This implementation is adapted and redistributed from the RHASH
 * project implementation of the sha3 algorithm
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
 *
 *    -- original license
 *
 * sha3.c - an implementation of Secure Hash Algorithm 3 (Keccak).
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

#ifndef OUROBOROS_LIB_SHA3_H
#define OUROBOROS_LIB_SHA3_H

#include <unistd.h>
#include <stdint.h>

#define sha3_224_hash_size        28
#define sha3_256_hash_size        32
#define sha3_384_hash_size        48
#define sha3_512_hash_size        64
#define sha3_max_permutation_size 25
#define sha3_max_rate_in_qwords   24

struct sha3_ctx {
        /* 1600 bits algorithm hashing state */
        uint64_t hash[sha3_max_permutation_size];
        /* 1536-bit buffer for leftovers */
        uint64_t message[sha3_max_rate_in_qwords];
        /* count of bytes in the message[] buffer */
        unsigned rest;
        /* size of a message block processed at once */
        unsigned block_size;
};

void rhash_sha3_224_init(struct sha3_ctx * ctx);

void rhash_sha3_256_init(struct sha3_ctx * ctx);

void rhash_sha3_384_init(struct sha3_ctx * ctx);

void rhash_sha3_512_init(struct sha3_ctx * ctx);

void rhash_sha3_update(struct sha3_ctx * ctx,
                       const uint8_t *   msg,
                       size_t            size);

void rhash_sha3_final(struct sha3_ctx * ctx,
                      uint8_t *         res);

#endif /* OUROBOROS_LIB_SHA3_H */