/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * SHA3 algorithm
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
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

#define SHA3_224_HASH_LEN         28
#define SHA3_256_HASH_LEN         32
#define SHA3_384_HASH_LEN         48
#define SHA3_512_HASH_LEN         64
#define SHA3_MAX_PERMUTATION_SIZE 25
#define SHA3_MAX_RATE_IN_QWORDS   24

struct sha3_ctx {
        /* 1600 bits algorithm hashing state */
        uint64_t hash[SHA3_MAX_PERMUTATION_SIZE];
        /* 1536-bit buffer for leftovers */
        uint64_t message[SHA3_MAX_RATE_IN_QWORDS];
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
                       const void    *   msg,
                       size_t            size);

void rhash_sha3_final(struct sha3_ctx * ctx,
                      uint8_t *         res);

#endif /* OUROBOROS_LIB_SHA3_H */
