/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * MD5 algorithm
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This implementation is adapted and redistributed from the RHASH
 * project implementation of the MD5 algorithm
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

#ifndef OUROBOROS_LIB_MD5_H
#define OUROBOROS_LIB_MD5_H

#include "unistd.h"
#include <stdint.h>

#define MD5_BLOCK_SIZE 64
#define MD5_HASH_LEN   16

struct md5_ctx
{
        /* 512-bit buffer for leftovers */
        uint32_t message[MD5_BLOCK_SIZE / 4];
        /* number of processed bytes */
        uint64_t length;
        /* 128-bit algorithm internal hashing state */
        uint32_t hash[4];
};

void rhash_md5_init(struct md5_ctx *ctx);

void rhash_md5_update(struct md5_ctx * ctx,
                      const void *     msg,
                      size_t           size);

void rhash_md5_final(struct md5_ctx * ctx,
                     uint8_t *        result);

#endif /* OUROBOROS_LIB_MD5_H */
