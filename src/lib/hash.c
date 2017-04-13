/*
 * Ouroboros - Copyright (C) 2016 - 2017
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
#include <ouroboros/hash.h>

#include <string.h>

void get_hash(uint8_t      buf[],
              const char * name)
{
        /* currently we only support 256 bit SHA-3 */
        struct sha3_ctx ctx;

        rhash_sha3_256_init(&ctx);

        rhash_sha3_update(&ctx, name, strlen(name));

        rhash_sha3_final(&ctx, buf);
}
