/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * 16-bit Cyclic Redundancy Check (CCITT-FALSE variant)
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

/*
 * CRC-16/CCITT-FALSE (reveng catalog, alias CRC-16/IBM-3740):
 *   poly   = 0x1021
 *   init   = 0xffff
 *   refin  = false
 *   refout = false
 *   xorout = 0x0000
 *   check  = crc16_ccitt_false("123456789") == 0x29b1
 */

#include "config.h"

#include <ouroboros/crc16.h>

/*  Bit-by-bit MSB-first CRC. */
void crc16_ccitt_false(uint16_t *   crc,
                       const void * buf,
                       size_t       len)
{
        const uint8_t * p;
        uint16_t        c;
        size_t          n;
        int             i;

        p = (const uint8_t *) buf;
        c = *crc ^ 0xffff;

        for (n = 0; n < len; n++) {
                c ^= ((uint16_t) p[n]) << 8;
                for (i = 0; i < 8; i++) {
                        if (c & 0x8000)
                                c = (uint16_t) ((c << 1) ^ 0x1021);
                        else
                                c = (uint16_t) (c << 1);
                }
        }

        *crc = c;
}
