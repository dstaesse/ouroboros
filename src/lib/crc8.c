/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * 8-bit Cyclic Redundancy Check (AUTOSAR variant)
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
 * CRC-8/AUTOSAR (reveng catalog):
 *   poly   = 0x2f
 *   init   = 0xff
 *   refin  = false
 *   refout = false
 *   xorout = 0xff
 *   check  = crc8_autosar("123456789") == 0xdf
 */

#include "config.h"

#include <ouroboros/crc8.h>

/* Bit-by-bit MSB-first CRC.  The expected use case is header check
 * sequences of a handful of bytes; a 256-byte lookup table would not
 * pay for the extra .rodata footprint at typical input sizes.
 */
void crc8_autosar(uint8_t *    crc,
                  const void * buf,
                  size_t       len)
{
        const uint8_t * p;
        uint8_t         c;
        size_t          n;
        int             i;

        p = (const uint8_t *) buf;
        c = *crc ^ 0xff;

        for (n = 0; n < len; n++) {
                c ^= p[n];
                for (i = 0; i < 8; i++) {
                        if (c & 0x80)
                                c = (uint8_t) ((c << 1) ^ 0x2f);
                        else
                                c = (uint8_t) (c << 1);
                }
        }

        *crc = c ^ 0xff;
}
