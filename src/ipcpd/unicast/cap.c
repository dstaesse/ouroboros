/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Link capacity codes
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

/*
 * Rate <-> 8-bit code (cap_enc / cap_dec): the high 6 bits hold a
 * band e = floor(log2 rate), the low 2 a quarter k splitting the
 * band at 256 * 2^(k/4) = {256, 304, 362, 431}; code = 4 * e + k.
 * Capacity is only ever needed to order-of-magnitude accuracy.
 */

#include "cap.h"

uint8_t cap_enc(uint64_t rate)
{
        static const uint16_t thr[3] = {304, 362, 431};
        uint64_t r = rate;         /* copy halved to find band  */
        unsigned e = 0;            /* band: floor log2 rate     */
        unsigned k = 0;            /* quarter within band 0..3  */
        unsigned c;                /* code = 4 * band + quarter */
        uint16_t top;              /* rate scaled to [256, 512) */

        if (rate == 0)
                return 0;

        while (r > 1) {
                r >>= 1;
                e++;
        }

        if (e >= 8)
                top = (uint16_t) (rate >> (e - 8));
        else
                top = (uint16_t) (rate << (8 - e));

        while (k < 3 && top >= thr[k])
                k++;

        c = 4 * e + k;
        if (c == 0)
                c = 1; /* 0 means unknown */

        return (uint8_t) c;
}

uint64_t cap_dec(uint8_t c)
{
        static const uint16_t m[4] = {256, 304, 362, 431};
        unsigned e = c >> 2;       /* band = c >> 2   */
        unsigned k = c & 3;        /* quarter = c & 3 */

        if (c == 0)
                return 0;

        if (e >= 8)
                return (uint64_t) m[k] << (e - 8);

        return ((uint64_t) m[k] << e) >> 8;
}

uint8_t cap_min(uint8_t a,
                uint8_t b)
{
        if (a == 0)
                return b;

        if (b == 0)
                return a;

        return a < b ? a : b;
}

void cap_stamp(uint8_t * pci,
               uint8_t   own)
{
        if (own == 0)
                return;

        if (*pci == 0 || own < *pci)
                *pci = own;
}
