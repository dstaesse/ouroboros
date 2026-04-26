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
 * Polynomial: ITU-T V.41 / CCITT-FALSE, CRC-16/IBM-3740.
 *   reveng catalog: https://reveng.sourceforge.io/crc-catalogue
 *
 * Intended for medium-size header check sequences (typ. <= 4 KiB).
 * Hamming distance HD=4 up to 32751 message bits.
 */

#ifndef OUROBOROS_LIB_CRC16_H
#define OUROBOROS_LIB_CRC16_H

#include <stddef.h>
#include <stdint.h>

#define CRC16_HASH_LEN 2

void crc16_ccitt_false(uint16_t *   crc,
                       const void * buf,
                       size_t       len);

#endif /* OUROBOROS_LIB_CRC16_H */
