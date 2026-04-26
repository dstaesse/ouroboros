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
 * Polynomial: AUTOSAR SWS_CRC, CRC-8/AUTOSAR.
 *   reveng catalog: https://reveng.sourceforge.io/crc-catalogue
 *
 * Intended for short header check sequences (typ. <= 32 bytes).
 * Hamming distance HD=4 up to 119 message bits, HD=3 up to 247.
 */

#ifndef OUROBOROS_LIB_CRC8_H
#define OUROBOROS_LIB_CRC8_H

#include <stddef.h>
#include <stdint.h>

#define CRC8_HASH_LEN 1

void crc8_autosar(uint8_t *    crc,
                  const void * buf,
                  size_t       len);

#endif /* OUROBOROS_LIB_CRC8_H */
