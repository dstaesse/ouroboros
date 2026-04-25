/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * 64-bit Cyclic Redundancy Check (NVMe variant)
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
 * Polynomial: NVM Express Base Spec, CRC-64/NVMe.
 *   reveng catalog: https://reveng.sourceforge.io/crc-catalogue
 *
 * Fold-by-N (PCLMUL/PMULL) algorithm:
 *   V. Gopal et al., "Fast CRC Computation for Generic Polynomials
 *   Using PCLMULQDQ", Intel white paper, 2009.
 */

#ifndef OUROBOROS_LIB_CRC64_H
#define OUROBOROS_LIB_CRC64_H

#include <stddef.h>
#include <stdint.h>

#define CRC64_HASH_LEN 8

void crc64_nvme(uint64_t *   crc,
                const void * buf,
                size_t       len);

#endif /* OUROBOROS_LIB_CRC64_H */
