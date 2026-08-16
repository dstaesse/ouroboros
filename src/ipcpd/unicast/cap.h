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

#ifndef OUROBOROS_IPCPD_UNICAST_CAP_H
#define OUROBOROS_IPCPD_UNICAST_CAP_H

#include <stdint.h>

/* Quarter-log2 capacity code: ~2^(c / 4) bytes/s, 0 = unknown. */
uint8_t  cap_enc(uint64_t rate);

uint64_t cap_dec(uint8_t c);

uint8_t  cap_min(uint8_t a,
                 uint8_t b);

/* MIN-combine the own link code into the PCI byte. */
void     cap_stamp(uint8_t * pci,
                   uint8_t   own);

#endif /* OUROBOROS_IPCPD_UNICAST_CAP_H */
