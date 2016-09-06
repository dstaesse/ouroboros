/*
 * Ouroboros - Copyright (C) 2016
 *
 * 32-bit Cyclic Redundancy Check
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef OUROBOROS_IPCP_CRC32_H
#define OUROBOROS_IPCP_CRC32_H

#include <stdint.h>

void crc32(uint32_t * crc, const uint8_t * buf, size_t len);

#endif /* OUROBOROS_IPCP_CRC32_H */
