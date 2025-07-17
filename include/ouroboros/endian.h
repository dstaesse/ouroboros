/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Endianness
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

#ifndef OUROBOROS_LIB_ENDIAN_H
#define OUROBOROS_LIB_ENDIAN_H

#if defined(__linux__) || defined(__CYGWIN__) || \
        (defined(__MACH__) && !defined(__APPLE__))
#ifndef _DEFAULT_SOURCE
#error You must define _DEFAULT_SOURCE before including this file
#endif
#include <endian.h>
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#else
#error OS currently not supported
#endif

#if defined (__APPLE__)

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define betoh16(x) OSSwapBigToHostInt16(x)
#define letoh16(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define betoh32(x) OSSwapBigToHostInt32(x)
#define letoh32(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define betoh64(x) OSSwapBigToHostInt64(x)
#define letoh64(x) OSSwapLittleToHostInt64(x)

#elif !defined(__OpenBSD__)

#define betoh16(x) be16toh(x)
#define letoh16(x) le16toh(x)
#define betoh32(x) be32toh(x)
#define letoh32(x) le32toh(x)
#define betoh64(x) be64toh(x)
#define letoh64(x) le64toh(x)

#endif

#define hton64(x) htobe64(x)
#define ntoh64(x) betoh64(x)
#define hton32(x) htobe32(x)
#define ntoh32(x) betoh32(x)
#define hton16(x) htobe16(x)
#define ntoh16(x) betoh16(x)

#endif /* OUROBOROS_LIB_ENDIAN_H */
