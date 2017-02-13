/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Endianness
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

/*
 * byte_order.h - byte order related platform dependent routines,
 *
 * Copyright: 2008-2012 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */

#ifndef OUROBOROS_ENDIAN_H
#define OUROBOROS_ENDIAN_H

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

#ifdef __GLIBC__
#include <endian.h>
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#endif

/* if x86 compatible cpu */
#if defined(i386) || defined(__i386__) || defined(__i486__) || \
        defined(__i586__) || defined(__i686__) || defined(__pentium__) || \
        defined(__pentiumpro__) || defined(__pentium4__) ||             \
        defined(__nocona__) || defined(prescott) || defined(__core2__) || \
        defined(__k6__) || defined(__k8__) || defined(__athlon__) ||    \
        defined(__amd64) || defined(__amd64__) ||                       \
        defined(__x86_64) || defined(__x86_64__) || defined(_M_IX86) || \
        defined(_M_AMD64) || defined(_M_IA64) || defined(_M_X64)
/* detect if x86-64 instruction set is supported */
# if defined(_LP64) || defined(__LP64__) || defined(__x86_64) || \
        defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#  define CPU_X64
# else
#  define CPU_IA32
# endif
#endif

/* detect CPU endianness */
#if (defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && \
     __BYTE_ORDER == __LITTLE_ENDIAN) ||                  \
        defined(CPU_IA32) || defined(CPU_X64) ||                        \
        defined(__ia64) || defined(__ia64__) || defined(__alpha__) ||   \
        defined(_M_ALPHA) || defined(vax) || defined(MIPSEL) ||         \
        defined(_ARM_) || defined(__arm__)
#define CPU_LITTLE_ENDIAN
#define IS_BIG_ENDIAN 0
#define IS_LITTLE_ENDIAN 1
#elif (defined(__BYTE_ORDER) && defined(__BIG_ENDIAN) &&                \
       __BYTE_ORDER == __BIG_ENDIAN) ||                                 \
        defined(__sparc) || defined(__sparc__) || defined(sparc) ||     \
        defined(_ARCH_PPC) || defined(_ARCH_PPC64) || defined(_POWER) || \
        defined(__POWERPC__) || defined(POWERPC) || defined(__powerpc) || \
        defined(__powerpc__) || defined(__powerpc64__) || defined(__ppc__) || \
        defined(__hpux)  || defined(_MIPSEB) || defined(mc68000) ||     \
        defined(__s390__) || defined(__s390x__) || defined(sel)
#define CPU_BIG_ENDIAN
#define IS_BIG_ENDIAN 1
#define IS_LITTLE_ENDIAN 0
#else
# error "Can't detect CPU architecture."
#endif

#if defined(__GNUC__)  && (__GNUC__ >= 4) &&  \
        (__GNUC__ > 4 || __GNUC_MINOR__ >= 3)
/* for GCC >= 4.3 */
#define bswap_32(x) __builtin_bswap32(x)
#elif !defined(__STRICT_ANSI__)
/* general bswap_32 definition */
static inline uint32_t bswap_32(uint32_t x) {
        x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0x00FF00FF);
        return (x >> 16) | (x << 16);
}
#else
#define bswap_32(x) ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
                     (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif /* bswap_32 */

#if defined(__GNUC__) && (__GNUC__ >= 4) && \
        (__GNUC__ > 4 || __GNUC_MINOR__ >= 3)
#define bswap_64(x) __builtin_bswap64(x)
#elif defined (bswap64)
#define bswap_64 bswap64
#else
#if !defined(__STRICT_ANSI__)
static inline uint64_t bswap_64(uint64_t x) {
        union {
                uint64_t ll;
                uint32_t l[2];
        } w, r;
        w.ll = x;
        r.l[0] = bswap_32(w.l[1]);
        r.l[1] = bswap_32(w.l[0]);
        return r.ll;
}
#else
#error "bswap_64 unsupported"
#endif
#endif

#ifdef CPU_LITTLE_ENDIAN
#define hton64(x) bswap_64(x)
#define hton32(x) bswap_32(x)
#define ntoh64(x) bswap_64(x)
#define ntoh32(x) bswap_32(x)
#else /* CPU_LITTLE_ENDIAN */
#define hton64(x) (x)
#define hton32(x) (x)
#define ntoh64(x) (x)
#define noth32(x) (x)
#endif /* CPU_LITTLE_ENDIAN */

#endif /* OUROBOROS_ENDIAN_H */
