/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Byte order routines for SHA3 function
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

#ifndef OUROBOROS_BYTE_ORDER_H
#define OUROBOROS_BYTE_ORDER_H

#include <ouroboros/endian.h>

#define IS_ALIGNED_32(p) (0 == (3 & ((const char*)(p) - (const char*)0)))
#define IS_ALIGNED_64(p) (0 == (7 & ((const char*)(p) - (const char*)0)))

#if defined(__GNUC__)
#define ALIGN_ATTR(n) __attribute__((aligned (n)))
#else
#define ALIGN_ATTR(n) /* nothing */
#endif

#define I64(x) x##LL

/* convert a hash flag to index */
#if __GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4) /* GCC < 3.4 */
#define rhash_ctz(x) __builtin_ctz(x)
#else
unsigned rhash_ctz(unsigned); /* define as function */
#endif

#ifdef CPU_BIG_ENDIAN
#define be2me_32(x) (x)
#define be2me_64(x) (x)
#define le2me_32(x) bswap_32(x)
#define le2me_64(x) bswap_64(x)

#define be32_copy(to, index, from, length) \
        memcpy((to) + (index), (from), (length))
#define le32_copy(to, index, from, length) \
        rhash_swap_copy_str_to_u32((to), (index), (from), (length))
#define be64_copy(to, index, from, length) \
        memcpy((to) + (index), (from), (length))
#define le64_copy(to, index, from, length) \
        rhash_swap_copy_str_to_u64((to), (index), (from), (length))
#define me64_to_be_str(to, from, length) \
        memcpy((to), (from), (length))
#define me64_to_le_str(to, from, length) \
        rhash_swap_copy_u64_to_str((to), (from), (length))

#else /* CPU_BIG_ENDIAN */
#define be2me_32(x) bswap_32(x)
#define be2me_64(x) bswap_64(x)
#define le2me_32(x) (x)
#define le2me_64(x) (x)

#define be32_copy(to, index, from, length) \
        rhash_swap_copy_str_to_u32((to), (index), (from), (length))
#define le32_copy(to, index, from, length) \
        memcpy((to) + (index), (from), (length))
#define be64_copy(to, index, from, length) \
        rhash_swap_copy_str_to_u64((to), (index), (from), (length))
#define le64_copy(to, index, from, length) \
        memcpy((to) + (index), (from), (length))
#define me64_to_be_str(to, from, length) \
        rhash_swap_copy_u64_to_str((to), (from), (length))
#define me64_to_le_str(to, from, length) \
        memcpy((to), (from), (length))
#endif /* CPU_BIG_ENDIAN */

/* ROTL/ROTR macros rotate a 32/64-bit word left/right by n bits */
#define ROTL32(dword, n) ((dword) << (n) ^ ((dword) >> (32 - (n))))
#define ROTR32(dword, n) ((dword) >> (n) ^ ((dword) << (32 - (n))))
#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))
#define ROTR64(qword, n) ((qword) >> (n) ^ ((qword) << (64 - (n))))

#endif /* OUROBOROS_BYTE_ORDER_H */
