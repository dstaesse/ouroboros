/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Pseudo random generator
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#include "config.h"

#include <ouroboros/random.h>

#if defined(__APPLE__) /* Barf */
#undef __OSX_AVAILABLE
#define __OSX_AVAILABLE(arg)
#undef __IOS_AVAILABLE
#define __IOS_AVAILABLE(arg)
#undef __TVOS_AVAILABLE
#define __TVOS_AVAILABLE(arg)
#undef __WATCHOS_AVAILABLE
#define __WATCHOS_AVAILABLE(arg)
#include <sys/random.h>
#elif defined(HAVE_SYS_RANDOM)
#include <sys/random.h>
#elif defined(HAVE_LIBGCRYPT)
#include <gcrypt.h>
#elif defined(__FreeBSD__)
#include <stdlib.h>
#elif defined(HAVE_OPENSSL_RNG)
#include <openssl/rand.h>
#include <limits.h>
#endif

int random_buffer(void * buf,
                  size_t len)
{
#if defined(__APPLE__)
        return getentropy(buf, len);
#elif defined(__FreeBSD__)
        arc4random_buf(buf, len);
        return 0;
#elif defined(HAVE_SYS_RANDOM)
        return getrandom(buf, len, GRND_NONBLOCK); /* glibc 2.25 */
#elif defined(HAVE_LIBGCRYPT)
        gcry_randomize(buf, len, GCRY_STRONG_RANDOM);
        return 0;
#elif defined(HAVE_OPENSSL_RNG)
        if (len > 0 && len < INT_MAX)
                return RAND_bytes((unsigned char *) buf, (int) len);
        return -1;
#endif
}
