/*
 * Ouroboros - Copyright (C) 2016 - 2017
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
#include <ouroboros/random.h>

#if defined(HAVE_SYS_RANDOM)
#include <sys/random.h>
#elif defined(HAVE_LIBGCRYPT)
#include <grypt.h>
#elif defined(__FreeBSD__)
#include <stdlib.h>
#elif defined(HAVE_OPENSSL)
#include <openssl/rand.h>
#include <limits.h>
#endif

int random_buffer(void * buf,
                  size_t len)
{
#if defined(HAVE_SYS_RANDOM)
        return getrandom(buf, len, GRND_NONBLOCK); /* glibc 2.25 */
#elif defined(HAVE_LIBGCRYPT)
        return gcry_randomize(buf, len, GCRY_STRONG_RANDOM);
#elif defined(__FreeBSD__)
        return arc4random_buf(buf, len);
#elif defined(HAVE_OPENSSL)
        if (len > 0 && len < INT_MAX)
                return RAND_bytes((unsigned char *) buf, (int) len);
        return -1;
#endif
}
