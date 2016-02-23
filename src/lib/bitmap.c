/*
 * Ouroboros - Copyright (C) 2016
 *
 * Bitmap implementation - taken partly from Linux kernel
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
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

#include <ouroboros/bitmap.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define BITS_PER_BYTE 8

#define BITS_PER_LONG (sizeof(long) *  BITS_PER_BYTE)

#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#define BITS_TO_LONGS(nr) \
        DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define BITS_IN_BITMAP ((2 << BITS_PER_BYTE) * sizeof(size_t))

static unsigned long find_next_zero_bit(const unsigned long * addr,
                                        unsigned long nbits)
{
        unsigned long tmp;
        unsigned long start = 0;
        unsigned long pos = 0;
        unsigned long mask;

        /* First find correct word */
        tmp = ~addr[start];
        while (!tmp) {
                start++;
                if (start >= (nbits / BITS_PER_LONG))
                        return nbits;

                tmp = ~addr[start];
        }

        /* Find the free bit in the word */
        mask = 1UL;
        while (!(tmp ^ mask)) {
                pos++;
                mask = 1UL << pos;
        }

        return (start * BITS_PER_LONG) + pos;
}

static void bitmap_zero(unsigned long * dst,
                        unsigned int nbits)
{
        unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
        memset(dst, 0, len);
}

static void bitmap_clear(unsigned long * map,
                         unsigned int start)
{
        unsigned long * p = map + BIT_WORD(start);
        unsigned long mask = ~(1UL << (start % (BITS_PER_LONG - 1)));

        *p &= mask;
}


static void bitmap_set(unsigned long * map,
                       unsigned int start)
{
        unsigned long * p = map + BIT_WORD(start);
        unsigned long mask = 1UL << (start % (BITS_PER_LONG - 1));

        *p |= mask;
}

struct rbmp {
        ssize_t offset;
        size_t  size;

        unsigned long bitmap[BITS_TO_LONGS(BITS_IN_BITMAP)];
};

struct rbmp * rbmp_create(size_t bits, ssize_t offset)
{
        struct rbmp * tmp;

        if (bits == 0)
                return NULL;

        tmp = malloc(sizeof(*tmp));
        if (!tmp)
                return NULL;

        tmp->size = bits;
        tmp->offset = offset;
        bitmap_zero(tmp->bitmap, BITS_IN_BITMAP);

        return tmp;
}


int rbmp_destroy(struct rbmp * b)
{
        if (!b)
                return -1;

        free(b);

        return 0;
}

static ssize_t bad_id(struct rbmp * b)
{
        assert(b);

        return b->offset - 1;
}

ssize_t rbmp_allocate(struct rbmp * b)
{
        ssize_t id;

        if (!b)
                return bad_id(b);

        id = (ssize_t) find_next_zero_bit(b->bitmap,
                                          BITS_IN_BITMAP);

        if (id == BITS_IN_BITMAP)
                return bad_id(b);

        bitmap_set(b->bitmap, id);

        return id + b->offset;
}

static bool is_id_ok(struct rbmp * b,
                     ssize_t id)
{
        assert(b);

        if ((id < b->offset) || (id > (b->offset + b->size)))
                return false;

        return true;
}

bool rbmp_is_id_ok(struct rbmp * b,
                   ssize_t id)
{
        if (!b)
                return false;

        return is_id_ok(b, id);
}

int rbmp_release(struct rbmp * b,
                 ssize_t       id)
{
        ssize_t rid;

        if (!b)
                return -1;

        if (!is_id_ok(b, id))
                return -1;

        rid = id - b->offset;

        bitmap_clear(b->bitmap, rid);

        return 0;
}
