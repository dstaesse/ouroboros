/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Bitmap implementation
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

#include <ouroboros/bitmap.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define BITS_PER_BYTE CHAR_BIT

#define BITS_PER_LONG (sizeof(size_t) *  BITS_PER_BYTE)

#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#define BITS_TO_LONGS(nr) \
        DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(size_t))

static size_t find_next_zero_bit(const size_t * addr,
                                 size_t         nbits)
{
        size_t tmp;
        size_t start = 0;
        size_t pos = 0;
        size_t mask;

        /* First find correct word */
        tmp = ~addr[start];
        while (!tmp) {
                start++;
                if (start >= DIV_ROUND_UP(nbits, BITS_PER_LONG))
                        return nbits;

                tmp = ~addr[start];
        }

        /* Find the free bit in the word */
        mask = 1UL;
        while (!(tmp & mask)) {
                pos++;
                mask = 1UL << pos;
        }

        return (start * BITS_PER_LONG) + pos;
}

static void bitmap_zero(size_t * dst,
                        size_t   nbits)
{
        memset(dst, 0, BITS_TO_LONGS(nbits) * sizeof(size_t));
}

static void bitmap_clear(size_t * map,
                         size_t   start)
{
        size_t * p = map + BIT_WORD(start);
        size_t mask = ~(1UL << (start % (BITS_PER_LONG)));

        *p &= mask;
}

static void bitmap_set(size_t * map,
                       size_t   start)
{
        size_t * p = map + BIT_WORD(start);
        size_t mask = 1UL << (start % (BITS_PER_LONG));

        *p |= mask;
}

struct bmp {
        ssize_t  offset;
        size_t   size;

        size_t * bitmap;
};

struct bmp * bmp_create(size_t  bits,
                        ssize_t offset)
{
        struct bmp * tmp;

        if (bits == 0)
                return NULL;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        tmp->bitmap = malloc(BITS_TO_LONGS(bits) * sizeof(size_t));
        if (tmp->bitmap == NULL) {
                free(tmp);
                return NULL;
        }

        tmp->size   = bits;
        tmp->offset = offset;
        bitmap_zero(tmp->bitmap, bits);

        return tmp;
}

void bmp_destroy(struct bmp * b)
{
        if (b == NULL)
                return;

        if (b->bitmap != NULL)
                free(b->bitmap);

        free(b);
}

static ssize_t bad_id(struct bmp * b)
{
        if (b == NULL)
                return -1;

        return b->offset - 1;
}

ssize_t bmp_allocate(struct bmp * b)
{
        size_t id;

        if (b == NULL)
                return -1;

        id = find_next_zero_bit(b->bitmap, b->size);
        if (id >= b->size)
                return bad_id(b);

        bitmap_set(b->bitmap, id);

        return id + b->offset;
}

static bool is_id_valid(struct bmp * b,
                        ssize_t      id)
{
        assert(b);

        if ((id < b->offset) || (id > (ssize_t) (b->offset + b->size)))
                return false;

        return true;
}

static bool is_id_used(size_t * map,
                       size_t   start)
{
        size_t * p = map + BIT_WORD(start);
        size_t mask = 1UL << (start % (BITS_PER_LONG));

        return (*p & mask) != 0;
}

bool bmp_is_id_valid(struct bmp * b,
                     ssize_t      id)
{
        if (b == NULL)
                return false;

        return is_id_valid(b, id);
}

int bmp_release(struct bmp * b,
                ssize_t      id)
{
        if (b == NULL)
                return -1;

        if (!is_id_valid(b, id))
                return -1;

        bitmap_clear(b->bitmap, id - b->offset);

        return 0;
}

bool bmp_is_id_used(struct bmp * b,
                    ssize_t      id)
{
        if (b == NULL)
                return false;

        return is_id_used(b->bitmap, id - b->offset);
}
