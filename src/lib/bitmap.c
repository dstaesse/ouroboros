/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Bitmap implementation
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
        struct bmp * bmp;

        assert(bits);

        bmp = malloc(sizeof(*bmp));
        if (bmp == NULL)
                return NULL;

        bmp->bitmap = malloc(BITS_TO_LONGS(bits) * sizeof(size_t));
        if (bmp->bitmap == NULL) {
                free(bmp);
                return NULL;
        }

        bmp->size   = bits;
        bmp->offset = offset;
        bitmap_zero(bmp->bitmap, bits);

        return bmp;
}

void bmp_destroy(struct bmp * bmp)
{
        assert(bmp);

        if (bmp->bitmap != NULL)
                free(bmp->bitmap);

        free(bmp);
}

static ssize_t bad_id(struct bmp * bmp)
{
        assert(bmp);

        return bmp->offset - 1;
}

ssize_t bmp_allocate(struct bmp * bmp)
{
        size_t id;

        assert(bmp);

        id = find_next_zero_bit(bmp->bitmap, bmp->size);
        if (id >= bmp->size)
                return bad_id(bmp);

        bitmap_set(bmp->bitmap, id);

        return id + bmp->offset;
}

static bool is_id_valid(struct bmp * bmp,
                        ssize_t      id)
{
        assert(bmp);

        if ((id < bmp->offset) || (id > (ssize_t) (bmp->offset + bmp->size)))
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

bool bmp_is_id_valid(struct bmp * bmp,
                     ssize_t      id)
{
        assert(bmp);

        return is_id_valid(bmp, id);
}

int bmp_release(struct bmp * bmp,
                ssize_t      id)
{
        assert(bmp);

        if (!is_id_valid(bmp, id))
                return -1;

        bitmap_clear(bmp->bitmap, id - bmp->offset);

        return 0;
}

bool bmp_is_id_used(struct bmp * bmp,
                    ssize_t      id)
{
        assert(bmp);

        return is_id_used(bmp->bitmap, id - bmp->offset);
}
