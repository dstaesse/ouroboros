/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Bitmap implementation
 *
 *    Sander Vrijders       <sander.vrijders@intec.ugent.be>
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
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

#define OUROBOROS_PREFIX "bitmap"

#include <ouroboros/bitmap.h>
#include <ouroboros/logs.h>
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

static size_t find_next_zero_bit(const size_t * addr, size_t nbits)
{
        size_t tmp;
        size_t start = 0;
        size_t pos = 0;
        size_t mask;

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
        while (!(tmp & mask)) {
                pos++;
                mask = 1UL << pos;
        }

        return (start * BITS_PER_LONG) + pos;
}

static void bitmap_zero(size_t * dst, size_t nbits)
{
        size_t len = BITS_TO_LONGS(nbits) * sizeof(size_t);
        memset(dst, 0, len);
}

static void bitmap_clear(size_t * map, size_t start)
{
        size_t * p = map + BIT_WORD(start);
        size_t mask = ~(1UL << (start % (BITS_PER_LONG)));

        *p &= mask;
}

static void bitmap_set(size_t * map, size_t start)
{
        size_t * p = map + BIT_WORD(start);
        size_t mask = 1UL << (start % (BITS_PER_LONG));

        *p |= mask;
}

struct bmp {
        ssize_t offset;
        size_t size;

        size_t * bitmap;
};

struct bmp * bmp_create(size_t bits, ssize_t offset)
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

        tmp->size = bits;
        tmp->offset = offset;
        bitmap_zero(tmp->bitmap, bits);

        return tmp;
}

int bmp_destroy(struct bmp * b)
{
        if (b == NULL)
                return -1;

        if (b->bitmap == NULL) {
                free(b);
                return -1;
        }

        free(b->bitmap);
        free(b);

        return 0;
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

static bool is_id_valid(struct bmp * b, ssize_t id)
{
        assert(b);

        if ((id < b->offset) || (id > (ssize_t) (b->offset + b->size)))
                return false;

        return true;
}

bool bmp_is_id_valid(struct bmp * b, ssize_t id)
{
        if (b == NULL)
                return false;

        return is_id_valid(b, id);
}

int bmp_release(struct bmp * b, ssize_t id)
{
        size_t rid;

        if (b == NULL)
                return -1;

        if (!is_id_valid(b, id))
                return -1;

        rid = id - b->offset;

        bitmap_clear(b->bitmap, rid);

        return 0;
}
