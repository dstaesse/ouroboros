/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Bitmap implementation
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#ifndef OUROBOROS_BITMAP_H
#define OUROBOROS_BITMAP_H

#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>

struct bmp;

struct bmp * bmp_create(size_t  bits,
                        ssize_t offset);

int          bmp_destroy(struct bmp * b);

ssize_t      bmp_allocate(struct bmp * instance);

int          bmp_release(struct bmp * instance,
                         ssize_t      id);

bool         bmp_is_id_valid(struct bmp * b,
                             ssize_t      id);

#endif /* OUROBOROS_BITMAP_H */
