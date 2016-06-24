/*
 * Ouroboros - Copyright (C) 2016
 *
 * Ouroboros specific error numbers
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#ifndef OUROBOROS_ERRNO_H
#define OUROBOROS_ERRNO_H

#include <errno.h>

#define ENOTALLOC    1000 /* Flow is not allocated */
#define EIPCPTYPE    1001 /* Unknown IPCP type */

#endif
