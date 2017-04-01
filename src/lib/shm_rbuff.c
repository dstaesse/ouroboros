/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Ring buffer implementations for incoming SDUs
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

#if ((SHM_RBUFF_LOCKLESS > 0) &&                        \
     (defined(__GNUC__) || defined (__clang__)))
#include "shm_rbuff_ll.c"
#else
#include "shm_rbuff_pthr.c"
#endif
