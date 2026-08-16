/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Atomic helpers
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

#ifndef OUROBOROS_LIB_ATOMICS_H
#define OUROBOROS_LIB_ATOMICS_H

#define LOAD_RELAXED(p)         (__atomic_load_n(p, __ATOMIC_RELAXED))
#define LOAD_ACQUIRE(p)         (__atomic_load_n(p, __ATOMIC_ACQUIRE))
#define LOAD(p)                 (__atomic_load_n(p, __ATOMIC_SEQ_CST))

#define STORE_RELAXED(p, v)     (__atomic_store_n(p, v, __ATOMIC_RELAXED))
#define STORE_RELEASE(p, v)     (__atomic_store_n(p, v, __ATOMIC_RELEASE))
#define STORE(p, v)             (__atomic_store_n(p, v, __ATOMIC_SEQ_CST))

#define FETCH_ADD_RELAXED(p, v) (__atomic_fetch_add(p, v, __ATOMIC_RELAXED))
#define FETCH_SUB_RELAXED(p, v) (__atomic_fetch_sub(p, v, __ATOMIC_RELAXED))
#define FETCH_ADD(p, v)         (__atomic_fetch_add(p, v, __ATOMIC_SEQ_CST))
#define FETCH_SUB(p, v)         (__atomic_fetch_sub(p, v, __ATOMIC_SEQ_CST))
#define FETCH_OR(p, v)          (__atomic_fetch_or(p, v, __ATOMIC_SEQ_CST))
#define FETCH_AND(p, v)         (__atomic_fetch_and(p, v, __ATOMIC_SEQ_CST))

#endif /* OUROBOROS_LIB_ATOMICS_H */
