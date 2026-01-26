/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * N+1 flow pool tracking for IPCPs
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_IPCPD_NP1_H
#define OUROBOROS_IPCPD_NP1_H

#include "config.h"

#include <ouroboros/ssm_pool.h>

#define NP1_LOAD(ptr)       (__atomic_load_n((ptr), __ATOMIC_ACQUIRE))
#define NP1_STORE(ptr, v)   (__atomic_store_n((ptr), (v), __ATOMIC_RELEASE))
#define NP1_GET_POOL(fd)    (NP1_LOAD(&np1.pool[(fd)]))
#define NP1_SET_POOL(fd, p) (NP1_STORE(&np1.pool[(fd)], (p)))

struct np1_state {
        struct ssm_pool * pool[SYS_MAX_FLOWS];
};

extern struct np1_state np1;

#endif /* OUROBOROS_IPCPD_NP1_H */
