/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Names registered with the local IPCP
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

#ifndef OUROBOROS_IPCPD_LOCAL_REG_H
#define OUROBOROS_IPCPD_LOCAL_REG_H

#include <stdbool.h>
#include <stdint.h>

/* The hashes of the names registered with this IPCP. */
struct reg;

struct reg * reg_create(void);

void         reg_destroy(struct reg * reg);

int          reg_add(struct reg *    reg,
                     const uint8_t * hash);

int          reg_del(struct reg *    reg,
                     const uint8_t * hash);

bool         reg_has(struct reg *    reg,
                     const uint8_t * hash);

#endif /* OUROBOROS_IPCPD_LOCAL_REG_H */
