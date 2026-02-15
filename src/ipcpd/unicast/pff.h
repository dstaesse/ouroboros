/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * PDU Forwarding Function
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

#ifndef OUROBOROS_IPCPD_UNICAST_PFF_H
#define OUROBOROS_IPCPD_UNICAST_PFF_H

#include <ouroboros/ipcp.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

enum pol_pff {
        PFF_SIMPLE = 0,
        PFF_ALTERNATE,
        PFF_MULTIPATH
};

struct pff * pff_create(enum pol_pff pol);

void         pff_destroy(struct pff * pff);

void         pff_lock(struct pff * pff);

void         pff_unlock(struct pff * pff);

int          pff_add(struct pff * pff,
                     uint64_t     addr,
                     int *        fd,
                     size_t       len);

int          pff_update(struct pff * pff,
                        uint64_t     addr,
                        int *        fd,
                        size_t       len);

int          pff_del(struct pff * pff,
                     uint64_t     addr);

void         pff_flush(struct pff * pff);

/* Returns fd towards next hop */
int          pff_nhop(struct pff * pff,
                      uint64_t     addr);

int          pff_flow_state_change(struct pff * pff,
                                   int          fd,
                                   bool         up);

#endif /* OUROBOROS_IPCPD_UNICAST_PFF_H */
