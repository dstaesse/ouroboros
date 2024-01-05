/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Policy for PFF with alternate next hops
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

#ifndef OUROBOROS_IPCPD_UNICAST_ALTERNATE_PFF_H
#define OUROBOROS_IPCPD_UNICAST_ALTERNATE_PFF_H

#include "ops.h"

struct pff_i * alternate_pff_create(void);

void           alternate_pff_destroy(struct pff_i * pff_i);

void           alternate_pff_lock(struct pff_i * pff_i);

void           alternate_pff_unlock(struct pff_i * pff_i);

int            alternate_pff_add(struct pff_i * pff_i,
                                 uint64_t       addr,
                                 int *          fd,
                                 size_t         len);

int            alternate_pff_update(struct pff_i * pff_i,
                                    uint64_t       addr,
                                    int *          fd,
                                    size_t         len);

int            alternate_pff_del(struct pff_i * pff_i,
                                 uint64_t       addr);

void           alternate_pff_flush(struct pff_i * pff_i);

/* Returns fd towards next hop */
int            alternate_pff_nhop(struct pff_i * pff_i,
                                  uint64_t       addr);

int            alternate_flow_state_change(struct pff_i * pff_i,
                                           int            fd,
                                           bool           up);

extern struct pff_ops alternate_pff_ops;

#endif /* OUROBOROS_IPCPD_UNICAST_ALTERNATE_PFF_H */
