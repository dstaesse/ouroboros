/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Policy for PFF supporting multipath routing
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *    Nick Aerts        <nick.aerts@ugent.be>
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

#ifndef OUROBOROS_IPCPD_UNICAST_MULTIPATH_PFF_H
#define OUROBOROS_IPCPD_UNICAST_MULTIPATH_PFF_H

#include "ops.h"

struct pff_i * multipath_pff_create(void);

void multipath_pff_destroy(struct pff_i * pff_i);

void           multipath_pff_lock(struct pff_i * pff_i);

void           multipath_pff_unlock(struct pff_i * pff_i);

int            multipath_pff_add(struct pff_i * pff_i,
                                 uint64_t       addr,
                                 int *          fds,
                                 size_t         len);

int            multipath_pff_update(struct pff_i * pff_i,
                                    uint64_t       addr,
                                    int *          fds,
                                    size_t         len);

int            multipath_pff_del(struct pff_i * pff_i,
                                 uint64_t       addr);

void multipath_pff_flush(struct pff_i * pff_i);

/* Returns fd towards next hop */
int            multipath_pff_nhop(struct pff_i * pff_i,
                                  uint64_t       addr);

extern struct pff_ops multipath_pff_ops;

#endif /* OUROBOROS_IPCPD_UNICAST_MULTIPATH_PFF_H */
