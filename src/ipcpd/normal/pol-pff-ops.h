/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Pff policy ops
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#ifndef OUROBOROS_IPCPD_NORMAL_POL_PFF_OPS_H
#define OUROBOROS_IPCPD_NORMAL_POL_PFF_OPS_H

#include <stdbool.h>

struct pff_i;

struct pol_pff_ops {
        struct pff_i * (* create)(void);

        void           (* destroy)(struct pff_i * pff_i);

        void           (* lock)(struct pff_i * pff_i);

        void           (* unlock)(struct pff_i * pff_i);

        int            (* add)(struct pff_i * pff_i,
                               uint64_t       addr,
                               int *          fd,
                               size_t         len);

        int            (* update)(struct pff_i * pff_i,
                                  uint64_t       addr,
                                  int *          fd,
                                  size_t         len);

        int            (* del)(struct pff_i * pff_i,
                               uint64_t       addr);

        void           (* flush)(struct pff_i * pff_i);

        int            (* nhop)(struct pff_i * pff_i,
                                uint64_t       addr);

        /* Optional operation. */
        int            (* flow_state_change)(struct pff_i * pff_i,
                                             int            fd,
                                             bool           up);
};

#endif /* OUROBOROS_IPCPD_NORMAL_POL_PFF_OPS_H */
