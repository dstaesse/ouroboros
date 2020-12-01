/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Congestion avoidance policy ops
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

#ifndef OUROBOROS_IPCPD_UNICAST_POL_CA_OPS_H
#define OUROBOROS_IPCPD_UNICAST_POL_CA_OPS_H

#include "ca.h"

struct pol_ca_ops {
        void *   (* ctx_create)(void);

        void     (* ctx_destroy)(void * ctx);

        ca_wnd_t (* ctx_update_snd)(void * ctx,
                                    size_t len);

        bool     (* ctx_update_rcv)(void *     ctx,
                                    size_t     len,
                                    uint8_t    ecn,
                                    uint16_t * ece);

        void     (* ctx_update_ece)(void *   ctx,
                                    uint16_t ece);

        void     (* wnd_wait)(ca_wnd_t wnd);

        uint8_t  (* calc_ecn)(int    fd,
                              size_t len);
};

#endif /* OUROBOROS_IPCPD_UNICAST_POL_CA_OPS_H */
