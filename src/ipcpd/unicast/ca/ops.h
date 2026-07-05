/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Congestion avoidance policy ops
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

#ifndef OUROBOROS_IPCPD_UNICAST_CA_OPS_H
#define OUROBOROS_IPCPD_UNICAST_CA_OPS_H

#include "ca.h"

struct ca_ops {
        void *   (* ctx_create)(void);

        void     (* ctx_destroy)(void * ctx);

        time_t   (* ctx_update_snd)(void *     ctx,
                                    size_t     len,
                                    uint8_t    lecn,
                                    uint64_t * ftag);

        bool     (* ctx_update_rcv)(void *     ctx,
                                    size_t     len,
                                    uint8_t    ecn,
                                    uint8_t    cap,
                                    uint16_t * ece,
                                    uint8_t *  fcap);

        void     (* ctx_update_ece)(void *   ctx,
                                    uint16_t ece,
                                    uint8_t  cap);

        int      (* calc_ecn)(size_t    queued,
                              uint8_t * ecn,
                              qoscube_t qc,
                              size_t    len);

        /* True if calc_ecn inspects the queue; gates the lookup. */
        bool        marks_ecn;

        /* Optional, can be NULL */
        ssize_t  (* print_stats)(void * ctx,
                                 char * buf,
                                 size_t len);

};

#endif /* OUROBOROS_IPCPD_UNICAST_CA_OPS_H */
