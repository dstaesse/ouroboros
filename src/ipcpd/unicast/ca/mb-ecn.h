/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Multi-bit ECN Congestion Avoidance
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

#ifndef OUROBOROS_IPCPD_UNICAST_CA_MB_ECN_H
#define OUROBOROS_IPCPD_UNICAST_CA_MB_ECN_H

#include "ops.h"

void *   mb_ecn_ctx_create(void);

void     mb_ecn_ctx_destroy(void * ctx);

time_t   mb_ecn_ctx_update_snd(void *     ctx,
                               size_t     len,
                               uint8_t    lecn,
                               uint64_t * ftag);

bool     mb_ecn_ctx_update_rcv(void *     ctx,
                               size_t     len,
                               uint8_t    ecn,
                               uint8_t    cap,
                               uint16_t * ece,
                               uint8_t *  fcap);

void     mb_ecn_ctx_update_ece(void *   ctx,
                               uint16_t ece,
                               uint8_t  cap);

int      mb_ecn_calc_ecn(size_t    queued,
                         uint8_t * ecn,
                         qoscube_t qc,
                         size_t    len);

ssize_t  mb_ecn_print_stats(void * ctx,
                            char * buf,
                            size_t len);

extern struct ca_ops mb_ecn_ca_ops;

#endif /* OUROBOROS_IPCPD_UNICAST_CA_MB_ECN_H */
