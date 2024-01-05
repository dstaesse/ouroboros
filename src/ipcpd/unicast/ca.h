/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Congestion avoidance
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

#ifndef OUROBOROS_IPCPD_UNICAST_CA_H
#define OUROBOROS_IPCPD_UNICAST_CA_H

#include <ouroboros/ipcp.h>
#include <ouroboros/qoscube.h>

#include <stdbool.h>
#include <sys/types.h>

typedef union {
        time_t wait;
} ca_wnd_t;

int      ca_init(enum pol_cong_avoid ca);

void     ca_fini(void);


/* OPS */
void *   ca_ctx_create(void);

void     ca_ctx_destroy(void * ctx);

ca_wnd_t ca_ctx_update_snd(void * ctx,
                           size_t len);

bool     ca_ctx_update_rcv(void *     ctx,
                           size_t     len,
                           uint8_t    ecn,
                           uint16_t * ece);

void     ca_ctx_update_ece(void *   ctx,
                           uint16_t ece);

void     ca_wnd_wait(ca_wnd_t wnd);

int      ca_calc_ecn(int       fd,
                     uint8_t * ecn,
                     qoscube_t qc,
                     size_t    len);

ssize_t  ca_print_stats(void * ctx,
                        char * buf,
                        size_t len);

#endif /* OUROBOROS_IPCPD_UNICAST_CA_H */
