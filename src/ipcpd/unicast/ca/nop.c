/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Dummy Congestion Avoidance
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

#include "nop.h"

#include <string.h>

struct ca_ops nop_ca_ops = {
        .ctx_create     = nop_ctx_create,
        .ctx_destroy    = nop_ctx_destroy,
        .ctx_update_snd = nop_ctx_update_snd,
        .ctx_update_rcv = nop_ctx_update_rcv,
        .ctx_update_ece = nop_ctx_update_ece,
        .wnd_wait       = nop_wnd_wait,
        .calc_ecn       = nop_calc_ecn,
        .print_stats    = NULL
};

void * nop_ctx_create(void)
{
        return (void *) 1;
}

void nop_ctx_destroy(void * ctx)
{
        (void) ctx;
}

ca_wnd_t nop_ctx_update_snd(void * ctx,
                            size_t len)
{
        ca_wnd_t wnd;

        (void) ctx;
        (void) len;

        memset(&wnd, 0, sizeof(wnd));

        return wnd;
}

void nop_wnd_wait(ca_wnd_t wnd)
{
        (void) wnd;
}

bool nop_ctx_update_rcv(void *     ctx,
                        size_t     len,
                        uint8_t    ecn,
                        uint16_t * ece)
{
        (void) ctx;
        (void) len;
        (void) ecn;
        (void) ece;

        return false;
}

void nop_ctx_update_ece(void *   ctx,
                        uint16_t ece)
{
        (void) ctx;
        (void) ece;
}


int nop_calc_ecn(int       fd,
                 uint8_t * ecn,
                 qoscube_t qc,
                 size_t    len)
{
        (void) fd;
        (void) len;
        (void) ecn;
        (void) qc;

        return 0;
}
