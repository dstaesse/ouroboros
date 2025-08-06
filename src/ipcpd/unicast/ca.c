/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Congestion Avoidance
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

#define OUROBOROS_PREFIX "ca"

#include <ouroboros/logs.h>

#include "ca.h"
#include "ca/pol.h"

struct {
        struct ca_ops * ops;
} ca;

int ca_init(enum pol_cong_avoid pol)
{
        switch(pol) {
        case CA_NONE:
                log_dbg("Disabling congestion control.");
                ca.ops = &nop_ca_ops;
                break;
        case CA_MB_ECN:
                log_dbg("Using multi-bit ECN.");
                ca.ops = &mb_ecn_ca_ops;
                break;
        default:
                return -1;
        }

        return 0;
}

void ca_fini(void)
{
        ca.ops = NULL;
}

void * ca_ctx_create(void)
{
        return ca.ops->ctx_create();
}

void ca_ctx_destroy(void * ctx)
{
        return ca.ops->ctx_destroy(ctx);
}

ca_wnd_t ca_ctx_update_snd(void * ctx,
                           size_t len)
{
        return ca.ops->ctx_update_snd(ctx, len);
}

bool ca_ctx_update_rcv(void *     ctx,
                       size_t     len,
                       uint8_t    ecn,
                       uint16_t * ece)
{
        return ca.ops->ctx_update_rcv(ctx, len, ecn, ece);
}

void ca_ctx_update_ece(void *   ctx,
                       uint16_t ece)
{
        return ca.ops->ctx_update_ece(ctx, ece);
}

void ca_wnd_wait(ca_wnd_t wnd)
{
        return ca.ops->wnd_wait(wnd);
}

int  ca_calc_ecn(int       fd,
                 uint8_t * ecn,
                 qoscube_t qc,
                 size_t    len)
{
        return ca.ops->calc_ecn(fd, ecn, qc, len);
}

ssize_t ca_print_stats(void * ctx,
                       char * buf,
                       size_t len)
{
        if (ca.ops->print_stats == NULL)
                return 0;

        return ca.ops->print_stats(ctx, buf, len);
}
