/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Multi-bit ECN Congestion Avoidance
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include <ouroboros/ipcp-dev.h>
#include <ouroboros/time_utils.h>

#include "ca-mb-ecn.h"

#include <stdlib.h>
#include <string.h>

/* congestion avoidance constants */
#define CA_SHFT      5
#define CA_WND       (1 << CA_SHFT)
#define CA_UPD       (1 << (CA_SHFT - 3))
#define CA_SLOT      18
#define CA_AI        20000
#define ECN_Q_SHFT   5
#define ts_to_ns(ts) (ts.tv_sec * BILLION + ts.tv_nsec)

struct mb_ecn_ctx {
        uint16_t        rx_ece; /* level of congestion (upstream)   */
        size_t          rx_ctr; /* receiver side packet counter     */

        uint16_t        tx_ece; /* level of congestion (downstream) */
        size_t          tx_ctr; /* sender side packet counter       */
        size_t          tx_aps; /* average packet size              */
        time_t          tx_wnd; /* tgt time to send packets (ns)    */
        bool            tx_cav; /* Congestion avoidance             */
        size_t          tx_slot;

        struct timespec t_sent; /* last sent packet                 */
};

struct pol_ca_ops mb_ecn_ca_ops = {
        .ctx_create     = mb_ecn_ctx_create,
        .ctx_destroy    = mb_ecn_ctx_destroy,
        .ctx_update_snd = mb_ecn_ctx_update_snd,
        .ctx_update_rcv = mb_ecn_ctx_update_rcv,
        .ctx_update_ece = mb_ecn_ctx_update_ece,
        .wnd_wait       = mb_ecn_wnd_wait,
        .calc_ecn       = mb_ecn_calc_ecn
};

void * mb_ecn_ctx_create(void)
{

        struct mb_ecn_ctx * ctx;

        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL)
                return NULL;

        memset(ctx, 0, sizeof(*ctx));

        return (void *) ctx;
}

void mb_ecn_ctx_destroy(void * ctx)
{
        free(ctx);
}

ca_wnd_t mb_ecn_ctx_update_snd(void * _ctx,
                               size_t len)
{
        struct timespec  now;
        size_t           slot;
        time_t           gap;
        ca_wnd_t         wnd;

        struct mb_ecn_ctx * ctx = _ctx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        if (ctx->tx_wnd == 0) { /* 10 ms initial window estimate */
                ctx->tx_wnd = 10 * MILLION;
                gap          = ctx->tx_wnd >> CA_SHFT;
                ctx->tx_aps = len >> CA_SHFT;
                ctx->tx_slot = ts_to_ns(now) >> CA_SLOT;
        } else {
                gap           = ts_diff_ns(&ctx->t_sent, &now);
                ctx->tx_aps -= ctx->tx_aps >> CA_SHFT;
                ctx->tx_aps += len;
        }

        ctx->t_sent = now;

        slot = ts_to_ns(now) >> CA_SLOT;

        ctx->tx_ctr++;

        if (slot - ctx->tx_slot > 0) {
                ctx->tx_slot = slot;

                if (ctx->tx_ctr > CA_WND)
                        ctx->tx_ece = 0;

                /* Slow start */
                if (!ctx->tx_cav) {
                        ctx->tx_wnd >>= 1;
                /* Multiplicative Decrease */
                } else if (ctx->tx_ece) { /* MD */
                        ctx->tx_wnd += (ctx->tx_wnd * ctx->tx_ece)
                                >> (CA_SHFT + 8);
                /* Additive Increase */
                } else {
                        size_t bw = ctx->tx_aps * BILLION / ctx->tx_wnd;
                        bw += CA_AI;
                        ctx->tx_wnd = ctx->tx_aps * BILLION / bw;
                }
        }

        wnd.wait = (ctx->tx_wnd >> CA_SHFT) - gap;

        return wnd;
}

void mb_ecn_wnd_wait(ca_wnd_t wnd)
{
        if (wnd.wait > 0) {
                struct timespec s = {0, 0};
                if (wnd.wait > BILLION) /* Don't care throttling < 1pps */
                        s.tv_sec = 1;
                else
                        s.tv_nsec = wnd.wait;

                nanosleep(&s, NULL);
        }
}

bool mb_ecn_ctx_update_rcv(void *     _ctx,
                           size_t     len,
                           uint8_t    ecn,
                           uint16_t * ece)
{
        struct mb_ecn_ctx* ctx = _ctx;
        bool               update;

        (void) len;

        if ((ctx->rx_ece | ecn) == 0)
                return false;

        if (ecn == 0) {
                /* end of congestion */
                ctx->rx_ece >>= 2;
                update = ctx->rx_ece == 0;
        } else {
                if (ctx->rx_ece == 0) {
                        /* start of congestion */
                        ctx->rx_ece = ecn;
                        ctx->rx_ctr = 0;
                        update = true;
                } else {
                        /* congestion update */
                        ctx->rx_ece -= ctx->rx_ece >> CA_SHFT;
                        ctx->rx_ece += ecn;
                        update = (ctx->rx_ctr++ & (CA_UPD - 1)) == true;
                }
        }

        *ece = ctx->rx_ece;

        return update;
}


void mb_ecn_ctx_update_ece(void *   _ctx,
                           uint16_t ece)
{
        struct mb_ecn_ctx* ctx = _ctx;

        ctx->tx_ece = ece;
        ctx->tx_ctr = 0;
        ctx->tx_cav = true;
}

uint8_t mb_ecn_calc_ecn(int    fd,
                        size_t len)
{
        size_t q;

        (void) len;

        q = ipcp_flow_queued(fd);

        return (uint8_t) (q >> ECN_Q_SHFT);
}
