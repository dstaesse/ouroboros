/*
 * Ouroboros - Copyright (C) 2016 - 2021
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include <ouroboros/ipcp-dev.h>
#include <ouroboros/time_utils.h>

#include "ca-mb-ecn.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* congestion avoidance constants */
#define CA_SHFT      5                    /* Average over 32 pkts   */
#define CA_WND       (1 << CA_SHFT)       /* 32 pkts receiver wnd   */
#define CA_UPD       (1 << (CA_SHFT - 3)) /* Update snd every 8 pkt */
#define CA_SLOT      24                   /* Initial slot = 16 ms   */
#define CA_INC       1UL << 16            /* ~4MiB/s^2 additive inc */
#define CA_IWL       1UL << 16            /* Initial limit ~4MiB/s  */
#define CA_MINPS     8                    /* Mimimum pkts / slot    */
#define CA_MAXPS     64                   /* Maximum pkts / slot    */
#define ECN_Q_SHFT   4
#define ts_to_ns(ts) ((size_t) ts.tv_sec * BILLION + ts.tv_nsec)

struct mb_ecn_ctx {
        uint16_t        rx_ece; /* Level of congestion (upstream)   */
        size_t          rx_ctr; /* Receiver side packet counter     */

        uint16_t        tx_ece; /* Level of congestion (downstream) */
        size_t          tx_ctr; /* Sender side packet counter       */
        size_t          tx_wbc; /* Window byte count                */
        size_t          tx_wpc; /* Window packet count              */
        size_t          tx_wbl; /* Window byte limit                */
        bool            tx_cav; /* Congestion avoidance             */
        size_t          tx_mul; /* Slot size multiplier             */
        size_t          tx_inc; /* Additive increase                */
        size_t          tx_slot;
};

struct pol_ca_ops mb_ecn_ca_ops = {
        .ctx_create     = mb_ecn_ctx_create,
        .ctx_destroy    = mb_ecn_ctx_destroy,
        .ctx_update_snd = mb_ecn_ctx_update_snd,
        .ctx_update_rcv = mb_ecn_ctx_update_rcv,
        .ctx_update_ece = mb_ecn_ctx_update_ece,
        .wnd_wait       = mb_ecn_wnd_wait,
        .calc_ecn       = mb_ecn_calc_ecn,
        .print_stats    = mb_ecn_print_stats
};

void * mb_ecn_ctx_create(void)
{
        struct timespec     now;
        struct mb_ecn_ctx * ctx;

        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL)
                return NULL;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        memset(ctx, 0, sizeof(*ctx));

        ctx->tx_mul  = CA_SLOT;
        ctx->tx_wbl  = CA_IWL;
        ctx->tx_inc  = CA_INC;
        ctx->tx_slot = ts_to_ns(now) >> ctx->tx_mul;

        return (void *) ctx;
}

void mb_ecn_ctx_destroy(void * ctx)
{
        free(ctx);
}

#define _slot_after(new, old) ((int64_t) (old - new) < 0)

ca_wnd_t mb_ecn_ctx_update_snd(void * _ctx,
                               size_t len)
{
        struct timespec     now;
        size_t              slot;
        ca_wnd_t            wnd;
        struct mb_ecn_ctx * ctx = _ctx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        slot = ts_to_ns(now) >> ctx->tx_mul;

        ctx->tx_ctr++;
        ctx->tx_wpc++;
        ctx->tx_wbc += len;

        if (ctx->tx_ctr > CA_WND)
                ctx->tx_ece = 0;

        if (_slot_after(slot, ctx->tx_slot)) {
                bool carry = false; /* may carry over if window increases */

                ctx->tx_slot = slot;

                if (!ctx->tx_cav) { /* Slow start */
                        if (ctx->tx_wbc > ctx->tx_wbl)
                                ctx->tx_wbl <<= 1;
                } else {
                        if (ctx->tx_ece) /* Mult. Decrease */
                                ctx->tx_wbl -= (ctx->tx_wbl * ctx->tx_ece)
                                        >> (CA_SHFT + 8);
                        else if (ctx->tx_wbc > ctx->tx_wbl) /* Add. Increase */
                                ctx->tx_wbl = ctx->tx_wbl + ctx->tx_inc;
                }

                /* Window scaling */
                if (ctx->tx_wpc < CA_MINPS) {
                        size_t fact = 0; /* factor to scale the window up */
                        size_t pkts = ctx->tx_wpc;
                        while (pkts < CA_MINPS) {
                                pkts <<= 1;
                                fact++;
                        }
                        ctx->tx_mul += fact;
                        ctx->tx_slot >>= fact;
                        if ((ctx->tx_slot & ((1 << fact)  - 1)) == 0) {
                                carry = true;
                                ctx->tx_slot += 1;
                        }
                        ctx->tx_wbl <<= fact;
                        ctx->tx_inc <<= fact;
                } else if (ctx->tx_wpc > CA_MAXPS) {
                        size_t fact = 0; /* factor to scale the window down */
                        size_t pkts = ctx->tx_wpc;
                        while (pkts > CA_MAXPS) {
                                pkts >>= 1;
                                fact++;
                        }
                        ctx->tx_mul -= fact;
                        ctx->tx_slot <<= fact;
                        ctx->tx_wbl >>= fact;
                        ctx->tx_inc >>= fact;
                } else {
                        ctx->tx_slot = slot;
                }

                if (!carry) {
                        ctx->tx_wbc = 0;
                        ctx->tx_wpc = 0;
                }
        }

        if (ctx->tx_wbc > ctx->tx_wbl)
                wnd.wait = ((ctx->tx_slot + 1) << ctx->tx_mul) - ts_to_ns(now);
        else
                wnd.wait = 0;

        return wnd;
}

void mb_ecn_wnd_wait(ca_wnd_t wnd)
{
        if (wnd.wait > 0) {
                struct timespec s = {0, 0};
                if (wnd.wait > BILLION) /* Don't care throttling < 1s */
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

        if (ecn == 0) { /* End of congestion */
                ctx->rx_ece >>= 2;
                update = ctx->rx_ece == 0;
        } else {
                if (ctx->rx_ece == 0) { /* Start of congestion */
                        ctx->rx_ece = ecn;
                        ctx->rx_ctr = 0;
                        update = true;
                } else { /* Congestion update */
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

int  mb_ecn_calc_ecn(int       fd,
                     uint8_t * ecn,
                     qoscube_t qc,
                     size_t    len)
{
        size_t q;

        (void) len;
        (void) qc;

        q = ipcp_flow_queued(fd);

        *ecn |= (uint8_t) (q >> ECN_Q_SHFT);

        return 0;
}

ssize_t  mb_ecn_print_stats(void * _ctx,
                            char * buf,
                            size_t len)
{
        struct mb_ecn_ctx* ctx = _ctx;
        char *             regime;

        if (len < 1024)
                return 0;

        if (!ctx->tx_cav)
                regime = "Slow start";
        else if (ctx->tx_ece)
                regime = "Multiplicative dec";
        else
                regime = "Additive inc";

        sprintf(buf,
                "Congestion avoidance algorithm:  %20s\n"
                "Upstream congestion level:       %20u\n"
                "Upstream packet counter:         %20zu\n"
                "Downstream congestion level:     %20u\n"
                "Downstream packet counter:       %20zu\n"
                "Congestion window size (ns):     %20" PRIu64 "\n"
                "Packets in this window:          %20zu\n"
                "Bytes in this window:            %20zu\n"
                "Max bytes in this window:        %20zu\n"
                "Current congestion regime:       %20s\n",
                "Multi-bit ECN",
                ctx->rx_ece, ctx->rx_ctr,
                ctx->tx_ece, ctx->tx_ctr, (size_t) (1UL << ctx->tx_mul),
                ctx->tx_wpc, ctx->tx_wbc, ctx->tx_wbl,
                regime);

        return strlen(buf);
}
