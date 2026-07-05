/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Unit tests for multi-bit ECN congestion avoidance
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

#include "mb-ecn.c"

#include <test/test.h>

#define MS (MILLION) /* one millisecond in ns */
#define LEN 1000    /* default packet size (bytes) */

/* Create a context with the clock zeroed for deterministic time steps. */
static struct mb_ecn_ctx * mk_ctx(void)
{
        struct mb_ecn_ctx * ctx;

        ctx = mb_ecn_ctx_create();
        if (ctx == NULL)
                return NULL;

        ctx->rx_ts     = 0;
        ctx->rx_win    = 0;
        ctx->last_ts   = 0;
        ctx->last_ctrl = 0;
        ctx->last_fb   = 0;
        ctx->last_loc  = 0;
        ctx->last_cap  = 0;

        ctx->snd_byt     = 0;
        ctx->snd_win     = 0;
        ctx->snd_r0      = CA_RATE_INIT;
        ctx->snd_rate    = CA_RATE_INIT;
        ctx->backlogged  = true;
        ctx->src_limited = false;
        ctx->started     = false;

        return ctx;
}

/*
 * Drive ctx as a fully backlogged flow: offer a packet every paced
 * wait, so the offered load tracks the paced rate. Returns end time.
 */
static uint64_t drive_backlogged(struct mb_ecn_ctx * ctx,
                                 uint64_t *          ftag,
                                 uint64_t            t,
                                 uint64_t            dur,
                                 size_t              len)
{
        uint64_t end = t + dur;
        time_t   w;

        while (t < end) {
                w = mb_ecn_snd(ctx, len, t, ftag);
                t += w > 0 ? (uint64_t) w : 1;
        }

        return t;
}

static int test_mb_ecn_ctx_create_destroy(void)
{
        struct mb_ecn_ctx * ctx;

        TEST_START();

        ctx = mb_ecn_ctx_create();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        if (ctx->rate != CA_RATE_INIT) {
                printf("Bad initial rate %" PRIu64 ".\n", ctx->rate);
                goto fail_ctx;
        }

        if (ctx->rate_min != CA_RATE_MIN) {
                printf("Bad initial floor %" PRIu64 ".\n", ctx->rate_min);
                goto fail_ctx;
        }

        if (ctx->vt != 0) {
                printf("Bad initial virtual clock %" PRIu64 ".\n", ctx->vt);
                goto fail_ctx;
        }

        if (ctx->tx_cav) {
                printf("Context did not start in slow start.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_mb_ecn_calc_ecn(void)
{
        uint8_t ecn;

        TEST_START();

        /* A queue below one ECN quantum marks nothing. */
        ecn = 0;
        mb_ecn_calc_ecn(CA_MARK_Q - 1, &ecn, QOS_CUBE_BE, 0);
        if (ecn != 0) {
                printf("Sub-quantum queue marked %u.\n", ecn);
                goto fail;
        }

        /* Queue depth maps to ecn = queued / CA_MARK_Q. */
        ecn = 0;
        mb_ecn_calc_ecn(5 * CA_MARK_Q, &ecn, QOS_CUBE_BE, 0);
        if (ecn != 5) {
                printf("Expected ecn 5, got %u.\n", ecn);
                goto fail;
        }

        /* MAX keeps the larger value; a smaller mark cannot raise it. */
        ecn = 0x80;
        mb_ecn_calc_ecn(CA_MARK_Q, &ecn, QOS_CUBE_BE, 0);
        if (ecn != 0x80) {
                printf("Expected ecn 0x80, got 0x%x.\n", ecn);
                goto fail;
        }

        ecn = 3;
        mb_ecn_calc_ecn(4 * CA_MARK_Q, &ecn, QOS_CUBE_BE, 0);
        if (ecn != 4) {
                printf("Expected ecn 4, got %u.\n", ecn);
                goto fail;
        }

        /* A queue past 255 quanta saturates, it does not wrap to a low mark. */
        ecn = 0;
        mb_ecn_calc_ecn(256 * CA_MARK_Q, &ecn, QOS_CUBE_BE, 0);
        if (ecn != 255) {
                printf("Deep queue wrapped: exp 255, got %u.\n", ecn);
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The first mark after idle emits the raw value with zero latency. */
static int test_mb_ecn_rcv_onset_immediate(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        if (!mb_ecn_rcv(ctx, LEN, 4, 0, &ece, &fcap, MS)) {
                printf("Onset did not update.\n");
                goto fail_ctx;
        }

        if (ece != 4 << CA_SHFT) {
                printf("Onset ece: exp %u, got %u.\n", 4 << CA_SHFT, ece);
                goto fail_ctx;
        }

        if (mb_ecn_rcv(ctx, LEN, 4, 0, &ece, &fcap, 2 * MS)) {
                printf("Mid-window packet updated.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A 50% duty mark square wave emits the time mean, not the last peak. */
static int test_mb_ecn_rcv_window_mean(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        size_t              upd;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, MS);

        /* The byte trigger closes every ~32 packets: two windows. */
        upd = 0;
        for (i = 1; i <= 68; i++) {
                time_t ecn = (i & 1) ? 8 : 0;
                time_t t   = MS + i * MS;
                if (mb_ecn_rcv(ctx, LEN, ecn, 0, &ece, &fcap, t))
                        upd++;
        }

        if (upd != 2) {
                printf("%zu updates in two windows.\n", upd);
                goto fail_ctx;
        }

        if (ece < 120 || ece > 136) {
                printf("window mean: exp ~128, got %u.\n", ece);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * Two flows on the same wall-clock mark timeline, 15x apart in byte
 * rate: the same congestion estimate, but the faster flow's window is
 * shorter, so it feeds back more often (cadence tracks byte rate).
 */
static int test_mb_ecn_rcv_rate_independent(void)
{
        struct mb_ecn_ctx * a;
        struct mb_ecn_ctx * b;
        uint16_t            ea;
        uint16_t            eb;
        uint8_t             fcap;
        size_t              ua;
        size_t              ub;
        size_t              i;

        TEST_START();

        a = mk_ctx();
        b = mk_ctx();
        if (a == NULL || b == NULL) {
                printf("Failed to create contexts.\n");
                goto fail_ctx;
        }

        ea = 0;
        eb = 0;
        ua = 0;
        ub = 0;

        /* 300 ms of sustained mark 8; a at 1 kpps, b at ~66 pps. */
        for (i = 1; i <= 300; i++) {
                ua += mb_ecn_rcv(a, LEN, 8, 0, &ea, &fcap, i * MS) ? 1 : 0;
                if (i % 15 != 0)
                        continue;

                ub += mb_ecn_rcv(b, LEN, 8, 0, &eb, &fcap, i * MS) ? 1 : 0;
        }

        if (ea > eb + 32 || eb > ea + 32) {
                printf("estimates diverge: %u vs %u.\n", ea, eb);
                goto fail_ctx;
        }

        if (ua < ub + 2) {
                printf("cadence not rate-scaled: %zu vs %zu.\n", ua, ub);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * Two flows on one bottleneck, equal byte rate but 7.5x apart in
 * packet size: the same congestion estimate and the same feedback
 * cadence. Framing does not skew the control signal (fair share).
 */
static int test_mb_ecn_rcv_size_fair(void)
{
        struct mb_ecn_ctx * a;
        struct mb_ecn_ctx * b;
        uint16_t            ea;
        uint16_t            eb;
        uint8_t             fcap;
        size_t              ua;
        size_t              ub;
        uint64_t            ta;
        uint64_t            tb;

        TEST_START();

        a = mk_ctx();
        b = mk_ctx();
        if (a == NULL || b == NULL) {
                printf("Failed to create contexts.\n");
                goto fail_ctx;
        }

        ea = 0;
        eb = 0;
        ua = 0;
        ub = 0;
        ta = 0;
        tb = 0;

        /* 1 MB/s each: a at 200 B / 200 us, b at 1500 B / 1.5 ms. */
        while (ta < 500 * MS) {
                ta += 200 * 1000;
                ua += mb_ecn_rcv(a, 200, 8, 0, &ea, &fcap, ta) ? 1 : 0;
        }

        while (tb < 500 * MS) {
                tb += 1500 * 1000;
                ub += mb_ecn_rcv(b, 1500, 8, 0, &eb, &fcap, tb) ? 1 : 0;
        }

        if (ea != 8 << CA_SHFT || eb != 8 << CA_SHFT) {
                printf("size-skewed estimate: %u vs %u.\n", ea, eb);
                goto fail_ctx;
        }

        if (ua > ub + 3 || ub > ua + 3) {
                printf("cadence skewed by size: %zu vs %zu.\n", ua, ub);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Release emits exactly one 0 and leaves the estimator fully idle. */
static int test_mb_ecn_rcv_release_exact_zero(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        size_t              ends;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        for (i = 1; i <= 140; i++)
                mb_ecn_rcv(ctx, LEN, 15, 0, &ece, &fcap, i * MS);

        ends = 0;
        for (i = 141; i <= 350; i++) {
                if (!mb_ecn_rcv(ctx, LEN, 0, 0, &ece, &fcap, i * MS))
                        continue;

                if (ece == 0)
                        ends++;
        }

        if (ends != 1) {
                printf("end of congestion fired %zu times.\n", ends);
                goto fail_ctx;
        }

        if (ctx->rx_ece != 0 || ctx->rx_acc != 0) {
                printf("estimator not idle: ece %u acc %" PRIu64 ".\n",
                       ctx->rx_ece, ctx->rx_acc);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A gap past the window restarts fresh: no stale, diluted estimate. */
static int test_mb_ecn_rcv_gap_restart(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        uint64_t            t;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        mb_ecn_rcv(ctx, LEN, 6, 0, &ece, &fcap, MS);
        mb_ecn_rcv(ctx, LEN, 6, 0, &ece, &fcap, 2 * MS);

        t = 2 * MS + 10 * CA_TW_INIT;
        if (!mb_ecn_rcv(ctx, LEN, 5, 0, &ece, &fcap, t)) {
                printf("gap restart did not update.\n");
                goto fail_ctx;
        }

        if (ece != 5 << CA_SHFT) {
                printf("gap restart: exp %u, got %u.\n", 5 << CA_SHFT, ece);
                goto fail_ctx;
        }

        t += 10 * CA_TW_INIT;
        if (!mb_ecn_rcv(ctx, LEN, 0, 0, &ece, &fcap, t) || ece != 0) {
                printf("gap with clean packet did not end: %u.\n", ece);
                goto fail_ctx;
        }

        if (mb_ecn_rcv(ctx, LEN, 0, 0, &ece, &fcap, t + MS)) {
                printf("idle packet updated.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Max marks at max gaps: exact ceiling, no overflow past the edge. */
static int test_mb_ecn_rcv_accum_bounds(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        uint64_t            t;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        mb_ecn_rcv(ctx, LEN, 15, 0, &ece, &fcap, MS);

        /* Two packets at dt just under CA_TW_INIT straddle the boundary. */
        t = MS + CA_TW_INIT - 1;
        if (mb_ecn_rcv(ctx, LEN, 15, 0, &ece, &fcap, t)) {
                printf("update before the window closed.\n");
                goto fail_ctx;
        }

        t += CA_TW_INIT - 1;
        if (!mb_ecn_rcv(ctx, LEN, 15, 0, &ece, &fcap, t)) {
                printf("no update at the window boundary.\n");
                goto fail_ctx;
        }

        if (ece != 15 << CA_SHFT) {
                printf("ceiling: exp %u, got %u.\n", 15 << CA_SHFT, ece);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Scale-free density: the window holds ~CA_N_TARGET packets at any rate. */
static int test_mb_ecn_rcv_window_holds_target(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        uint16_t            last_ece;
        uint64_t            rates[4];
        uint64_t            ia;
        uint64_t            t;
        size_t              closes;
        size_t              since;
        size_t              count;
        size_t              ri;

        TEST_START();

        rates[0] = 5000000;
        rates[1] = 10000000;
        rates[2] = 50000000;
        rates[3] = 100000000;

        ctx = NULL;
        for (ri = 0; ri < 4; ri++) {
                ia = 8000ULL * BILLION / rates[ri];
                t = 0;
                closes = 0;
                since = 0;
                count = 0;
                last_ece = 0;

                ctx = mk_ctx();
                if (ctx == NULL) {
                        printf("Failed to create context.\n");
                        goto fail;
                }

                /* Warm past the ramp from CA_TW_INIT, then time one gap. */
                while (closes < 42) {
                        t += ia;
                        since++;
                        if (!mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, t))
                                continue;
                        closes++;
                        if (closes == 41) {
                                since = 0;
                        } else if (closes == 42) {
                                count = since - 1;
                                last_ece = ece;
                        }
                }

                if (count < 8 || count > 32) {
                        printf("rate %" PRIu64 ": %zu pkts/window.\n",
                               rates[ri], count);
                        goto fail_ctx;
                }

                if (last_ece < 224 || last_ece > 288) {
                        printf("rate %" PRIu64 ": ece %u ~256.\n",
                               rates[ri], last_ece);
                        goto fail_ctx;
                }

                mb_ecn_ctx_destroy(ctx);
                ctx = NULL;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * The window floors at CA_TW_MIN, tracks the rate below the old knee,
 * and only a pathological fold hits the CA_TW_ABSMAX ceiling.
 */
static int test_mb_ecn_rcv_window_clip_bounds(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        uint64_t            ia;
        uint64_t            t;
        size_t              closes;

        TEST_START();

        /* 1 GbE is above the high knee: the window floors at CA_TW_MIN. */
        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ia = 8000ULL * BILLION / 1000000000ULL;
        t = 0;
        closes = 0;
        while (closes < 40) {
                t += ia;
                if (mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, t))
                        closes++;
        }

        if (ctx->rx_tw != CA_TW_MIN) {
                printf("high-rate window: exp %" PRIu64 ", got %" PRIu64
                       ".\n", (uint64_t) CA_TW_MIN, ctx->rx_tw);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        /* 1 Mbps: past the old knee, ~16 pkts = 16 * 8 ms = 131 ms. */
        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ia = 8000ULL * BILLION / 1000000ULL;
        t = 0;
        closes = 0;
        while (closes < 40) {
                t += ia;
                if (mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, t))
                        closes++;
        }

        if (ctx->rx_tw < 120 * MS || ctx->rx_tw > 140 * MS) {
                printf("low-rate window: exp ~131 ms, got %" PRIu64 ".\n",
                       ctx->rx_tw);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        /* A near-empty window folds a huge target: ceiling holds. */
        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        mb_ecn_rcv(ctx, 10, 8, 0, &ece, &fcap, MS);
        mb_ecn_rcv(ctx, 10, 8, 0, &ece, &fcap, MS + CA_TW_INIT);

        if (ctx->rx_tw != CA_TW_ABSMAX) {
                printf("window ceiling breached: %" PRIu64 ".\n",
                       ctx->rx_tw);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A CA-limited slow flow grows its window to hold ~16 packets. */
static int test_mb_ecn_rcv_slow_window(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* 1400 B every 171 ms (~8 KB/s), sustained mark 8. */
        for (i = 1; i <= 100; i++)
                mb_ecn_rcv(ctx, 1400, 8, 0, &ece, &fcap, i * 171 * MS);

        /* Target window 16 * 1000 B at 8187 B/s ~= 2.0 s. */
        if (ctx->rx_tw < 1400 * MS || ctx->rx_tw > 2800 * MS) {
                printf("slow window: exp ~2 s, got %" PRIu64 ".\n",
                       ctx->rx_tw);
                goto fail_ctx;
        }

        /* Steady mark 8 emits exactly 256 once the window settles. */
        if (ece != 8 << CA_SHFT) {
                printf("slow-flow estimate: exp %u, got %u.\n",
                       8 << CA_SHFT, ece);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A physically maximal window must fold without overflow or wrap. */
static int test_mb_ecn_rcv_no_overflow_highrate(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        bool                ok;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Open a window, then inject a maximal byte count and span. */
        mb_ecn_rcv(ctx, LEN, 15, 0, &ece, &fcap, 0);
        ctx->rx_byt = CA_RATE_MAX / 8;
        ctx->rx_ts  = 2 * CA_TW_INIT - 2;

        ok = mb_ecn_rcv(ctx, LEN, 15, 0, &ece, &fcap, 2 * CA_TW_INIT - 1);

        if (!ok) {
                printf("max-window close did not fire.\n");
                goto fail_ctx;
        }

        if (ece > 8160) {
                printf("estimate %u wrapped.\n", ece);
                goto fail_ctx;
        }

        /* A wrapped numerator drives rx_tw to MAX; it must descend. */
        if (ctx->rx_tw >= CA_TW_INIT || ctx->rx_tw < CA_TW_MIN) {
                printf("window %" PRIu64 " did not descend.\n", ctx->rx_tw);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * The sender holds a mark across the full inter-feedback gap (TTL >
 * 2 * CA_TW_INIT) and a repeated mark must not re-fire the one-sided lead.
 */
static int test_mb_ecn_ece_ttl_covers_cadence(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            prev;
        uint64_t            t;
        uint64_t            ftag = 0;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate   = (uint64_t) 100 << 20;
        ctx->tx_cav = true;

        mb_ecn_ece(ctx, 100, 0, MS);
        mb_ecn_snd(ctx, LEN, MS, &ftag);

        /* Sends between feedbacks spaced 2 * CA_TW_INIT + 5 ms apart. */
        t = MS;
        for (i = 0; i < 4; i++) {
                t += (2 * CA_TW_INIT + 5 * MS) / 4;
                mb_ecn_snd(ctx, LEN, t, &ftag);
                if (ctx->tx_ece == 0) {
                        printf("mark cleared inside the feedback gap.\n");
                        goto fail_ctx;
                }
        }

        /* Same mark again: rise 0, so only the proportional cut. */
        prev = ctx->rate;
        t   += MS;
        mb_ecn_ece(ctx, 100, 0, t);
        mb_ecn_snd(ctx, LEN, t, &ftag);

        if (prev - ctx->rate > prev / 100) {
                printf("phantom lead cut: %" PRIu64 " -> %" PRIu64 ".\n",
                       prev, ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_mb_ecn_slow_start(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            prev;
        uint64_t            t;
        uint64_t            ftag = 0;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        prev = ctx->rate;
        t    = 0;

        /* No feedback: the flow stays in slow start and grows each step. */
        for (i = 0; i < 16; i++) {
                t += MS;
                mb_ecn_snd(ctx, LEN, t, &ftag);
                if (ctx->rate <= prev) {
                        printf("rate did not grow: %" PRIu64 ".\n", ctx->rate);
                        goto fail_ctx;
                }

                prev = ctx->rate;
        }

        /* Exponential ramp doubles in ~ln2 * CA_SS_TC ~= 14 ms. */
        if (ctx->rate < 2 * CA_RATE_INIT) {
                printf("slow start too slow: %" PRIu64 ".\n", ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_mb_ecn_dt_scaling_invariant(void)
{
        struct mb_ecn_ctx * a;
        struct mb_ecn_ctx * b;
        uint64_t            inc_a;
        uint64_t            inc_b;
        uint64_t            t;
        uint64_t            fta = 0;
        uint64_t            ftb = 0;
        size_t              i;

        TEST_START();

        a = mk_ctx();
        b = mk_ctx();
        if (a == NULL || b == NULL) {
                printf("Failed to create contexts.\n");
                goto fail_ctx;
        }

        /* Leave slow start; seed a realistic rate (truncation-free). */
        mb_ecn_ece(a, 0, 0, 0);
        mb_ecn_ece(b, 0, 0, 0);
        a->rate = (uint64_t) 10 << 20;
        b->rate = (uint64_t) 10 << 20;
        a->r_bkt = a->rate;
        b->r_bkt = b->rate;

        /* a: one 30 ms step (under one washout bucket, so it stays out). */
        mb_ecn_snd(a, LEN, 30 * MS, &fta);

        /* b: thirty 1 ms steps over the same 30 ms. */
        t = 0;
        for (i = 0; i < 30; i++) {
                t += MS;
                mb_ecn_snd(b, LEN, t, &ftb);
        }

        inc_a = a->rate - ((uint64_t) 10 << 20);
        inc_b = b->rate - ((uint64_t) 10 << 20);

        /* Equal within 1 %; the small gap is per-step integer truncation. */
        if (inc_a == 0 || inc_b == 0) {
                printf("no additive increase: %" PRIu64 " %" PRIu64 ".\n",
                       inc_a, inc_b);
                goto fail_ctx;
        }

        if (inc_a > inc_b + inc_a / 100 || inc_b > inc_a + inc_a / 100) {
                printf("cadence-dependent AI: %" PRIu64 " vs %" PRIu64 ".\n",
                       inc_a, inc_b);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_mb_ecn_multiplicative_decrease(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            prev;
        uint64_t            t;
        uint64_t            ftag = 0;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate = (uint64_t) 100 << 20;
        prev      = ctx->rate;
        t         = 0;

        for (i = 0; i < 10; i++) {
                t += MS;
                mb_ecn_ece(ctx, CA_ECE_REF, 0, t);
                mb_ecn_snd(ctx, LEN, t, &ftag);
                if (ctx->rate >= prev) {
                        printf("rate did not shrink: %" PRIu64 ".\n",
                               ctx->rate);
                        goto fail_ctx;
                }

                prev = ctx->rate;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_mb_ecn_rate_floor(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Cut larger than headroom must clamp; stay inside CA_ECE_TTL. */
        ctx->rate = CA_RATE_MIN + 1000;
        mb_ecn_ece(ctx, CA_ECE_REF, 0, 0);
        mb_ecn_snd(ctx, LEN, 30 * MS, &ftag);

        if (ctx->rate != CA_RATE_MIN) {
                printf("rate floor breached: %" PRIu64 ".\n", ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_mb_ecn_fixed_point(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            exp;
        uint64_t            t;
        uint64_t            ftag = 0;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        exp = CA_AI_RATE * CA_ECE_REF /
              (128 - CA_ECE_REF * BILLION / CA_PROBE_TC);
        t   = 0;

        /* ~20 s: the probe raises the loop time constant to CA_PROBE_TC. */
        for (i = 0; i < 20000; i++) {
                t += MS;
                mb_ecn_ece(ctx, 128, 0, t);
                mb_ecn_snd(ctx, LEN, t, &ftag);
        }

        if (ctx->rate < exp - exp / 4 || ctx->rate > exp + exp / 4) {
                printf("no fixed point: exp ~%" PRIu64 ", got %" PRIu64 ".\n",
                        exp, ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * One-sided lead: a mark rise cuts rate * rise / (REF * DEN) once;
 * a flat or falling mark leaves only the dt-scaled proportional cut.
 */
static int test_mb_ecn_lead_cut(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            prev;
        uint64_t            drop;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate = (uint64_t) 100 << 20;
        ctx->tx_cav = true;

        /* Rise 0 -> 256: lead cuts ~rise/(REF*DEN) = 1/8 of the rate. */
        prev = ctx->rate;
        mb_ecn_ece(ctx, 256, 0, MS);
        mb_ecn_snd(ctx, LEN, MS, &ftag);
        drop = prev - ctx->rate;
        if (drop < prev / 10) {
                printf("lead cut missing: dropped %" PRIu64 ".\n", drop);
                goto fail_ctx;
        }

        /* Flat mark: rise 0, only the ~0.05%% proportional cut. */
        prev = ctx->rate;
        mb_ecn_ece(ctx, 256, 0, 2 * MS);
        mb_ecn_snd(ctx, LEN, 2 * MS, &ftag);
        drop = prev - ctx->rate;
        if (drop > prev / 100) {
                printf("flat mark over-cut: dropped %" PRIu64 ".\n", drop);
                goto fail_ctx;
        }

        /* Falling mark: one-sided lead must not fire. */
        prev = ctx->rate;
        mb_ecn_ece(ctx, 64, 0, 3 * MS);
        mb_ecn_snd(ctx, LEN, 3 * MS, &ftag);
        drop = prev > ctx->rate ? prev - ctx->rate : 0;
        if (drop > prev / 100) {
                printf("falling mark cut: dropped %" PRIu64 ".\n", drop);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A local first-hop mark exits slow start with no feedback needed. */
static int test_mb_ecn_slow_start_local_brake(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            prev;
        uint64_t            ftag = 0;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        for (i = 1; i <= 50; i++)
                mb_ecn_snd(ctx, LEN, i * MS, &ftag);

        if (ctx->tx_cav) {
                printf("Left slow start without any signal.\n");
                goto fail_ctx;
        }

        prev = ctx->rate;
        mb_ecn_loc(ctx, 1, 50 * MS);
        if (!ctx->tx_cav) {
                printf("Local mark did not exit slow start.\n");
                goto fail_ctx;
        }

        mb_ecn_snd(ctx, LEN, 51 * MS, &ftag);
        if (ctx->rate > prev + prev / 20) {
                printf("SS ramp survived the brake: %" PRIu64 ".\n",
                       ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A clean path still ramps to line rate in well under a second. */
static int test_mb_ecn_slow_start_clean_ramp(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Backlogged, no marks: slow start sprints in a couple windows. */
        drive_backlogged(ctx, &ftag, MS, 2 * CA_SND_WIN, LEN);

        if (ctx->rate < (1ULL << 24)) {
                printf("backlogged slow start too slow: %" PRIu64 ".\n",
                       ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * A sender starved of send-path control steps recovers through the
 * feedback path: honest elapsed time, at most a 50% cut per step.
 */
static int test_mb_ecn_starved_decrease_escape(void)
{
        struct mb_ecn_ctx * ctx;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate   = (uint64_t) 100 << 20;
        ctx->tx_cav = true;

        /* Feedback arrives once per second; no sends at all. */
        for (i = 1; i <= 6; i++)
                mb_ecn_ece(ctx, 480, 0, i * BILLION);

        if (ctx->rate > (5ULL << 19)) {
                printf("still wedged at %" PRIu64 " B/s.\n", ctx->rate);
                goto fail_ctx;
        }

        if (ctx->rate < CA_RATE_MIN) {
                printf("rate floor breached: %" PRIu64 ".\n", ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* With feedback fully dead, the local mark alone recovers the rate. */
static int test_mb_ecn_starved_local_fallback(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            t;
        uint64_t            ftag = 0;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate = (uint64_t) 100 << 20;

        for (i = 1; i <= 7; i++) {
                t = i * BILLION;
                mb_ecn_loc(ctx, 15, t);
                mb_ecn_snd(ctx, LEN, t, &ftag);
        }

        if (!ctx->tx_cav) {
                printf("Local mark did not exit slow start.\n");
                goto fail_ctx;
        }

        if (ctx->rate > (5ULL << 19)) {
                printf("still wedged at %" PRIu64 " B/s.\n", ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * MD Δt-invariance: the same elapsed time under the same mark cuts
 * the same, in one big step or five small ones.
 */
static int test_mb_ecn_decrease_dt_invariant(void)
{
        struct mb_ecn_ctx * a;
        struct mb_ecn_ctx * b;
        uint64_t            cut_a;
        uint64_t            cut_b;
        uint64_t            r0;
        uint64_t            fta = 0;
        uint64_t            ftb = 0;
        size_t              i;

        TEST_START();

        a = mk_ctx();
        b = mk_ctx();
        if (a == NULL || b == NULL) {
                printf("Failed to create contexts.\n");
                goto fail_ctx;
        }

        r0 = (uint64_t) 100 << 20;
        a->rate = r0;
        b->rate = r0;

        mb_ecn_ece(a, 256, 0, 0);
        mb_ecn_ece(b, 256, 0, 0);

        /* a: one 50 ms step; b: five 10 ms steps (both within DT_CAP). */
        mb_ecn_snd(a, LEN, 50 * MS, &fta);

        for (i = 1; i <= 5; i++)
                mb_ecn_snd(b, LEN, i * 10 * MS, &ftb);

        cut_a = r0 - a->rate;
        cut_b = r0 - b->rate;

        if (cut_a == 0 || cut_b == 0) {
                printf("no cut: %" PRIu64 " %" PRIu64 ".\n", cut_a, cut_b);
                goto fail_ctx;
        }

        /* Within 10%: residual is Euler compounding of MD and the probe. */
        if (cut_a > cut_b + cut_a / 10 || cut_b > cut_a + cut_a / 10) {
                printf("cadence-dependent MD: %" PRIu64 " vs %" PRIu64
                       ".\n", cut_a, cut_b);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Resuming after a long idle gap: bounded AI, no cut from stale marks. */
static int test_mb_ecn_idle_resume_bounded(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            prev;
        uint64_t            bump;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate = (uint64_t) 10 << 20;

        mb_ecn_loc(ctx, 15, MS);
        mb_ecn_ece(ctx, 480, 0, MS);

        prev = ctx->rate;

        /* 600 s later: both signals stale; one capped AI + probe step. */
        mb_ecn_snd(ctx, LEN, 600 * BILLION, &ftag);

        if (ctx->rate < prev) {
                printf("stale mark cut the rate: %" PRIu64 ".\n",
                       ctx->rate);
                goto fail_ctx;
        }

        bump  = CA_AI_RATE * CA_DT_CAP / BILLION;
        bump += (prev + bump) * CA_DT_CAP / CA_PROBE_TC;

        if (ctx->rate > prev + bump + 2) {
                printf("idle resume cap breached: %" PRIu64 ".\n", ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The congestion signal ages out on wall-clock time, not packet count. */
static int test_mb_ecn_ece_staleness(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* A fast flow's control step caches the floor TTL. */
        ctx->rate   = (uint64_t) 1 << 20;
        ctx->tx_cav = true;
        mb_ecn_snd(ctx, LEN, MS, &ftag);

        if (ctx->ece_ttl != CA_ECE_TTL) {
                printf("Fast-flow TTL: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) CA_ECE_TTL, ctx->ece_ttl);
                goto fail_ctx;
        }

        mb_ecn_ece(ctx, CA_ECE_REF, 0, 2 * MS);

        /* Just inside the TTL: the signal is still held. */
        mb_ecn_snd(ctx, LEN, 2 * MS + ctx->ece_ttl, &ftag);
        if (ctx->tx_ece == 0) {
                printf("signal aged out too early.\n");
                goto fail_ctx;
        }

        /* Past the TTL without feedback: the signal is cleared. */
        mb_ecn_snd(ctx, LEN, 2 * MS + ctx->ece_ttl + 1, &ftag);
        if (ctx->tx_ece != 0) {
                printf("stale signal not cleared: %u.\n", ctx->tx_ece);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The staleness horizon stretches with a slow flow's window. */
static int test_mb_ecn_ece_ttl_tracks_rate(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            want;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate     = 8192;
        ctx->rate_min = 8192;
        ctx->ai_rate  = 0;
        ctx->tx_cav   = true;
        mb_ecn_snd(ctx, 1400, MS, &ftag);

        want = (1 << CA_TW_GAP_SHFT) * CA_RX_WBYTES * BILLION / ctx->rate;
        if (ctx->ece_ttl != want) {
                printf("Slow-flow TTL: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       want, ctx->ece_ttl);
                goto fail_ctx;
        }

        if (ctx->ece_ttl < 7 * (uint64_t) BILLION) {
                printf("TTL did not stretch: %" PRIu64 ".\n",
                       ctx->ece_ttl);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * First packet of a flow starts at the clock; a same-instant second
 * packet leads by its length and is paced by lead / rate.
 */
static int test_mb_ecn_sfq_pace(void)
{
        struct mb_ecn_ctx * ctx;
        time_t              wait;
        uint64_t            ftag = 0;
        time_t              want;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate     = 1U << 20;
        ctx->inv_rate = mb_ecn_rate_inv(ctx->rate);

        /* First send: start tag equals the clock, so no wait. */
        wait = mb_ecn_snd(ctx, 1500, 0, &ftag);
        if (wait != 0) {
                printf("first packet waited %ld, expected 0.\n", (long) wait);
                goto fail_ctx;
        }

        /* Same instant (dt = 0): the flow now leads by 1500 B. */
        wait = mb_ecn_snd(ctx, 1500, 0, &ftag);
        want = (time_t) ((uint64_t) 1500 * BILLION / ctx->rate);

        if (wait != want) {
                printf("paced wait %ld, expected %ld.\n",
                       (long) wait, (long) want);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * The proportional probe grows the rate by the same fraction per unit
 * time regardless of the absolute rate: two clean flows 100x apart in
 * rate grow by the same ratio. Deleting the probe leaves only the tiny
 * additive increase, failing the growth floor.
 */
static int test_mb_ecn_probe_scale_invariant(void)
{
        struct mb_ecn_ctx * a;
        struct mb_ecn_ctx * b;
        uint64_t            ra0;
        uint64_t            rb0;
        double              ga;
        double              gb;
        uint64_t            t;
        size_t              i;

        TEST_START();

        a = mk_ctx();
        b = mk_ctx();
        if (a == NULL || b == NULL) {
                printf("Failed to create contexts.\n");
                goto fail_ctx;
        }

        /* Clean path (mark 0), out of slow start, backlogged, 100x apart. */
        mb_ecn_ece(a, 0, 0, 0);
        mb_ecn_ece(b, 0, 0, 0);
        a->rate = (uint64_t) 10 << 20;
        b->rate = (uint64_t) 1000 << 20;
        a->r_bkt = a->rate;
        b->r_bkt = b->rate;
        a->backlogged = true;
        b->backlogged = true;
        ra0 = a->rate;
        rb0 = b->rate;

        /* Drive control via the feedback path so backlogged stays set. */
        t = 0;
        for (i = 0; i < 500; i++) {
                t += MS;
                mb_ecn_ece(a, 0, 0, t);
                mb_ecn_ece(b, 0, 0, t);
        }

        ga = (double) a->rate / ra0;
        gb = (double) b->rate / rb0;

        if (ga < gb - gb / 50 || gb < ga - ga / 50) {
                printf("probe not scale-invariant: %.4f vs %.4f.\n", ga, gb);
                goto fail_ctx;
        }

        /* And it must actually grow: the probe is present, not deleted. */
        if (ga < 1.05) {
                printf("probe did not grow the rate: %.4f.\n", ga);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(a);
        mb_ecn_ctx_destroy(b);
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * The proportional probe e-folds the rate over CA_PROBE_TC: a clean flow
 * grows by ~e in 8 s. Pinned to a literal e-band so a mistuned
 * CA_PROBE_TC (e.g. 4 s gives e^2) fails.
 */
static int test_mb_ecn_probe_time_constant(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            r0;
        double              ratio;
        uint64_t            t;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Clean path, out of slow start, backlogged, below the ceiling. */
        mb_ecn_ece(ctx, 0, 0, 0);
        ctx->rate = (uint64_t) 1 << 30;
        ctx->r_bkt = ctx->rate;
        ctx->backlogged = true;
        r0 = ctx->rate;

        /* 8000 x 1 ms of clean growth, driven via the feedback path. */
        t = 0;
        for (i = 0; i < 8000; i++) {
                t += MS;
                mb_ecn_ece(ctx, 0, 0, t);
        }

        /* Washout damps the probe to ~4/3 TC, so 8 s -> ~2.12x. */
        ratio = (double) ctx->rate / r0;
        if (ratio < 2.0 || ratio > 2.25) {
                printf("probe TC off: exp ~2.12, got %.3fx over 8 s.\n",
                       ratio);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The fed-back capacity is the MIN of the nonzero caps in the window. */
static int test_mb_ecn_rcv_cap_window_min(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        uint64_t            t;
        bool                upd;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Onset packet carries no capacity: feed back unknown. */
        if (!mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, MS)) {
                printf("Onset did not update.\n");
                goto fail_ctx;
        }

        if (fcap != 0) {
                printf("Onset fed back cap: exp 0, got %u.\n", fcap);
                goto fail_ctx;
        }

        mb_ecn_rcv(ctx, LEN, 8, 40, &ece, &fcap, 2 * MS);
        mb_ecn_rcv(ctx, LEN, 8, 36, &ece, &fcap, 3 * MS);

        t = 3 * MS + CA_TW_INIT;
        if (!mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, t)) {
                printf("Window did not close.\n");
                goto fail_ctx;
        }

        if (fcap != 36) {
                printf("Window min cap: exp 36, got %u.\n", fcap);
                goto fail_ctx;
        }

        /* The next window starts unknown; follow the adapted rx_tw. */
        upd = false;
        for (i = 0; i < 128 && !upd; i++) {
                t += CA_TW_INIT;
                upd = mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, t);
        }

        if (!upd) {
                printf("Second window did not close.\n");
                goto fail_ctx;
        }

        if (fcap != 0) {
                printf("Stale cap %u leaked into the next window.\n", fcap);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Onset and gap restarts emit the triggering packet's cap, fresh. */
static int test_mb_ecn_rcv_cap_onset_fresh(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        uint64_t            t;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        if (!mb_ecn_rcv(ctx, LEN, 4, 77, &ece, &fcap, MS)) {
                printf("Onset did not update.\n");
                goto fail_ctx;
        }

        if (fcap != 77) {
                printf("Onset cap: exp 77, got %u.\n", fcap);
                goto fail_ctx;
        }

        mb_ecn_rcv(ctx, LEN, 4, 50, &ece, &fcap, 2 * MS);

        /* A gap restart must not fold in the stale window min. */
        t = 2 * MS + 5 * CA_TW_INIT;
        if (!mb_ecn_rcv(ctx, LEN, 4, 90, &ece, &fcap, t)) {
                printf("Gap restart did not update.\n");
                goto fail_ctx;
        }

        if (fcap != 90) {
                printf("Gap restart cap: exp 90, got %u.\n", fcap);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Fed-back capacity derives the floor and slope: EWMA toward C/32. */
static int test_mb_ecn_ece_cap_derives_rates(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            tgt;
        uint64_t            want;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Code 120 = 2^30 B/s; target floor = 2^25 B/s. */
        tgt = cap_dec(120) >> CA_CAP_SHFT;

        mb_ecn_ece(ctx, 100, 120, MS);

        want = CA_RATE_MIN + ((tgt - CA_RATE_MIN) >> CA_CAP_SM_SHFT);
        if (ctx->rate_min != want) {
                printf("Floor: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       want, ctx->rate_min);
                goto fail_ctx;
        }

        if (ctx->ai_rate != ctx->rate_min) {
                printf("AI slope did not track the floor.\n");
                goto fail_ctx;
        }

        mb_ecn_ece(ctx, 100, 120, 2 * MS);

        want += (tgt - want) >> CA_CAP_SM_SHFT;
        if (ctx->rate_min != want) {
                printf("Floor EWMA: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       want, ctx->rate_min);
                goto fail_ctx;
        }

        if (ctx->n_cap != 2) {
                printf("Capacity updates: exp 2, got %" PRIu64 ".\n",
                       ctx->n_cap);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Feedback without a capacity leaves the derived rates untouched. */
static int test_mb_ecn_ece_cap_zero_keeps_rates(void)
{
        struct mb_ecn_ctx * ctx;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        mb_ecn_ece(ctx, 100, 0, MS);

        if (ctx->rate_min != CA_RATE_MIN || ctx->ai_rate != CA_AI_RATE) {
                printf("Unknown cap moved the derived rates.\n");
                goto fail_ctx;
        }

        if (ctx->n_cap != 0) {
                printf("Unknown cap counted as an update.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The derived floor clamps to [CA_RATE_MIN, CA_RMIN_MAX]. */
static int test_mb_ecn_ece_cap_clamps(void)
{
        struct mb_ecn_ctx * ctx;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* A path slower than the default floor cannot lower it. */
        mb_ecn_ece(ctx, 100, 1, MS);

        if (ctx->rate_min != CA_RATE_MIN) {
                printf("Slow path lowered the floor: %" PRIu64 ".\n",
                       ctx->rate_min);
                goto fail_ctx;
        }

        /* A absurdly fast path saturates at the ceiling. */
        for (i = 1; i <= 40; i++)
                mb_ecn_ece(ctx, 100, 255, (1 + i) * MS);

        if (ctx->rate_min > CA_RMIN_MAX) {
                printf("Floor above the ceiling: %" PRIu64 ".\n",
                       ctx->rate_min);
                goto fail_ctx;
        }

        if (ctx->rate_min < CA_RMIN_MAX - 4) {
                printf("Floor did not reach the ceiling: %" PRIu64 ".\n",
                       ctx->rate_min);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Stale capacity reverts the derived rates to the defaults. */
static int test_mb_ecn_cap_ttl_reverts(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        mb_ecn_ece(ctx, 100, 120, MS);

        if (ctx->rate_min == CA_RATE_MIN) {
                printf("Capacity did not derive a floor.\n");
                goto fail_ctx;
        }

        /* Just inside the TTL: the derived rates hold. */
        mb_ecn_snd(ctx, LEN, MS + (ctx->ece_ttl << CA_CAP_TTL_SHFT), &ftag);

        if (ctx->rate_min == CA_RATE_MIN) {
                printf("Derived rates reverted too early.\n");
                goto fail_ctx;
        }

        /* Past the TTL: back to the defaults. */
        mb_ecn_snd(ctx, LEN, MS + (ctx->ece_ttl << CA_CAP_TTL_SHFT) + 1,
                   &ftag);

        if (ctx->rate_min != CA_RATE_MIN || ctx->ai_rate != CA_AI_RATE) {
                printf("Stale capacity kept the derived rates.\n");
                goto fail_ctx;
        }

        if (ctx->tx_cap != 0) {
                printf("Stale capacity code not cleared.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The control law uses the per-ctx AI slope. */
static int test_mb_ecn_ctrl_per_ctx_ai(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            want;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Leave slow start; raise the slope as capacity would. */
        mb_ecn_ece(ctx, 0, 0, 0);
        ctx->rate    = (uint64_t) 10 << 20;
        ctx->r_bkt   = ctx->rate;
        ctx->ai_rate = 16 * CA_AI_RATE;

        want  = ctx->rate + ctx->ai_rate * (30 * MS) / BILLION;
        want += want * (30 * MS) / CA_PROBE_TC;

        mb_ecn_snd(ctx, LEN, 30 * MS, &ftag);

        if (ctx->rate != want) {
                printf("AI not per-ctx: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       want, ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The rate clamp honours the per-ctx derived floor. */
static int test_mb_ecn_ctrl_per_ctx_floor(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate_min = (uint64_t) 1 << 20;
        ctx->rate     = ((uint64_t) 1 << 20) + 1000;

        mb_ecn_ece(ctx, CA_ECE_REF, 0, 0);
        mb_ecn_snd(ctx, LEN, 30 * MS, &ftag);

        if (ctx->rate != ctx->rate_min) {
                printf("Floor not per-ctx: %" PRIu64 ".\n", ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * A paced flow slower than one packet per CA_DT_CAP must not decay:
 * the gap credit law grants its true elapsed service, so the lead
 * stays pinned at ~one packet instead of growing without bound.
 */
static int test_mb_ecn_snd_slow_rate_paced(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;
        uint64_t            t = 0;
        time_t              wait;
        size_t              i;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* 8 KB/s, 1400 B packets: inter-send gap ~171 ms > CA_DT_CAP. */
        ctx->rate     = 8192;
        ctx->rate_min = 8192;
        ctx->ai_rate  = 0;
        ctx->inv_rate = mb_ecn_rate_inv(8192);
        ctx->tx_cav   = true;

        for (i = 0; i < 50; i++) {
                wait = mb_ecn_snd(ctx, 1400, t, &ftag);
                t += wait > 0 ? (uint64_t) wait : 1;
        }

        if (ctx->lead > 2 * 1400) {
                printf("Pacer starves a slow flow: lead %" PRIu64 ".\n",
                       ctx->lead);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * A long idle makes the aggregate source-limited, so the offered-load
 * ceiling bounds the resume rate (hence the burst) well below the
 * pre-idle rate.
 */
static int test_mb_ecn_snd_idle_burst_bound(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate     = (uint64_t) 1 << 20;
        ctx->inv_rate = mb_ecn_rate_inv(ctx->rate);
        ctx->tx_cav   = true;

        mb_ecn_snd(ctx, 1400, 0, &ftag);   /* warm-up: sets started */

        /* 600 s idle. */
        mb_ecn_snd(ctx, 1400, 600 * BILLION, &ftag);

        if (ctx->backlogged) {
                printf("long idle did not clear backlogged.\n");
                goto fail_ctx;
        }

        if (ctx->rate >= ((uint64_t) 1 << 20)) {
                printf("idle resume rate not ceiling-bounded: %" PRIu64
                       ".\n", ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A deep backlog at a low rate must not wrap the wait computation. */
static int test_mb_ecn_snd_wait_no_overflow(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            want;
        uint64_t            ftag;
        time_t              wait;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate     = 8192;
        ctx->inv_rate = mb_ecn_rate_inv(8192);

        /* 128 flows x 1400 B of SFQ lead at the floor rate. */
        ftag = 128 * 1400;

        wait = mb_ecn_snd(ctx, 1400, 0, &ftag);
        want = (uint64_t) 128 * 1400 * BILLION / 8192;

        if ((uint64_t) wait < want - want / 100 ||
            (uint64_t) wait > want + want / 100) {
                printf("Wait wrapped: exp ~%" PRIu64 ", got %" PRIu64 ".\n",
                       want, (uint64_t) wait);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A fully paced-backlogged flow reads backlogged after a window. */
static int test_mb_ecn_backlogged_paced(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->backlogged = false;   /* prove a window close re-earns it */

        drive_backlogged(ctx, &ftag, MS, 4 * CA_SND_WIN, LEN);

        if (!ctx->backlogged) {
                printf("paced-backlogged flow read source-limited.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * A source-limited flow is capped to the next quarter-log2 headroom
 * above the offered estimate, and NOT re-floored to a high capacity
 * rate_min.
 */
static int test_mb_ecn_source_limited_ceiling(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;
        uint64_t            t = 10 * MS;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->tx_cav     = true;
        ctx->started    = true;
        ctx->backlogged = false;
        ctx->rate       = (uint64_t) 100 << 20;
        ctx->inv_rate   = mb_ecn_rate_inv(ctx->rate);
        ctx->rate_min   = (uint64_t) 50 << 20;
        ctx->snd_rate   = (uint64_t) 1 << 20;
        ctx->snd_r0     = ctx->rate;
        ctx->snd_win    = t;
        ctx->last_ts    = t;
        ctx->last_ctrl  = t;

        mb_ecn_snd(ctx, LEN, t + 2 * MS, &ftag);

        if (ctx->rate != ((uint64_t) 2 << 20)) {
                printf("ceiling: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) 2 << 20, ctx->rate);
                goto fail_ctx;
        }

        if (!ctx->src_limited) {
                printf("ceiling bound but src_limited not set.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* One quiet window must not collapse the max-filter; it decays ~1/16. */
static int test_mb_ecn_max_filter(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;
        uint64_t            hi = (uint64_t) 10 << 20;
        uint64_t            t = 10 * MS;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->started   = true;
        ctx->snd_rate  = hi;
        ctx->snd_r0    = hi;
        ctx->snd_byt   = 0;
        ctx->snd_win   = t;
        ctx->last_ts   = t;
        ctx->last_ctrl = t;

        /* Close one window with almost no bytes offered. */
        mb_ecn_snd(ctx, LEN, t + CA_SND_WIN + 1, &ftag);

        if (ctx->snd_rate >= hi || ctx->snd_rate < hi - hi / 8) {
                printf("max-filter: exp ~15/16 of %" PRIu64 ", got %"
                       PRIu64 " after one quiet window.\n",
                       hi, ctx->snd_rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A >CA_DT_CAP gap clears backlogged without touching the estimate. */
static int test_mb_ecn_idle_clears_backlogged(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;
        uint64_t            snd_rate = (uint64_t) 5 << 20;
        uint64_t            t = 10 * MS;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->started    = true;
        ctx->backlogged = true;
        ctx->snd_rate   = snd_rate;
        ctx->snd_win    = t;
        ctx->last_ts    = t;
        ctx->last_ctrl  = t;

        /* 55 ms gap: past CA_DT_CAP, under CA_SND_WIN (no window close). */
        mb_ecn_snd(ctx, LEN, t + 55 * MS, &ftag);

        if (ctx->backlogged) {
                printf("idle gap did not clear backlogged.\n");
                goto fail_ctx;
        }

        if (ctx->snd_rate != snd_rate) {
                printf("idle step altered snd_rate %" PRIu64 ".\n",
                       ctx->snd_rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The first send is never misread as idle, whatever the wall clock. */
static int test_mb_ecn_first_send_warmup(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* started == false; a large first timestamp must not look idle. */
        mb_ecn_snd(ctx, LEN, 500 * MS, &ftag);

        if (!ctx->started) {
                printf("first send did not set the warm-up sentinel.\n");
                goto fail_ctx;
        }

        if (!ctx->backlogged) {
                printf("first send misclassified as idle.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int mb_ecn_test(int     argc,
                char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_mb_ecn_ctx_create_destroy();
        ret |= test_mb_ecn_calc_ecn();
        ret |= test_mb_ecn_rcv_onset_immediate();
        ret |= test_mb_ecn_rcv_window_mean();
        ret |= test_mb_ecn_rcv_rate_independent();
        ret |= test_mb_ecn_rcv_size_fair();
        ret |= test_mb_ecn_rcv_release_exact_zero();
        ret |= test_mb_ecn_rcv_gap_restart();
        ret |= test_mb_ecn_rcv_accum_bounds();
        ret |= test_mb_ecn_rcv_window_holds_target();
        ret |= test_mb_ecn_rcv_window_clip_bounds();
        ret |= test_mb_ecn_rcv_slow_window();
        ret |= test_mb_ecn_rcv_no_overflow_highrate();
        ret |= test_mb_ecn_ece_ttl_covers_cadence();
        ret |= test_mb_ecn_slow_start();
        ret |= test_mb_ecn_dt_scaling_invariant();
        ret |= test_mb_ecn_probe_scale_invariant();
        ret |= test_mb_ecn_multiplicative_decrease();
        ret |= test_mb_ecn_fixed_point();
        ret |= test_mb_ecn_lead_cut();
        ret |= test_mb_ecn_slow_start_local_brake();
        ret |= test_mb_ecn_slow_start_clean_ramp();
        ret |= test_mb_ecn_starved_decrease_escape();
        ret |= test_mb_ecn_starved_local_fallback();
        ret |= test_mb_ecn_decrease_dt_invariant();
        ret |= test_mb_ecn_idle_resume_bounded();
        ret |= test_mb_ecn_rate_floor();
        ret |= test_mb_ecn_ece_staleness();
        ret |= test_mb_ecn_ece_ttl_tracks_rate();
        ret |= test_mb_ecn_sfq_pace();
        ret |= test_mb_ecn_probe_time_constant();
        ret |= test_mb_ecn_rcv_cap_window_min();
        ret |= test_mb_ecn_rcv_cap_onset_fresh();
        ret |= test_mb_ecn_ece_cap_derives_rates();
        ret |= test_mb_ecn_ece_cap_zero_keeps_rates();
        ret |= test_mb_ecn_ece_cap_clamps();
        ret |= test_mb_ecn_cap_ttl_reverts();
        ret |= test_mb_ecn_ctrl_per_ctx_ai();
        ret |= test_mb_ecn_ctrl_per_ctx_floor();
        ret |= test_mb_ecn_snd_slow_rate_paced();
        ret |= test_mb_ecn_snd_idle_burst_bound();
        ret |= test_mb_ecn_snd_wait_no_overflow();
        ret |= test_mb_ecn_backlogged_paced();
        ret |= test_mb_ecn_source_limited_ceiling();
        ret |= test_mb_ecn_max_filter();
        ret |= test_mb_ecn_idle_clears_backlogged();
        ret |= test_mb_ecn_first_send_warmup();

        return ret;
}
