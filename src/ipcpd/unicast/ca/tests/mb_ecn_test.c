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
        ctx->last_sig  = 0;
        ctx->last_loc  = 0;
        ctx->last_cap  = 0;

        ctx->snd_byt     = 0;
        ctx->snd_win     = 0;
        ctx->snd_r0      = CA_RATE_INIT;
        ctx->snd_rate    = CA_RATE_INIT;
        ctx->backlogged  = true;
        ctx->src_limited = false;
        ctx->started     = false;
        ctx->ss_tc       = 20 * MS; /* fixed slope for deterministic SS */

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

        if (ctx->cap_rate != CA_RATE_MIN) {
                printf("Bad initial floor %" PRIu64 ".\n", ctx->cap_rate);
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

/* The pricing window derives from the declared RTT. */
static int test_mb_ecn_init_window(void)
{
        TEST_START();

        /* A fabric RTT lands on the floor, not below it. */
        mb_ecn_init(1);

        if (mb_ecn_tw != CA_TW_MIN) {
                printf("fabric window %" PRIu64 ".\n", mb_ecn_tw);
                goto fail;
        }

        /* A WAN RTT caps the window. */
        mb_ecn_init(200);

        if (mb_ecn_tw != CA_TW) {
                printf("wan window %" PRIu64 ".\n", mb_ecn_tw);
                goto fail;
        }

        /* An unspecified RTT takes the default and caps the window. */
        mb_ecn_init(0);

        if (mb_ecn_tw != CA_TW) {
                printf("default window %" PRIu64 ".\n", mb_ecn_tw);
                goto fail;
        }

        mb_ecn_init(CA_SS_RTT_DEF);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        mb_ecn_init(CA_SS_RTT_DEF);
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Queue depth (packets) that reads as full congestion. */
#define FULL_PKTS (CA_MARK_KNEE << ((CA_ECE_REF >> CA_SHFT) / 4))

static int test_mb_ecn_calc_ecn(void)
{
        uint8_t ecn;

        TEST_START();

        /* One packet in the queue is the floor: it marks nothing. */
        ecn = 0;

        mb_ecn_calc_ecn(1400, &ecn, QOS_CUBE_BE, 1400);

        if (ecn != 0) {
                printf("Single packet marked %u.\n", ecn);
                goto fail;
        }

        /* An unknown mean packet size cannot mark. */
        ecn = 0;

        mb_ecn_calc_ecn(1400, &ecn, QOS_CUBE_BE, 0);

        if (ecn != 0) {
                printf("Unknown mean marked %u.\n", ecn);
                goto fail;
        }

        /* Each doubling of the queue adds 4. */
        ecn = 0;

        mb_ecn_calc_ecn(2 * 1400, &ecn, QOS_CUBE_BE, 1400);

        if (ecn != 4) {
                printf("Expected ecn 4 at 2 packets, got %u.\n", ecn);
                goto fail;
        }

        /* FULL_PKTS packets is full congestion. */
        ecn = 0;

        mb_ecn_calc_ecn(FULL_PKTS * 1400, &ecn, QOS_CUBE_BE, 1400);

        if (ecn != (CA_ECE_REF >> CA_SHFT)) {
                printf("Expected ecn %u at full, got %u.\n",
                       CA_ECE_REF >> CA_SHFT, ecn);
                goto fail;
        }

        /* The same packet count marks the same at any packet size. */
        ecn = 0;

        mb_ecn_calc_ecn(FULL_PKTS * 200, &ecn, QOS_CUBE_BE, 200);

        if (ecn != (CA_ECE_REF >> CA_SHFT)) {
                printf("Size dependence: exp %u, got %u.\n",
                       CA_ECE_REF >> CA_SHFT, ecn);
                goto fail;
        }

        /* MAX keeps the larger value; a smaller mark cannot lower it. */
        ecn = 0x80;

        mb_ecn_calc_ecn(2 * 1400, &ecn, QOS_CUBE_BE, 1400);

        if (ecn != 0x80) {
                printf("Expected ecn 0x80, got 0x%x.\n", ecn);
                goto fail;
        }

        ecn = 3;

        mb_ecn_calc_ecn(4 * 1400, &ecn, QOS_CUBE_BE, 1400);

        if (ecn != 8) {
                printf("Expected ecn 8, got %u.\n", ecn);
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

        t = 2 * MS + 10 * CA_TW;
        if (!mb_ecn_rcv(ctx, LEN, 5, 0, &ece, &fcap, t)) {
                printf("gap restart did not update.\n");
                goto fail_ctx;
        }

        if (ece != 5 << CA_SHFT) {
                printf("gap restart: exp %u, got %u.\n", 5 << CA_SHFT, ece);
                goto fail_ctx;
        }

        t += 10 * CA_TW;
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

/*
 * At a floored layer RTT, rx_tw sits at CA_TW_MIN, so 4 * rx_tw is
 * well under CA_ECE_TTL. A gap in that band must still close the
 * window as a diluted average, not restart fresh: a fresh restart
 * always emits the raw undiluted mark (ecn << CA_SHFT), so an ece
 * that low pins the CA_ECE_TTL floor in mb_ecn_rcv_fresh.
 */
static int test_mb_ecn_rcv_gap_floor(void)
{
        struct mb_ecn_ctx * ctx;
        uint16_t            ece;
        uint8_t             fcap;
        uint64_t            t;

        TEST_START();

        mb_ecn_init(2);

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        if (ctx->rx_tw != CA_TW_MIN) {
                printf("window not floored: %" PRIu64 ".\n", ctx->rx_tw);
                goto fail_ctx;
        }

        /* Onset, then a second packet inside the window: mark banked. */
        mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, MS);
        mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, 2 * MS);

        /* 20 ms gap: past 4 * rx_tw (16 ms), well under CA_ECE_TTL. */

        t = 2 * MS + 20 * MS;
        if (!mb_ecn_rcv(ctx, LEN, 8, 0, &ece, &fcap, t)) {
                printf("window did not close.\n");
                goto fail_ctx;
        }

        /* A fresh restart would emit the raw mark 8 << CA_SHFT, undiluted. */
        if (ece >= (8 << CA_SHFT)) {
                printf("gap read as a fresh onset: ece %u.\n", ece);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);
        mb_ecn_init(CA_SS_RTT_DEF);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(ctx);
 fail:
        mb_ecn_init(CA_SS_RTT_DEF);
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

        /* Two packets at dt just under CA_TW straddle the boundary. */
        t = MS + CA_TW - 1;
        if (mb_ecn_rcv(ctx, LEN, 15, 0, &ece, &fcap, t)) {
                printf("update before the window closed.\n");
                goto fail_ctx;
        }

        t += CA_TW - 1;
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

/*
 * The window floors at CA_TW, tracks the rate below the knee,
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

        /* 1 GbE is above the high knee: the window floors at CA_TW. */
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

        if (ctx->rx_tw != CA_TW) {
                printf("high-rate window: exp %" PRIu64 ", got %" PRIu64
                       ".\n", (uint64_t) CA_TW, ctx->rx_tw);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        /* 1 Mbps: below the knee, ~16 pkts = 16 * 8 ms = 131 ms. */
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
        mb_ecn_rcv(ctx, 10, 8, 0, &ece, &fcap, MS + CA_TW);

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
        ctx->rx_ts  = 2 * CA_TW - 2;

        ok = mb_ecn_rcv(ctx, LEN, 15, 0, &ece, &fcap, 2 * CA_TW - 1);

        if (!ok) {
                printf("max-window close did not fire.\n");
                goto fail_ctx;
        }

        if (ece > 8160) {
                printf("estimate %u wrapped.\n", ece);
                goto fail_ctx;
        }

        /* A wrapped numerator drives rx_tw to MAX; it must descend. */
        if (ctx->rx_tw > CA_TW || ctx->rx_tw < CA_TW) {
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
 * 2 * CA_TW); a repeated mark adds only the proportional cut.
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

        /* Sends between feedbacks spaced 2 * CA_TW + 5 ms apart. */
        t = MS;
        for (i = 0; i < 4; i++) {
                t += (2 * CA_TW + 5 * MS) / 4;
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

        /* a: one 30 ms step. */
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

/*
 * The hold releases on fresh feedback below the gate and on nothing
 * above it: a standing mark of 20 controllers is unsaturated but at
 * the gate, so it holds, where it once released below the clamp.
 */
static int test_mb_ecn_ai_hold_release(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            r0 = (uint64_t) 100 << 20;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* A saturated mark keeps the hold: the queue has not drained. */
        ctx->ai_hold = true;

        mb_ecn_ece(ctx, CA_ECE_MAX, 0, MS);

        if (!ctx->ai_hold) {
                printf("saturated feedback released the hold.\n");
                goto fail_ctx;
        }

        /* A standing mark of 20 controllers is at the gate: hold. */
        mb_ecn_ece(ctx, 22 << CA_SHFT, 0, 2 * MS);

        if (!ctx->ai_hold) {
                printf("a mark above the gate released the hold.\n");
                goto fail_ctx;
        }

        /* The gate itself holds; one step under it releases. */
        mb_ecn_ece(ctx, CA_ECE_REF, 0, 3 * MS);

        if (!ctx->ai_hold) {
                printf("the reference mark released the hold.\n");
                goto fail_ctx;
        }

        mb_ecn_ece(ctx, CA_ECE_REF - 1, 0, 4 * MS);

        if (ctx->ai_hold) {
                printf("feedback below the gate held the increase.\n");
                goto fail_ctx;
        }

        /* The ece 0 release is fresh feedback too. */
        ctx->ai_hold = true;

        mb_ecn_ece(ctx, 0, 0, 5 * MS);

        if (ctx->ai_hold) {
                printf("an ece 0 release held the increase.\n");
                goto fail_ctx;
        }

        /* The decrease still scales with the mark saturated at CA_ECE_MAX. */
        ctx->rate    = r0;
        ctx->tx_cav  = true;
        ctx->tx_ece  = CA_ECE_MAX;
        ctx->tx_ecp  = CA_ECE_MAX;
        ctx->dec_acc = 0;

        mb_ecn_decrease(ctx, MILLION);

        if (ctx->rate > r0 - r0 / 700) {
                printf("clamped decrease too weak: %" PRIu64 ".\n", ctx->rate);
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

        /*
         * A starved 600 ms at full mark takes the rate/2 branch, far
         * below the floor; stays inside the initial ~976 ms mark TTL.
         */
        ctx->rate = CA_RATE_MIN + 1000;
        mb_ecn_ece(ctx, CA_ECE_REF, 0, 0);
        mb_ecn_snd(ctx, LEN, 600 * MS, &ftag);

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

/* The lead is two-sided: it cuts on a rise and gives back on a fall. */
static int test_mb_ecn_lead_symmetric(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            r0 = (uint64_t) 100 << 20;
        uint64_t            net;
        uint64_t            drop;
        uint64_t            gain;
        uint64_t            kd2;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->tx_cav = true;

        /* Rise of one reference: cut rate / CA_MD_KD_DIV, no more. */
        ctx->rate    = r0;
        ctx->tx_ece  = CA_ECE_REF;
        ctx->tx_ecp  = 0;
        ctx->dec_acc = 0;

        mb_ecn_decrease(ctx, 0);

        drop = r0 - ctx->rate;
        if (drop != r0 / CA_MD_KD_DIV) {
                printf("rise cut %" PRIu64 ", want %" PRIu64 ".\n",
                       drop, r0 / CA_MD_KD_DIV);
                goto fail_ctx;
        }

        /* Fall of one reference: give the same fraction back. */
        ctx->rate    = r0;
        ctx->tx_ece  = 1;
        ctx->tx_ecp  = CA_ECE_REF + 1;
        ctx->dec_acc = 0;

        mb_ecn_decrease(ctx, 0);

        gain = ctx->rate - r0;
        if (gain != r0 / CA_MD_KD_DIV) {
                printf("fall boost %" PRIu64 ", want %" PRIu64 ".\n",
                       gain, r0 / CA_MD_KD_DIV);
                goto fail_ctx;
        }

        /* A collapse from deep saturation is clamped to the same. */
        ctx->rate    = r0;
        ctx->tx_ece  = 1;
        ctx->tx_ecp  = 255 << CA_SHFT;
        ctx->dec_acc = 0;

        mb_ecn_decrease(ctx, 0);

        gain = ctx->rate - r0;
        if (gain != r0 / CA_MD_KD_DIV) {
                printf("unclamped fall boost %" PRIu64 ".\n", gain);
                goto fail_ctx;
        }

        /* A cycle that stays marked nets out: no standing bias. */
        ctx->rate    = r0;
        ctx->tx_ecp  = 4 << CA_SHFT;
        ctx->tx_ece  = 12 << CA_SHFT;
        ctx->dec_acc = 0;

        mb_ecn_decrease(ctx, 0);

        ctx->tx_ece  = 4 << CA_SHFT;
        ctx->dec_acc = 0;

        mb_ecn_decrease(ctx, 0);

        net = ctx->rate > r0 ? ctx->rate - r0 : r0 - ctx->rate;
        /*
         * The two lead steps compound to (1 - x)(1 + x), x = 1 /
         * (2 * CA_MD_KD_DIV), so net ~= r0 / (4 * CA_MD_KD_DIV^2).
         * Band it a factor of 2 either side so a materially weaker
         * gain (e.g. KD off by a factor of 4) fails the floor.
         */
        kd2 = (uint64_t) CA_MD_KD_DIV * CA_MD_KD_DIV;
        if (net > r0 / (2 * kd2)) {
                printf("cycle bias %" PRIu64 " of %" PRIu64 ".\n", net, r0);
                goto fail_ctx;
        }

        if (net < r0 / (8 * kd2)) {
                printf("lead gain weaker than expected: net %" PRIu64
                       " of %" PRIu64 ".\n", net, r0);
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

/* Sub-ms control steps must not lose decrease time to truncation. */
static int test_mb_ecn_decrease_subms_carry(void)
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

        /* Same 30 ms of marked time; b's steps have a 0.5 ms tail. */
        for (i = 1; i <= 10; i++)
                mb_ecn_snd(a, LEN, i * 3 * MS, &fta);

        for (i = 1; i <= 20; i++)
                mb_ecn_snd(b, LEN, i * 3 * MS / 2, &ftb);

        cut_a = r0 - a->rate;
        cut_b = r0 - b->rate;

        if (cut_a == 0 || cut_b == 0) {
                printf("no cut: %" PRIu64 " %" PRIu64 ".\n", cut_a, cut_b);
                goto fail_ctx;
        }

        /* Within 10%: the sub-ms remainder must carry, not vanish. */
        if (cut_a > cut_b + cut_a / 10 || cut_b > cut_a + cut_a / 10) {
                printf("sub-ms decrease lost: %" PRIu64 " vs %" PRIu64
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
        ctx->cap_rate = 8192;
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
        ctx->backlogged = true;
        r0 = ctx->rate;

        /* 8000 x 1 ms of clean growth, driven via the feedback path. */
        t = 0;
        for (i = 0; i < 8000; i++) {
                t += MS;
                mb_ecn_ece(ctx, 0, 0, t);
        }

        /* Undamped probe: 8 s at TC 8 s is one full e-fold, ~2.72x. */
        ratio = (double) ctx->rate / r0;
        if (ratio < 2.6 || ratio > 2.85) {
                printf("probe TC off: exp ~2.72, got %.3fx over 8 s.\n", ratio);
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

        t = 3 * MS + CA_TW;
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
                t += CA_TW;
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
        t = 2 * MS + 5 * CA_TW;
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
        if (ctx->cap_rate != want) {
                printf("Floor: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       want, ctx->cap_rate);
                goto fail_ctx;
        }

        if (ctx->ai_rate != 2 * ctx->cap_rate) {
                printf("AI slope did not track the floor.\n");
                goto fail_ctx;
        }

        mb_ecn_ece(ctx, 100, 120, 2 * MS);

        want += (tgt - want) >> CA_CAP_SM_SHFT;
        if (ctx->cap_rate != want) {
                printf("Floor EWMA: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       want, ctx->cap_rate);
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

        if (ctx->cap_rate != CA_RATE_MIN || ctx->ai_rate != CA_AI_RATE) {
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

        if (ctx->cap_rate != CA_RATE_MIN) {
                printf("Slow path lowered the floor: %" PRIu64 ".\n",
                       ctx->cap_rate);
                goto fail_ctx;
        }

        /* A absurdly fast path saturates at the ceiling. */
        for (i = 1; i <= 40; i++)
                mb_ecn_ece(ctx, 100, 255, (1 + i) * MS);

        if (ctx->cap_rate > CA_RMIN_MAX) {
                printf("Floor above the ceiling: %" PRIu64 ".\n",
                       ctx->cap_rate);
                goto fail_ctx;
        }

        if (ctx->cap_rate < CA_RMIN_MAX - 4) {
                printf("Floor did not reach the ceiling: %" PRIu64 ".\n",
                       ctx->cap_rate);
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

        if (ctx->cap_rate == CA_RATE_MIN) {
                printf("Capacity did not derive a floor.\n");
                goto fail_ctx;
        }

        /* Just inside the TTL: the derived rates hold. */
        mb_ecn_snd(ctx, LEN, MS + (ctx->ece_ttl << CA_CAP_TTL_SHFT), &ftag);

        if (ctx->cap_rate == CA_RATE_MIN) {
                printf("Derived rates reverted too early.\n");
                goto fail_ctx;
        }

        /* Past the TTL: back to the defaults. */
        mb_ecn_snd(ctx, LEN, MS + (ctx->ece_ttl << CA_CAP_TTL_SHFT) + 1,
                   &ftag);

        if (ctx->cap_rate != CA_RATE_MIN || ctx->ai_rate != CA_AI_RATE) {
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
/*
 * cap_rate seeds the slope and nothing else. It floored the rate
 * once, and this scenario asserted that: 30 ms at the reference mark
 * from just above it landed exactly on it. That floor is what pinned
 * n > 32 controllers at n / 32 of the link. Now the reference mark
 * holds the increase and the rate sheds straight through cap_rate;
 * only CA_RATE_MIN is a floor. Below the gate the increase keeps a
 * probing controller above 2 * cap_rate on its own (the fixpoint
 * ai / (m / m_ref - 1 / T_probe) at m < m_ref), so nothing is lost.
 */
static int test_mb_ecn_ctrl_no_capacity_floor(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->cap_rate = (uint64_t) 1 << 20;
        ctx->ai_rate  = 2 * ctx->cap_rate;
        ctx->tx_cap   = cap_enc((uint64_t) 1 << (20 + CA_CAP_SHFT));
        ctx->rate     = ((uint64_t) 1 << 20) + 1000;

        mb_ecn_ece(ctx, CA_ECE_REF, 0, 0);
        mb_ecn_snd(ctx, LEN, 30 * MS, &ftag);

        if (!ctx->ai_hold) {
                printf("not held at the reference mark.\n");
                goto fail_ctx;
        }

        if (ctx->rate >= ctx->cap_rate) {
                printf("cap_rate floored the rate: %" PRIu64 ".\n",
                       ctx->rate);
                goto fail_ctx;
        }

        if (ctx->rate < (uint64_t) CA_RATE_MIN) {
                printf("absolute floor breached: %" PRIu64 ".\n",
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
        ctx->cap_rate = 8192;
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
 * A source-limited flow is capped to the backlog level above the
 * offered estimate, and NOT re-floored to a high capacity rate_min.
 */
static int test_mb_ecn_source_limited_ceiling(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;
        uint64_t            t = 10 * MS;
        uint64_t            expect;

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
        ctx->cap_rate   = (uint64_t) 50 << 20;
        ctx->snd_rate   = (uint64_t) 1 << 20;
        ctx->snd_r0     = ctx->rate;
        ctx->snd_win    = t;
        ctx->last_ts    = t;
        ctx->last_ctrl  = t;

        mb_ecn_snd(ctx, LEN, t + 2 * MS, &ftag);

        expect = 1398101;              /* (1 << 20) * 4 / 3, truncated */
        if (ctx->rate != expect) {
                printf("ceiling: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       expect, ctx->rate);
                goto fail_ctx;
        }

        if (!ctx->src_limited) {
                printf("ceiling bound but src_limited not set.\n");
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        /* Non-power-of-two case: verify the exact level, not a step. */

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
        ctx->cap_rate   = (uint64_t) 50 << 20;
        ctx->snd_rate   = (uint64_t) 303 << 12;
        ctx->snd_r0     = ctx->rate;
        ctx->snd_win    = t;
        ctx->last_ts    = t;
        ctx->last_ctrl  = t;

        mb_ecn_snd(ctx, LEN, t + 2 * MS, &ftag);

        expect = 1654784;              /* (303 << 12) * 4 / 3, exact   */
        if (ctx->rate != expect) {
                printf("exact ceiling: exp %" PRIu64 ", got %" PRIu64
                       ".\n", expect, ctx->rate);
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
        ctx->rate       = snd_rate;
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

/*
 * Couple one or two backlogged flows through a shared bottleneck of
 * capacity cap: each step marks the shared queue with the real
 * calc_ecn, feeds each flow that mark delayed by its own lag (in
 * steps), drives it backlogged for one step, then drains the queue.
 * A faithful discrete run of the fluid model on the real control law,
 * with the forwarder abstracted to a single shared price. b may be
 * NULL for a single-flow run.
 */
#define TF_STEP  (5 * MS)          /* control step (ns)         */
#define TF_HIST  64                /* mark ring, bounds max lag */
#define TF_QMAX  (8192 * LEN)      /* bottleneck buffer (bytes) */
#define TF_MAXN  32                /* flows per shared-link run */

static void shared_link_run(struct mb_ecn_ctx * a,
                            struct mb_ecn_ctx * b,
                            uint64_t            cap,
                            size_t              lag_a,
                            size_t              lag_b,
                            size_t              steps)
{
        uint16_t hist[TF_HIST];
        uint64_t ta    = 0;
        uint64_t tb    = 0;
        uint64_t fta   = 0;
        uint64_t ftb   = 0;
        uint64_t q     = 0;
        uint64_t drain = cap * TF_STEP / BILLION;
        uint64_t tgt;
        uint64_t arr;
        uint8_t  cc    = cap_enc(cap);
        uint8_t  ecn;
        uint16_t ea;
        uint16_t eb;
        size_t   k;

        memset(hist, 0, sizeof(hist));

        for (k = 0; k < steps; k++) {
                tgt = (k + 1) * TF_STEP;
                ecn = 0;

                mb_ecn_calc_ecn(q, &ecn, QOS_CUBE_BE, LEN);
                hist[k % TF_HIST] = (uint16_t) (ecn << CA_SHFT);

                ea = k < lag_a ? 0 : hist[(k - lag_a) % TF_HIST];
                if (ea > 0)         /* no feedback until congestion */
                        mb_ecn_ece(a, ea, cc, ta);

                /* Active flow: heartbeat/window liveness stays fresh. */
                a->last_sig = ta;
                if (tgt > ta)
                        ta = drive_backlogged(a, &fta, ta, tgt - ta, LEN);

                arr = a->rate * TF_STEP / BILLION;

                if (b != NULL) {
                        eb = k < lag_b ? 0 : hist[(k - lag_b) % TF_HIST];
                        if (eb > 0)
                                mb_ecn_ece(b, eb, cc, tb);

                        b->last_sig = tb;
                        if (tgt > tb)
                                tb = drive_backlogged(b, &ftb, tb,
                                                      tgt - tb, LEN);

                        arr += b->rate * TF_STEP / BILLION;
                }

                q += arr;
                q  = q > drain ? q - drain : 0;
                if (q > (uint64_t) TF_QMAX)
                        q = TF_QMAX;
        }
}

/*
 * Two flows sharing one bottleneck, both fed every queue mark, must
 * converge from a lopsided start toward an equal split (the fluid
 * model's drho/dt -> 0) rather than latch winner-take-all. Isolates
 * the rate law from the forwarder: neither flow is starved of marks.
 */
static int test_mb_ecn_two_flow_converge(void)
{
        struct mb_ecn_ctx * a;
        struct mb_ecn_ctx * b;
        uint64_t            cap  = 1ULL << 20;
        uint64_t            fair = (1ULL << 20) / 2;
        uint64_t            lo;
        uint64_t            hi;

        TEST_START();

        a = mk_ctx();
        b = mk_ctx();
        if (a == NULL || b == NULL) {
                printf("Failed to create contexts.\n");
                goto fail_ctx;
        }

        a->rate = cap;             /* a hogs, b starts small */
        b->rate = CA_RATE_INIT;

        shared_link_run(a, b, cap, 0, 0, 6000);

        lo = a->rate < b->rate ? a->rate : b->rate;
        hi = a->rate > b->rate ? a->rate : b->rate;

        if (lo < fair / 4) {
                printf("flow starved: %" PRIu64 " / %" PRIu64 ".\n",
                       a->rate, b->rate);
                goto fail_ctx;
        }

        if (hi > 3 * lo) {
                printf("did not converge: %" PRIu64 " / %" PRIu64 ".\n",
                       a->rate, b->rate);
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
 * A remote bottleneck exits slow start only on fed-back congestion,
 * so a longer feedback delay lets the exponential ramp overshoot
 * further: the slow-start peak grows with RTT. Nothing caps the ramp
 * at the path capacity, so the sender latches near the first-hop rate.
 */
static int test_mb_ecn_ramp_overshoot_grows_with_rtt(void)
{
        struct mb_ecn_ctx * lo_rtt;
        struct mb_ecn_ctx * hi_rtt;
        uint64_t            cap = 1ULL << 20;

        TEST_START();

        lo_rtt = mk_ctx();
        hi_rtt = mk_ctx();
        if (lo_rtt == NULL || hi_rtt == NULL) {
                printf("Failed to create contexts.\n");
                goto fail_ctx;
        }

        /* Same bottleneck; feedback lags 1 vs 8 steps (~5 vs 40 ms). */
        shared_link_run(lo_rtt, NULL, cap, 1, 0, 2000);
        shared_link_run(hi_rtt, NULL, cap, 8, 0, 2000);

        if (hi_rtt->ss_peak <= lo_rtt->ss_peak) {
                printf("overshoot did not grow with RTT: %" PRIu64
                       " vs %" PRIu64 ".\n",
                       hi_rtt->ss_peak, lo_rtt->ss_peak);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(lo_rtt);
        mb_ecn_ctx_destroy(hi_rtt);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_ctx:
        mb_ecn_ctx_destroy(lo_rtt);
        mb_ecn_ctx_destroy(hi_rtt);
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * Flows sharing a context offer bytes together against one rate, the
 * path's, so the window compares the two as they are. Four flows
 * offering two thirds of the rate between them read source-limited;
 * the whole rate between them reads backlogged, with no share-out by
 * flow count in between.
 */
static int test_mb_ecn_shared_ctx_offered_aggregate(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            rate = 1000000;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate      = rate;
        ctx->snd_flows = 4;
        ctx->snd_r0    = rate;
        ctx->snd_win   = 0;
        ctx->snd_byt   = rate * 2 / 3;

        mb_ecn_win(ctx, BILLION);

        if (ctx->backlogged) {
                printf("two thirds of the rate read as backlogged.\n");
                goto fail_ctx;
        }

        /* The close left a fresh window; the whole rate clears it. */
        ctx->snd_byt = rate;

        mb_ecn_win(ctx, 2 * BILLION);

        if (!ctx->backlogged) {
                printf("the whole rate was shared out by flow count.\n");
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
 * A join or a leave opens a fresh window, so none divides the bytes
 * one population offered by the count of another. An unchanged count
 * leaves the running window alone.
 */
static int test_mb_ecn_flow_count_restarts_window(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            rate = 1000000;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->rate      = rate;
        ctx->snd_flows = 2;
        ctx->snd_win   = MS;
        ctx->snd_byt   = 12345;
        ctx->snd_r0    = 7;

        mb_ecn_flows(ctx, 5, 8 * MS);

        if (ctx->snd_flows != 5 || ctx->snd_byt != 0
            || ctx->snd_win != 8 * MS || ctx->snd_r0 != rate) {
                printf("count change left a stale window: flows=%zu "
                       "byt=%" PRIu64 " win=%" PRIu64 " r0=%" PRIu64
                       ".\n", ctx->snd_flows, ctx->snd_byt,
                       ctx->snd_win, ctx->snd_r0);
                goto fail_ctx;
        }

        ctx->snd_byt = 999;

        mb_ecn_flows(ctx, 5, 20 * MS);

        if (ctx->snd_byt != 999 || ctx->snd_win != 8 * MS) {
                printf("unchanged count restarted the window.\n");
                goto fail_ctx;
        }

        /* An empty context still measures a single sender. */
        mb_ecn_flows(ctx, 0, 30 * MS);

        if (ctx->snd_flows != 1) {
                printf("zero flows did not floor at one: %zu.\n",
                       ctx->snd_flows);
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
 * The ceiling must land where a window of the delivered rate reads
 * backlogged again: a context clamped above that level can never
 * leave the clamp, and loses its capacity floor with it.
 */
static int test_mb_ecn_ceiling_clears_backlog(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            x = 1 << 20;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->backlogged = false;
        ctx->snd_rate   = x;
        ctx->rate       = 100 * x;
        ctx->cap_rate   = CA_RATE_MIN;

        mb_ecn_ceiling(ctx);

        if (ctx->rate >= 100 * x) {
                printf("ceiling did not bind: %" PRIu64 ".\n", ctx->rate);
                goto fail_ctx;
        }

        /* One window delivering x, with the pacer deferring nothing. */
        ctx->snd_r0    = ctx->rate;
        ctx->snd_flows = 1;
        ctx->snd_win   = 0;
        ctx->snd_byt   = x;
        ctx->snd_pac   = 0;

        mb_ecn_win(ctx, BILLION);

        if (!ctx->backlogged) {
                printf("clamped at %" PRIu64 " cannot clear on %" PRIu64
                       ".\n", ctx->snd_r0, x);
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
 * ------------------------------------------------------------------
 * Flows sharing one ctx, read the way psched reads them: each flow
 * holds the deadline the pacer set, the earliest due flow sends next,
 * ties go round-robin, and a flow given no wait is read again in the
 * next round. A greedy flow always has a packet; one past its stop
 * time has none and no longer holds the ctx (ca_ctx_put).
 * ------------------------------------------------------------------
 */
#define SH_MAXN 8

struct sh_flow {
        uint64_t ftag;
        uint64_t due;        /* next read (ns), UINT64_MAX = gone */
        size_t   len;
        uint64_t t1;         /* stop time (ns), 0 = runs to end   */
        uint64_t bytes;      /* admitted from t_from on           */
};

static struct mb_ecn_ctx * sh_ctx(uint64_t rate)
{
        struct mb_ecn_ctx * ctx;

        ctx = mk_ctx();
        if (ctx == NULL)
                return NULL;

        /* AIMD with no marks and the increase held: the rate stands. */
        ctx->rate     = rate;
        ctx->inv_rate = mb_ecn_rate_inv(rate);
        ctx->tx_cav   = true;
        ctx->ai_hold  = true;

        return ctx;
}

/*
 * Serve the flows on ctx from t to end, counting each flow's bytes
 * from t_from and the widest run of packets admitted at one instant.
 */
static void sh_run(struct mb_ecn_ctx * ctx,
                   struct sh_flow *    fl,
                   size_t              n,
                   uint64_t            t,
                   uint64_t            end,
                   uint64_t            t_from,
                   size_t *            burst)
{
        uint64_t last = UINT64_MAX;
        size_t   run  = 0;
        size_t   k    = n - 1;
        size_t   live;
        size_t   i;
        size_t   j;
        time_t   w;

        *burst = 0;

        for (i = 0; i < n; i++) {
                fl[i].due   = t;
                fl[i].bytes = 0;
        }

        while (true) {
                uint64_t nxt = UINT64_MAX;
                size_t   pick = 0;

                live = 0;

                for (j = 0; j < n; j++) {
                        i = (k + 1 + j) % n;

                        if (fl[i].t1 > 0 && fl[i].due >= fl[i].t1)
                                fl[i].due = UINT64_MAX;

                        if (fl[i].due != UINT64_MAX)
                                live++;

                        if (fl[i].due < nxt) {
                                nxt  = fl[i].due;
                                pick = i;
                        }
                }

                if (nxt >= end)
                        break;

                k = pick;

                mb_ecn_flows(ctx, live, nxt);

                w = mb_ecn_snd(ctx, fl[k].len, nxt, &fl[k].ftag);

                if (nxt >= t_from) {
                        fl[k].bytes += fl[k].len;
                        run = nxt == last ? run + 1 : 1;
                        if (run > *burst)
                                *burst = run;
                }

                last      = nxt;
                fl[k].due = nxt + (w > 0 ? (uint64_t) w : 0);
        }
}

/* |got - want| <= want * pct / 100 */
static bool sh_near(uint64_t got,
                    uint64_t want,
                    uint64_t pct)
{
        uint64_t tol = want * pct / 100;

        return got + tol >= want && got <= want + tol;
}

/*
 * Four greedy flows on one ctx divide its rate: together they admit
 * the rate, each a quarter, the pacer counts four deferred flows, and
 * a round goes out one packet at a time, not as a burst of four.
 */
static int test_mb_ecn_sfq_share_rate(void)
{
        struct mb_ecn_ctx * ctx;
        struct sh_flow      fl[4];
        uint64_t            rate = 1U << 20;
        uint64_t            tot  = 0;
        size_t              burst;
        size_t              i;

        TEST_START();

        ctx = sh_ctx(rate);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        memset(fl, 0, sizeof(fl));
        for (i = 0; i < 4; i++)
                fl[i].len = LEN;

        /* 400 ms of warm-up, then one second scored. */
        sh_run(ctx, fl, 4, 0, 1400 * MS, 400 * MS, &burst);

        for (i = 0; i < 4; i++)
                tot += fl[i].bytes;

        if (!sh_near(tot, rate, 3)) {
                printf("four flows admitted %" PRIu64 " at rate %" PRIu64
                       ".\n", tot, rate);
                goto fail_ctx;
        }

        for (i = 0; i < 4; i++) {
                if (sh_near(fl[i].bytes, rate / 4, 5))
                        continue;

                printf("flow %zu got %" PRIu64 " of a %" PRIu64 " share.\n",
                       i, fl[i].bytes, rate / 4);
                goto fail_ctx;
        }

        if (!sh_near(ctx->snd_bl, 4ULL << CA_BL_SHFT, 12)) {
                printf("pacer counts %" PRIu64 "/256 deferred flows, not 4.\n",
                       ctx->snd_bl);
                goto fail_ctx;
        }

        if (burst > 2) {
                printf("%zu packets admitted at one instant.\n", burst);
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
 * The share is in bytes: a flow of 9000 B packets and one of 1000 B
 * packets split the rate evenly, nine small packets to one large.
 */
static int test_mb_ecn_sfq_share_bytes(void)
{
        struct mb_ecn_ctx * ctx;
        struct sh_flow      fl[2];
        uint64_t            rate = 1U << 20;
        size_t              burst;

        TEST_START();

        ctx = sh_ctx(rate);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        memset(fl, 0, sizeof(fl));
        fl[0].len = 9000;
        fl[1].len = 1000;

        sh_run(ctx, fl, 2, 0, 3000 * MS, 1000 * MS, &burst);

        if (!sh_near(fl[0].bytes + fl[1].bytes, 2 * rate, 3)) {
                printf("two flows admitted %" PRIu64 " at rate %" PRIu64
                       ".\n", fl[0].bytes + fl[1].bytes, rate);
                goto fail_ctx;
        }

        if (!sh_near(fl[0].bytes, rate, 10)) {
                printf("large packets got %" PRIu64 " of a %" PRIu64
                       " share.\n", fl[0].bytes, rate);
                goto fail_ctx;
        }

        if (!sh_near(fl[1].bytes, rate, 10)) {
                printf("small packets got %" PRIu64 " of a %" PRIu64
                       " share.\n", fl[1].bytes, rate);
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
 * Two of four flows leave: within a few windows the two that stay
 * have the whole rate between them and the pacer counts two.
 */
static int test_mb_ecn_sfq_leave(void)
{
        struct mb_ecn_ctx * ctx;
        struct sh_flow      fl[4];
        uint64_t            rate = 1U << 20;
        size_t              burst;
        size_t              i;

        TEST_START();

        ctx = sh_ctx(rate);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        memset(fl, 0, sizeof(fl));
        for (i = 0; i < 4; i++)
                fl[i].len = LEN;

        fl[2].t1 = BILLION;
        fl[3].t1 = BILLION;

        /* Score the second after 500 ms of settling past the leave. */
        sh_run(ctx, fl, 4, 0, 2500 * MS, 1500 * MS, &burst);

        if (!sh_near(fl[0].bytes + fl[1].bytes, rate, 3)) {
                printf("two flows left admit %" PRIu64 " at rate %" PRIu64
                       ".\n", fl[0].bytes + fl[1].bytes, rate);
                goto fail_ctx;
        }

        if (!sh_near(fl[0].bytes, rate / 2, 5)) {
                printf("flow 0 got %" PRIu64 " of a %" PRIu64 " share.\n",
                       fl[0].bytes, rate / 2);
                goto fail_ctx;
        }

        if (!sh_near(fl[1].bytes, rate / 2, 5)) {
                printf("flow 1 got %" PRIu64 " of a %" PRIu64 " share.\n",
                       fl[1].bytes, rate / 2);
                goto fail_ctx;
        }

        if (!sh_near(ctx->snd_bl, 2ULL << CA_BL_SHFT, 12)) {
                printf("pacer counts %" PRIu64 "/256 deferred flows, not 2.\n",
                       ctx->snd_bl);
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
 * A join widens the round at once, by the flows that joined; a leave
 * is left to the window estimate, since the flow may not have been
 * one the pacer was holding back.
 */
static int test_mb_ecn_flow_join_widens_round(void)
{
        struct mb_ecn_ctx * ctx;

        TEST_START();

        ctx = mk_ctx();
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        mb_ecn_flows(ctx, 3, MS);

        if (ctx->snd_bl != 3ULL << CA_BL_SHFT) {
                printf("two joins left the round at %" PRIu64 "/256.\n",
                       ctx->snd_bl);
                goto fail_ctx;
        }

        mb_ecn_flows(ctx, 2, 2 * MS);

        if (ctx->snd_bl != 3ULL << CA_BL_SHFT) {
                printf("a leave narrowed the round to %" PRIu64 "/256.\n",
                       ctx->snd_bl);
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
 * Five source-limited flows that write in step put five packets in at
 * one instant every 40 ms, an eighth of the rate. The FIFO spreads the
 * burst but that is not the pacer holding anyone to a share: the ctx
 * reads source-limited, the ceiling lands on the load rather than the
 * rate running away, and the spread never counts as a second deferred
 * flow (the ceiling leaves the burst waiting a fraction of a round).
 */
static int test_mb_ecn_fifo_burst_not_backlogged(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag[5];
        uint64_t            rate = 1U << 20;
        uint64_t            t;
        size_t              i;

        TEST_START();

        ctx = sh_ctx(rate);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->ai_hold = false;   /* let the increase run: it must not */

        memset(ftag, 0, sizeof(ftag));

        for (t = 0; t < 2 * BILLION; t += 40 * MS) {
                mb_ecn_flows(ctx, 5, t);
                for (i = 0; i < 5; i++)
                        mb_ecn_snd(ctx, LEN, t, &ftag[i]);
        }

        if (ctx->backlogged) {
                printf("a FIFO-spread burst read as backlogged.\n");
                goto fail_ctx;
        }

        if (ctx->snd_bl >= 2ULL << CA_BL_SHFT) {
                printf("a spread burst counts as %" PRIu64 "/256 deferred "
                       "flows.\n", ctx->snd_bl);
                goto fail_ctx;
        }

        if (ctx->rate >= rate) {
                printf("rate ran off to %" PRIu64 " on an eighth load.\n",
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
 * ------------------------------------------------------------------
 * The hold: gate, stale feedback, loss; one release.
 * ------------------------------------------------------------------
 */

/* A context in AIMD on a scaled link, backlogged, at rate r. */
static struct mb_ecn_ctx * hold_ctx(uint64_t r)
{
        struct mb_ecn_ctx * ctx;

        ctx = mk_ctx();
        if (ctx == NULL)
                return NULL;

        ctx->rate     = r;
        ctx->inv_rate = mb_ecn_rate_inv(r);
        ctx->cap_rate = (uint64_t) 1 << 20;      /* C'/32: a 256 Mb/s path */
        ctx->ai_rate  = 2 * ctx->cap_rate;
        ctx->tx_cav   = true;
        /* The code the path feeds back, as mb_ecn_ece sets it: the gate
           arms on the raw code, not on its EWMA. */
        ctx->tx_cap   = cap_enc((uint64_t) 1 << (20 + CA_CAP_SHFT));

        return ctx;
}

/*
 * The gate: a mark one step under the reference lets the increase
 * run; the reference itself holds it and only the decrease acts. With
 * the slope at its compile-time floor the gate does not engage.
 */
static int test_mb_ecn_gate_at_ref(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            r0 = (uint64_t) 1 << 20;

        TEST_START();

        ctx = hold_ctx(r0);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Under the gate: the increase outruns a 1% cut over 10 ms. */
        ctx->tx_ecp = CA_ECE_REF - 1;   /* no lead: the mark is standing */

        mb_ecn_ece(ctx, CA_ECE_REF - 1, 0, 10 * MS);

        if (ctx->ai_hold) {
                printf("held one step under the gate.\n");
                goto fail_ctx;
        }

        if (ctx->rate <= r0) {
                printf("no increase under the gate: %" PRIu64 ".\n",
                       ctx->rate);
                goto fail_ctx;
        }

        /* At the gate: held, and the rate only sheds. */
        ctx->rate = r0;

        mb_ecn_ece(ctx, CA_ECE_REF, 0, 20 * MS);

        if (!ctx->ai_hold) {
                printf("the reference mark did not hold.\n");
                goto fail_ctx;
        }

        if (ctx->rate >= r0) {
                printf("held, yet the rate rose: %" PRIu64 ".\n", ctx->rate);
                goto fail_ctx;
        }

        if (ctx->n_hold != 1) {
                printf("hold count %" PRIu64 ".\n", ctx->n_hold);
                goto fail_ctx;
        }

        /* Unscaled slope: the same mark does not gate. The code goes
           with it -- the gate reads the code the path fed back, and a
           path at the compile-time floor feeds back a floor code. */
        ctx->ai_hold  = false;
        ctx->cap_rate = CA_RATE_MIN;
        ctx->ai_rate  = 2 * CA_RATE_MIN;
        ctx->tx_cap   = 0;

        mb_ecn_ece(ctx, CA_ECE_REF, 0, 30 * MS);

        if (ctx->ai_hold) {
                printf("gated with the slope at its floor.\n");
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
 * Held under a saturated mark the rate sheds through cap_rate down
 * to CA_RATE_MIN; released by feedback below the gate it climbs
 * again. This is the floor the gate had to remove: n held controllers
 * at C'/32 are n / 32 of the link whatever the mark says.
 */
static int test_mb_ecn_hold_sheds_to_floor(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            r0 = (uint64_t) 2 << 20;
        uint64_t            ftag = 0;
        uint64_t            t = 0;
        size_t              i;

        TEST_START();

        ctx = hold_ctx(r0);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* Saturated feedback every 100 ms for 3 s, sending throughout. */
        for (i = 0; i < 30; i++) {
                mb_ecn_ece(ctx, CA_ECE_MAX, 0, t);
                t = drive_backlogged(ctx, &ftag, t, 100 * MS, LEN);
        }

        if (!ctx->ai_hold) {
                printf("saturated mark did not hold.\n");
                goto fail_ctx;
        }

        if (ctx->rate != CA_RATE_MIN) {
                printf("rate %" PRIu64 " under a saturated mark, cap_rate %"
                       PRIu64 ".\n", ctx->rate, ctx->cap_rate);
                goto fail_ctx;
        }

        /* Released below the gate the increase resumes at once. */
        mb_ecn_ece(ctx, CA_ECE_REF / 4, 0, t);
        t = drive_backlogged(ctx, &ftag, t, 100 * MS, LEN);

        if (ctx->ai_hold) {
                printf("feedback below the gate did not release.\n");
                goto fail_ctx;
        }

        if (ctx->rate <= CA_RATE_MIN) {
                printf("no increase after release: %" PRIu64 ".\n",
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
 * Feedback going stale on a flow still sending holds the increase
 * with the mark it clears, so the rate stands: neither the increase
 * (the mark is gone) nor the decrease (so is the mark). Liveness
 * through the loss horizon then releases it, a path that delivers
 * and reports nothing being clear; the loss cut halves it instead
 * when nothing at all comes back, and stays held.
 */
static int test_mb_ecn_stale_hold(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            r0 = (uint64_t) 1 << 20;
        uint64_t            ftag = 0;
        uint64_t            ttl;
        uint64_t            r1;
        uint64_t            t;
        size_t              i;

        TEST_START();

        ctx = hold_ctx(r0);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        /* One mark below the gate, then silence while sending. */
        mb_ecn_ece(ctx, CA_ECE_REF / 2, 0, MS);
        ttl = ctx->ece_ttl;
        t   = drive_backlogged(ctx, &ftag, MS, ttl + 10 * MS, LEN);

        if (ctx->tx_ece != 0) {
                printf("mark did not age out.\n");
                goto fail_ctx;
        }

        if (!ctx->ai_hold) {
                printf("stale feedback did not hold a sending flow.\n");
                goto fail_ctx;
        }

        /* Frozen: no term acts on a held flow with no mark. */
        r1 = ctx->rate;
        t  = drive_backlogged(ctx, &ftag, t, 200 * MS, LEN);

        if (ctx->rate != r1) {
                printf("held rate moved %" PRIu64 " -> %" PRIu64 ".\n",
                       r1, ctx->rate);
                goto fail_ctx;
        }

        /* Pongs keep coming: released once the loss horizon passes. */
        for (i = 0; i < 6 && ctx->ai_hold; i++) {
                mb_ecn_ctx_rtt(ctx, t, 2 * MS);
                t = drive_backlogged(ctx, &ftag, t, ttl, LEN);
        }

        if (ctx->ai_hold) {
                printf("live silence never released the hold.\n");
                goto fail_ctx;
        }

        if (ctx->n_loss != 0) {
                printf("liveness intact yet %" PRIu64 " loss cuts.\n",
                       ctx->n_loss);
                goto fail_ctx;
        }

        if (ctx->rate <= r1) {
                printf("no increase after release: %" PRIu64 ".\n",
                       ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        /* Silence without liveness: the cut, and the hold stays. */
        ctx = hold_ctx(r0);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ftag = 0;

        mb_ecn_ece(ctx, CA_ECE_REF / 2, 0, MS);
        ttl = ctx->ece_ttl;
        t   = drive_backlogged(ctx, &ftag, MS, CA_HB_LOSS * ttl - 5 * MS,
                               LEN);

        if (ctx->n_loss != 0 || !ctx->ai_hold) {
                printf("cut early, or not held: %" PRIu64 " cuts.\n",
                       ctx->n_loss);
                goto fail_ctx;
        }

        r1 = ctx->rate;
        t  = drive_backlogged(ctx, &ftag, t, 15 * MS, LEN);

        if (ctx->n_loss != 1) {
                printf("dead silence: %" PRIu64 " loss cuts.\n", ctx->n_loss);
                goto fail_ctx;
        }

        if (!ctx->ai_hold) {
                printf("dead silence released the hold.\n");
                goto fail_ctx;
        }

        if (ctx->rate > r1 / 2 + r1 / 100) {
                printf("loss cut left the rate at %" PRIu64 " of %" PRIu64
                       ".\n", ctx->rate, r1);
                goto fail_ctx;
        }

        if (ctx->last_sig != MS) {
                printf("the cut touched the signal clock.\n");
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

/* An idle flow's mark ages out without a hold: silence there is idle. */
static int test_mb_ecn_stale_idle_no_hold(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            ftag = 0;

        TEST_START();

        ctx = hold_ctx((uint64_t) 1 << 20);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        mb_ecn_snd(ctx, LEN, MS, &ftag);
        mb_ecn_ece(ctx, CA_ECE_REF / 2, 0, 2 * MS);

        /* One send after a gap past the idle threshold and the TTL. */
        mb_ecn_snd(ctx, LEN, 2 * MS + ctx->ece_ttl + MS, &ftag);

        if (ctx->backlogged) {
                printf("idle gap read as backlogged.\n");
                goto fail_ctx;
        }

        if (ctx->tx_ece != 0) {
                printf("mark did not age out.\n");
                goto fail_ctx;
        }

        if (ctx->ai_hold) {
                printf("an idle flow was held.\n");
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
 * The loss horizon follows the heartbeat: on a quiet path only pongs
 * carry liveness, one per heartbeat interval plus an RTT. A backlogged
 * flow on an uncongested 0.8 s RTT path (pongs every 1.6 s) is not
 * cut; the same cadence on a path declared fast is, as the feedback
 * horizon alone (1.07 s) says it should be.
 */
static int test_mb_ecn_loss_horizon_tracks_rtt(void)
{
        struct mb_ecn_ctx * ctx;
        uint64_t            r0 = (uint64_t) 1 << 20;
        uint64_t            ftag = 0;
        uint64_t            t;
        size_t              i;

        TEST_START();

        ctx = hold_ctx(r0);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ctx->ss_tc = 1600 * MS;               /* tracking an 0.8 s RTT */

        mb_ecn_ece(ctx, 0, 0, MS);            /* the path has reported */
        t = MS;

        for (i = 0; i < 8; i++) {
                t = drive_backlogged(ctx, &ftag, t, 1600 * MS, LEN);
                mb_ecn_ctx_rtt(ctx, t, 800 * MS);
        }

        if (ctx->n_loss != 0) {
                printf("%" PRIu64 " loss cuts on a quiet long path.\n",
                       ctx->n_loss);
                goto fail_ctx;
        }

        if (ctx->ai_hold) {
                printf("held on a quiet long path.\n");
                goto fail_ctx;
        }

        if (ctx->rate <= r0) {
                printf("no increase on a quiet long path: %" PRIu64 ".\n",
                       ctx->rate);
                goto fail_ctx;
        }

        mb_ecn_ctx_destroy(ctx);

        /* Declared fast, the same silence is collapse. */
        ctx = hold_ctx(r0);
        if (ctx == NULL) {
                printf("Failed to create context.\n");
                goto fail;
        }

        ftag = 0;

        mb_ecn_ece(ctx, 0, 0, MS);
        t = drive_backlogged(ctx, &ftag, MS, 1600 * MS, LEN);

        if (ctx->n_loss == 0) {
                printf("no cut on a fast path silent for 1.6 s.\n");
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
        ret |= test_mb_ecn_init_window();
        ret |= test_mb_ecn_calc_ecn();
        ret |= test_mb_ecn_rcv_onset_immediate();
        ret |= test_mb_ecn_rcv_rate_independent();
        ret |= test_mb_ecn_rcv_size_fair();
        ret |= test_mb_ecn_rcv_release_exact_zero();
        ret |= test_mb_ecn_rcv_gap_restart();
        ret |= test_mb_ecn_rcv_gap_floor();
        ret |= test_mb_ecn_rcv_accum_bounds();
        ret |= test_mb_ecn_rcv_window_clip_bounds();
        ret |= test_mb_ecn_rcv_slow_window();
        ret |= test_mb_ecn_rcv_no_overflow_highrate();
        ret |= test_mb_ecn_ece_ttl_covers_cadence();
        ret |= test_mb_ecn_slow_start();
        ret |= test_mb_ecn_dt_scaling_invariant();
        ret |= test_mb_ecn_probe_scale_invariant();
        ret |= test_mb_ecn_multiplicative_decrease();
        ret |= test_mb_ecn_ai_hold_release();
        ret |= test_mb_ecn_fixed_point();
        ret |= test_mb_ecn_lead_symmetric();
        ret |= test_mb_ecn_slow_start_local_brake();
        ret |= test_mb_ecn_slow_start_clean_ramp();
        ret |= test_mb_ecn_starved_decrease_escape();
        ret |= test_mb_ecn_starved_local_fallback();
        ret |= test_mb_ecn_decrease_dt_invariant();
        ret |= test_mb_ecn_decrease_subms_carry();
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
        ret |= test_mb_ecn_ctrl_no_capacity_floor();
        ret |= test_mb_ecn_snd_slow_rate_paced();
        ret |= test_mb_ecn_snd_idle_burst_bound();
        ret |= test_mb_ecn_snd_wait_no_overflow();
        ret |= test_mb_ecn_backlogged_paced();
        ret |= test_mb_ecn_source_limited_ceiling();
        ret |= test_mb_ecn_max_filter();
        ret |= test_mb_ecn_idle_clears_backlogged();
        ret |= test_mb_ecn_first_send_warmup();
        ret |= test_mb_ecn_two_flow_converge();
        ret |= test_mb_ecn_ramp_overshoot_grows_with_rtt();
        ret |= test_mb_ecn_shared_ctx_offered_aggregate();
        ret |= test_mb_ecn_flow_count_restarts_window();
        ret |= test_mb_ecn_ceiling_clears_backlog();
        ret |= test_mb_ecn_sfq_share_rate();
        ret |= test_mb_ecn_sfq_share_bytes();
        ret |= test_mb_ecn_sfq_leave();
        ret |= test_mb_ecn_flow_join_widens_round();
        ret |= test_mb_ecn_fifo_burst_not_backlogged();
        ret |= test_mb_ecn_gate_at_ref();
        ret |= test_mb_ecn_hold_sheds_to_floor();
        ret |= test_mb_ecn_stale_hold();
        ret |= test_mb_ecn_stale_idle_no_hold();
        ret |= test_mb_ecn_loss_horizon_tracks_rtt();

        return ret;
}
