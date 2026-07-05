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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include <ouroboros/time.h>
#include <ouroboros/utils.h>

#include "cap.h"
#include "mb-ecn.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * The sender paces with a token bucket at a rate driven by Δt-scaled
 * AIMD: each step changes the rate proportional to elapsed wall-clock
 * time, so the per-second dynamics do not depend on how often packets
 * arrive. The receiver's averaging window and the sender's feedback
 * staleness both stretch with the flow's byte rate, so a slow flow
 * is measured and controlled like a fast one; CA_RATE_MIN only
 * bounds those horizons (window <= CA_TW_ABSMAX, TTL ~8 s). There
 * is no per-flow timer; the control runs on packet sends.
 *
 * The floor and the AI slope scale with the path: forwarders stamp
 * their measured link capacity into the PCI (cap.c), the receiver
 * feeds the path MIN back with the ece, and the sender derives
 * rate_min = ai_rate = C / 32, clamped to [CA_RATE_MIN, CA_RMIN_MAX],
 * falling back to those defaults when the signal goes stale.
 */

#define CA_SHFT      5                    /* ece fixed point: 32 * ecn  */
#define CA_TW_MIN    (1ULL << 20)         /* min mean window ~1.05 ms   */
#define CA_TW_INIT   (1ULL << 26)         /* initial mean window ~67ms  */
#define CA_TW_ABSMAX (1ULL << 32)         /* window ceiling ~4.3 s      */
/* Quiet horizon, in windows (1 << shift): gap restart and the TTLs.    */
#define CA_TW_GAP_SHFT 2
#define CA_N_TARGET  16                   /* target packets per window  */
#define CA_RX_WBYTES (CA_N_TARGET * 1000ULL) /* target bytes/window     */
#define CA_RX_WCLOSE (2 * CA_RX_WBYTES)   /* byte-triggered early close */
#define CA_TW_SM_SHFT 2                   /* window EWMA weight 1/4     */
#define CA_MARK_Q    4                    /* mark quantum (packets)     */

#define CA_RATE_MIN  (1ULL << 13)         /* 8 KiB/s rate floor         */
#define CA_RATE_INIT (1ULL << 16)         /* slow start seed 64 KiB/s   */
/* Rate cap; also keeps rate * dt and rate * rise below 2^64. */
#define CA_RATE_MAX  (1ULL << 37)
#define CA_INV_SHFT  32                   /* reciprocal-rate fixp       */
#define CA_AI_RATE   (1ULL << 16)         /* 64 KiB/s^2 additive inc    */
#define CA_PROBE_TC  (8ULL * BILLION)     /* proportional probe TC 8s   */
#define CA_ECE_REF   (16 << CA_SHFT)      /* full congestion: ecn 16    */
#define CA_MD_KD_DIV 4                    /* one-sided lead gain 1/4    */
/* Must stay >= 1 ms: the MD term scales by dtc / MILLION (truncates).  */
#define CA_DT_CTRL   (BILLION / 1000)
#define CA_DT_CAP    (BILLION / 20)       /* idle-resume Δt clamp 50ms  */
/* Floor of the rate-relative feedback staleness (ctx->ece_ttl). */
#define CA_ECE_TTL   ((1 << CA_TW_GAP_SHFT) * CA_TW_INIT)
#define CA_SS_TC     (BILLION / 50)
#define CA_WASH_BKT  (BILLION / 32)       /* washout bucket ~31 ms      */
#define CA_WASH_SHFT 2                    /* damp 1/4 of bucket change  */

#define CA_CAP_SHFT   5                   /* floor = capacity / 32      */
#define CA_CAP_SM_SHFT 1                  /* capacity EWMA weight 1/2   */
/* Outlives ece_ttl 16x: onset-fresh fcap re-seeds each episode. */
#define CA_CAP_TTL_SHFT 4
#define CA_RMIN_MAX  (1ULL << 32)         /* derived floor ceiling      */

#define CA_SND_WIN     CA_TW_INIT         /* sender util window ~67ms   */
#define CA_USE_NUM     3                  /* backlogged: offered >=     */
#define CA_USE_DEN     4                  /*   3/4 * window-start rate  */
#define CA_HDRM_MARKS  4                  /* ceiling ~2x offered load   */
#define CA_SND_DEC_SHFT 4                 /* offered max-filter 1/16    */
#define CA_SND_DEC_CAP 16                 /* bound gapped-close decay   */
#define CA_SND_BYT_MAX (1ULL << 33)       /* offered-byte saturation    */

/*
 * Retuning invariants (pinned by the unit tests):
 * - (1 << CA_TW_GAP_SHFT) * CA_TW_INIT > S * BILLION / CA_RATE_MIN, or
 *   a floor-rate flow's onset restart-loops (S ~ one MTU; both ns).
 * - CA_RX_WBYTES * BILLION / CA_RATE_MIN < CA_TW_ABSMAX: the
 *   floor-rate window must clear the ceiling.
 * - CA_RATE_MAX * CA_DT_CAP, the folded lead * inv_rate at
 *   CA_RATE_MIN, and owed * BILLION (owed clamped in mb_ecn_snd) all
 *   keep the pacer arithmetic below 2^64.
 * - CA_DT_CTRL < CA_WASH_BKT < CA_DT_CAP: control cadence under the
 *   washout bucket under the sparse-step cutoff.
 * - CA_RATE_MIN <= CA_RATE_INIT and CA_RMIN_MAX < CA_RATE_MAX.
 */

struct mb_ecn_ctx {
        uint16_t rx_ece;      /* smoothed congestion echo (32 * ecn)  */
        uint64_t rx_acc;      /* window integral of ecn * dt          */
        uint64_t rx_byt;      /* bytes arrived in current window      */
        uint64_t rx_ts;       /* last packet arrival (ns)             */
        uint64_t rx_win;      /* window start (ns)                    */
        uint64_t rx_tw;       /* adaptive averaging window (ns)       */
        uint8_t  rx_cap;      /* window bottleneck capacity code      */

        uint16_t tx_ece;      /* congestion reported from downstream  */
        uint16_t tx_ecp;      /* previous tx_ece (rise detection)     */
        uint8_t  tx_loc;      /* local first-hop ecn mark (fallback)  */
        uint8_t  tx_cap;      /* path capacity code fed back to us    */
        bool     tx_cav;      /* past slow start                      */
        uint64_t rate;        /* paced send rate (bytes/s)            */
        uint64_t rate_min;    /* capacity-derived rate floor (B/s)    */
        uint64_t ai_rate;     /* additive-increase slope (B/s^2)      */
        uint64_t ece_ttl;     /* how long feedback stays valid (ns)   */
        uint64_t r_bkt;       /* rate snapshot at last washout bucket */
        uint64_t wash_acc;    /* washout bucket time accumulator (ns) */
        uint64_t inv_rate;    /* fixed-point 1/rate for pacing        */
        uint64_t vt;          /* virtual service clock (bytes)        */
        uint64_t lead;        /* pacer lead of last send (bytes)      */
        uint64_t last_ts;     /* last clock advance (ns)              */
        uint64_t last_ctrl;   /* last rate update (ns)                */
        uint64_t last_fb;     /* last feedback applied (ns)           */
        uint64_t last_loc;    /* last local mark seen (ns)            */
        uint64_t last_cap;    /* last capacity applied (ns)           */

        uint64_t n_ctrl;      /* control steps taken                  */
        uint64_t t_ctrl;      /* wall time covered by steps (ns)      */
        uint64_t t_bank;      /* increase time banked in steps (ns)   */
        uint64_t n_fb;        /* feedback updates received            */
        uint64_t n_ttl;       /* feedback aged out (TTL)              */
        uint64_t n_cap;       /* capacity updates applied             */
        uint64_t ss_peak;     /* peak rate in slow start (bytes/s)    */

        uint64_t snd_byt;     /* bytes offered this window (capped)   */
        uint64_t snd_win;     /* utilisation window start (ns)        */
        uint64_t snd_r0;      /* rate at window start                 */
        uint64_t snd_rate;    /* max-filter of offered rate (B/s)     */
        bool     backlogged;  /* offered load keeps the pacer busy    */
        bool     src_limited; /* rate held at offered-load ceiling    */
        bool     started;     /* a real send has occurred             */
};

struct ca_ops mb_ecn_ca_ops = {
        .ctx_create     = mb_ecn_ctx_create,
        .ctx_destroy    = mb_ecn_ctx_destroy,
        .ctx_update_snd = mb_ecn_ctx_update_snd,
        .ctx_update_rcv = mb_ecn_ctx_update_rcv,
        .ctx_update_ece = mb_ecn_ctx_update_ece,
        .calc_ecn       = mb_ecn_calc_ecn,
        .marks_ecn      = true,
        .print_stats    = mb_ecn_print_stats
};

static uint64_t mb_ecn_rate_inv(uint64_t rate)
{
        return ((uint64_t) BILLION << CA_INV_SHFT) / rate;
}

/*
 * Feedback arrives once per receiver window, and the window tracks
 * the flow's byte rate. Mirror it: age the signal out only past the
 * quiet horizon at the current rate, floored for fast flows.
 */
static uint64_t mb_ecn_ece_ttl(uint64_t rate)
{
        uint64_t ttl;

        ttl = (1 << CA_TW_GAP_SHFT) * CA_RX_WBYTES * BILLION / rate;

        return ttl > (uint64_t) CA_ECE_TTL ? ttl : (uint64_t) CA_ECE_TTL;
}

void * mb_ecn_ctx_create(void)
{
        struct timespec     now;
        uint64_t            t;
        struct mb_ecn_ctx * ctx;

        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL)
                return NULL;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        memset(ctx, 0, sizeof(*ctx));

        t = TS_TO_UINT64(now);

        ctx->rate      = CA_RATE_INIT;
        ctx->rate_min  = CA_RATE_MIN;
        ctx->ai_rate   = CA_AI_RATE;
        ctx->ece_ttl   = mb_ecn_ece_ttl(CA_RATE_INIT);
        ctx->r_bkt     = CA_RATE_INIT;
        ctx->inv_rate  = mb_ecn_rate_inv(CA_RATE_INIT);
        ctx->rx_ts     = t;
        ctx->rx_win    = t;
        ctx->rx_tw     = CA_TW_INIT;
        ctx->last_ts   = t;
        ctx->last_ctrl = t;
        ctx->last_fb   = t;
        ctx->last_loc  = t;
        ctx->last_cap  = t;

        /* snd_win/last_ts re-seeded lazily on the first real send. */
        ctx->snd_r0     = CA_RATE_INIT;
        ctx->snd_rate   = CA_RATE_INIT;
        ctx->backlogged = true;

        return (void *) ctx;
}

void mb_ecn_ctx_destroy(void * ctx)
{
        free(ctx);
}

/* Local first-hop mark exits slow start and covers dead feedback. */
static void mb_ecn_loc(struct mb_ecn_ctx * ctx,
                       uint8_t             lecn,
                       uint64_t            t)
{
        if (lecn == 0)
                return;

        ctx->tx_loc   = lecn;
        ctx->tx_cav   = true;
        ctx->last_loc = t;
}

/* Slow start: ramp only while backlogged. */
static void mb_ecn_slow_start(struct mb_ecn_ctx * ctx,
                              uint64_t            dta)
{
        if (ctx->backlogged)
                ctx->rate += ctx->rate * dta / CA_SS_TC;

        ctx->r_bkt = ctx->rate;
}

/* Additive increase plus a rate-independent proportional probe. */
static void mb_ecn_increase(struct mb_ecn_ctx * ctx,
                            uint64_t            dta)
{
        if (!ctx->backlogged)
                return;

        ctx->rate += ctx->ai_rate * dta / BILLION;
        ctx->rate += ctx->rate * dta / CA_PROBE_TC;
}

/* Multiplicative decrease: proportional cut plus a one-sided lead. */
static void mb_ecn_decrease(struct mb_ecn_ctx * ctx,
                            uint64_t            dtc)
{
        uint64_t dtm;
        uint64_t mark;
        uint64_t rise;
        uint64_t cut;
        uint16_t m;

        m = ctx->tx_ece > 0 ? ctx->tx_ece
                            : (uint16_t) (ctx->tx_loc << CA_SHFT);
        if (m == 0) {
                ctx->tx_ecp = 0;
                return;
        }

        mark = MIN(m, CA_ECE_REF);
        rise = 0;
        if (m > ctx->tx_ecp)
                rise = MIN(m - ctx->tx_ecp, CA_ECE_REF);

        cut = ctx->rate * rise / (CA_ECE_REF * CA_MD_KD_DIV);

        /* Honest elapsed ms, so a starved sender still cuts. */
        dtm = dtc / MILLION;
        if (mark * dtm >= CA_ECE_REF * 500)
                cut += ctx->rate / 2;
        else
                cut += ctx->rate * mark * dtm / (CA_ECE_REF * 1000);

        if (cut > ctx->rate / 2)
                cut = ctx->rate / 2;

        ctx->rate -= cut;
        ctx->tx_ecp = m;
}

/*
 * Washout: once per wall-clock bucket, damp a fixed fraction of the
 * rate change over that bucket. Bucketed (not per-step) so it stays
 * cadence-independent; bounded so it cannot reverse a ramp. A sparse
 * step resets it, so a starved sender keeps its cut.
 */
static void mb_ecn_washout(struct mb_ecn_ctx * ctx,
                           uint64_t            dtc,
                           uint64_t            dta)
{
        if (dtc > (uint64_t) CA_DT_CAP) {
                ctx->r_bkt = ctx->rate;
                ctx->wash_acc = 0;
                return;
        }

        ctx->wash_acc += dta;
        if (ctx->wash_acc < (uint64_t) CA_WASH_BKT)
                return;

        if (ctx->rate > ctx->r_bkt)
                ctx->rate -= (ctx->rate - ctx->r_bkt) >> CA_WASH_SHFT;
        else
                ctx->rate += (ctx->r_bkt - ctx->rate) >> CA_WASH_SHFT;

        ctx->r_bkt = ctx->rate;
        ctx->wash_acc = 0;
}

/* Offered-load ceiling backstop while source-limited. */
static void mb_ecn_ceiling(struct mb_ecn_ctx * ctx)
{
        unsigned code;
        uint64_t hi;

        if (ctx->backlogged) {
                ctx->src_limited = false;
                return;
        }

        code = (unsigned) cap_enc(ctx->snd_rate) + CA_HDRM_MARKS;
        if (code > UINT8_MAX)          /* keep the cast lossless */
                code = UINT8_MAX;

        hi = cap_dec((uint8_t) code);
        if (hi > CA_RATE_MAX)
                hi = CA_RATE_MAX;

        if (hi < CA_RATE_MIN)
                hi = CA_RATE_MIN;

        ctx->src_limited = ctx->rate > hi;
        if (ctx->src_limited) {
                ctx->rate  = hi;
                ctx->r_bkt = ctx->rate;
        }
}

static void mb_ecn_ctrl(struct mb_ecn_ctx * ctx,
                        uint64_t            dtc)
{
        uint64_t dta;
        uint64_t lo;

        /* AI and slow start bank at most CA_DT_CAP of idle time. */
        dta = MIN(dtc, (uint64_t) CA_DT_CAP);

        ctx->n_ctrl++;
        ctx->t_ctrl += dtc;
        ctx->t_bank += dta;

        if (ctx->tx_cav) {
                mb_ecn_increase(ctx, dta);
                mb_ecn_decrease(ctx, dtc);
                mb_ecn_washout(ctx, dtc, dta);
        } else {
                mb_ecn_slow_start(ctx, dta);
        }

        mb_ecn_ceiling(ctx);

        /* Capacity floor only while backlogged; else the absolute floor. */
        lo = ctx->backlogged ? ctx->rate_min : (uint64_t) CA_RATE_MIN;
        if (ctx->rate < lo)
                ctx->rate = lo;

        if (ctx->rate > CA_RATE_MAX)
                ctx->rate = CA_RATE_MAX;

        ctx->inv_rate = mb_ecn_rate_inv(ctx->rate);
        ctx->ece_ttl  = mb_ecn_ece_ttl(ctx->rate);

        if (!ctx->tx_cav && ctx->rate > ctx->ss_peak)
                ctx->ss_peak = ctx->rate;
}

/* Fold offered into the max filter: rise at once, decay 1/16 per window. */
static void mb_ecn_offered(struct mb_ecn_ctx * ctx,
                           uint64_t            offered,
                           uint64_t            elapsed)
{
        uint64_t n;

        if (offered >= ctx->snd_rate) {
                ctx->snd_rate = offered;
                return;
        }

        n = MIN(elapsed / CA_SND_WIN, CA_SND_DEC_CAP);
        while (n-- > 0 && ctx->snd_rate > offered)
                ctx->snd_rate -= (ctx->snd_rate - offered) >> CA_SND_DEC_SHFT;
}

/*
 * Close the utilisation window: set backlogged from the level test,
 * fold offered into the max filter, then reset the window.
 */
static void mb_ecn_win(struct mb_ecn_ctx * ctx,
                       uint64_t            t)
{
        uint64_t elapsed = t - ctx->snd_win;
        uint64_t offered;

        offered = ctx->snd_byt * BILLION / elapsed;

        ctx->backlogged = offered * CA_USE_DEN >= ctx->snd_r0 * CA_USE_NUM;

        mb_ecn_offered(ctx, offered, elapsed);

        if (ctx->backlogged)
                ctx->src_limited = false;

        ctx->snd_win = t;
        ctx->snd_byt = 0;
        ctx->snd_r0  = ctx->rate;
}

/* Age out congestion, local-mark and capacity signals once stale. */
static void mb_ecn_age(struct mb_ecn_ctx * ctx,
                       uint64_t            t)
{
        if (t - ctx->last_fb > ctx->ece_ttl) {
                if (ctx->tx_ece > 0)
                        ctx->n_ttl++;
                ctx->tx_ece = 0;
        }

        if (t - ctx->last_loc > ctx->ece_ttl)
                ctx->tx_loc = 0;

        /* Stale capacity: fall back to the compile-time defaults. */
        if (t - ctx->last_cap > ctx->ece_ttl << CA_CAP_TTL_SHFT) {
                ctx->rate_min = CA_RATE_MIN;
                ctx->ai_rate  = CA_AI_RATE;
                ctx->tx_cap   = 0;
        }
}

/* Advance the virtual clock; a gap past CA_DT_CAP credits a burst. */
static void mb_ecn_advance(struct mb_ecn_ctx * ctx,
                           uint64_t            dt,
                           size_t              len,
                           uint64_t            ftag)
{
        uint64_t burst;
        uint64_t owed;

        if (dt <= (uint64_t) CA_DT_CAP) {
                ctx->vt += ctx->rate * dt / BILLION;
                return;
        }

        burst = ctx->rate * CA_DT_CAP / BILLION;
        if (burst < (uint64_t) len)
                burst = len;

        owed = ftag > ctx->vt ? ftag - ctx->vt + burst : burst;

        /* Clamp so owed * BILLION cannot wrap (2^33 B backlog). */
        if (owed > (1ULL << 33))
                owed = 1ULL << 33;

        if (dt >= owed * BILLION / ctx->rate)
                ctx->vt += owed;
        else
                ctx->vt += ctx->rate * dt / BILLION;
}

static time_t mb_ecn_snd(struct mb_ecn_ctx * ctx,
                         size_t              len,
                         uint64_t            t,
                         uint64_t *          ftag)
{
        uint64_t dt;
        uint64_t dtc;
        uint64_t s;

        /* Lazy warm-up seed: packet #1 is never an idle resume. */
        if (!ctx->started) {
                ctx->started = true;
                ctx->last_ts = t;
                ctx->snd_win = t;
                ctx->snd_r0  = ctx->rate;
        }

        dt = t - ctx->last_ts;
        ctx->last_ts = t;

        mb_ecn_age(ctx, t);

        /* Offered-load estimator: accumulate, gate growth, size ceiling. */
        ctx->snd_byt += len;
        if (ctx->snd_byt > (uint64_t) CA_SND_BYT_MAX)
                ctx->snd_byt = CA_SND_BYT_MAX;

        if (dt > (uint64_t) CA_DT_CAP)
                ctx->backlogged = false;

        if (t - ctx->snd_win >= (uint64_t) CA_SND_WIN)
                mb_ecn_win(ctx, t);

        /* Rate update before the vt advance: burst uses the clamped rate. */
        dtc = t - ctx->last_ctrl;
        if (dtc >= (uint64_t) CA_DT_CTRL) {
                ctx->last_ctrl = t;
                mb_ecn_ctrl(ctx, dtc);
        }

        mb_ecn_advance(ctx, dt, len, *ftag);

        /* SFQ start tag: behind the clock starts now, ahead waits. */
        s = *ftag > ctx->vt ? *ftag : ctx->vt;
        *ftag = s + len;

        ctx->lead = s - ctx->vt;

        /* Reciprocal pacing; folded so any lead * rate stays in range. */
        if (s > ctx->vt)
                return (time_t) ((ctx->lead * (ctx->inv_rate >> 16))
                                 >> (CA_INV_SHFT - 16));

        return 0;
}

time_t mb_ecn_ctx_update_snd(void *     _ctx,
                             size_t     len,
                             uint8_t    lecn,
                             uint64_t * ftag)
{
        struct timespec     now;
        uint64_t            t;
        struct mb_ecn_ctx * ctx = _ctx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        t = TS_TO_UINT64(now);

        mb_ecn_loc(ctx, lecn, t);

        return mb_ecn_snd(ctx, len, t, ftag);
}

/* Estimator idle, or a gap past ~4 current windows: restart fresh. */
static bool mb_ecn_rcv_fresh(const struct mb_ecn_ctx * ctx,
                             uint64_t                  dt)
{
        if (ctx->rx_ece == 0 && ctx->rx_acc == 0)
                return true;

        return dt > ctx->rx_tw << CA_TW_GAP_SHFT;
}

/* Size the next averaging window to ~CA_N_TARGET packets at this rate. */
static void mb_ecn_resize(struct mb_ecn_ctx * ctx,
                          uint64_t            win)
{
        uint64_t tw = CA_RX_WBYTES * win / ctx->rx_byt;

        if (tw > ctx->rx_tw)
                ctx->rx_tw += (tw - ctx->rx_tw) >> CA_TW_SM_SHFT;
        else
                ctx->rx_tw -= (ctx->rx_tw - tw) >> CA_TW_SM_SHFT;

        if (ctx->rx_tw < CA_TW_MIN)
                ctx->rx_tw = CA_TW_MIN;

        if (ctx->rx_tw > CA_TW_ABSMAX)
                ctx->rx_tw = CA_TW_ABSMAX;
}

static bool mb_ecn_rcv(struct mb_ecn_ctx * ctx,
                       size_t              len,
                       uint8_t             ecn,
                       uint8_t             cap,
                       uint16_t *          ece,
                       uint8_t *           fcap,
                       uint64_t            t)
{
        uint64_t dt;
        uint64_t win;

        dt = t - ctx->rx_ts;
        ctx->rx_ts = t;

        if (ctx->rx_ece == 0 && ctx->rx_acc == 0 && ecn == 0)
                return false;

        /* Onset, or ~4 windows of silence: emit fresh, undiluted. */
        if (mb_ecn_rcv_fresh(ctx, dt)) {
                ctx->rx_win = t;
                ctx->rx_acc = 0;
                ctx->rx_byt = len;
                ctx->rx_cap = cap; /* fresh, seeds the new window */
                ctx->rx_ece = (uint16_t) (ecn << CA_SHFT);
                *ece  = ctx->rx_ece;
                *fcap = ctx->rx_cap;
                return true;
        }

        /* Dwell clamp: one packet weighs at most one window of mark. */
        ctx->rx_acc += ecn * MIN(dt, ctx->rx_tw);
        ctx->rx_byt += len;
        ctx->rx_cap  = cap_min(ctx->rx_cap, cap);

        *ece = ctx->rx_ece;

        win = t - ctx->rx_win;
        if (win < ctx->rx_tw) {
                /* Early close once 2x target bytes arrive (speed-up). */
                if (ctx->rx_byt < CA_RX_WCLOSE)
                        return false;

                if (win < CA_TW_MIN)
                        return false;
        }

        /* Time-integral mean over the actual window elapsed (never rx_tw). */
        ctx->rx_ece = (uint16_t) ((ctx->rx_acc << CA_SHFT) / win);

        if (ctx->rx_byt > 0)
                mb_ecn_resize(ctx, win);

        *fcap = ctx->rx_cap;

        ctx->rx_win = t;
        ctx->rx_acc = 0;
        ctx->rx_byt = 0;
        ctx->rx_cap = 0; /* the next window starts unknown */

        *ece = ctx->rx_ece;

        return true;
}

bool mb_ecn_ctx_update_rcv(void *     _ctx,
                           size_t     len,
                           uint8_t    ecn,
                           uint8_t    cap,
                           uint16_t * ece,
                           uint8_t *  fcap)
{
        struct timespec     now;
        struct mb_ecn_ctx * ctx = _ctx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        return mb_ecn_rcv(ctx, len, ecn, cap, ece, fcap, TS_TO_UINT64(now));
}

static void mb_ecn_ece(struct mb_ecn_ctx * ctx,
                       uint16_t            ece,
                       uint8_t             cap,
                       uint64_t            t)
{
        uint64_t tgt;

        ctx->tx_ece  = ece;
        ctx->tx_cav  = true;
        ctx->last_fb = t;
        ctx->n_fb++;

        /* Scale the floor and AI slope to the path bottleneck. */
        if (cap != 0) {
                tgt = cap_dec(cap) >> CA_CAP_SHFT;
                if (tgt < CA_RATE_MIN)
                        tgt = CA_RATE_MIN;

                if (tgt > CA_RMIN_MAX)
                        tgt = CA_RMIN_MAX;

                if (tgt > ctx->rate_min)
                        ctx->rate_min += (tgt - ctx->rate_min)
                                         >> CA_CAP_SM_SHFT;
                else
                        ctx->rate_min -= (ctx->rate_min - tgt)
                                         >> CA_CAP_SM_SHFT;

                ctx->ai_rate  = ctx->rate_min;
                ctx->tx_cap   = cap;
                ctx->last_cap = t;
                ctx->n_cap++;
        }

        /* Control from the feedback path: a starved sender recovers. */
        if (t - ctx->last_ctrl < (uint64_t) CA_DT_CTRL)
                return;

        mb_ecn_ctrl(ctx, t - ctx->last_ctrl);

        ctx->last_ctrl = t;
}

void mb_ecn_ctx_update_ece(void *   _ctx,
                           uint16_t ece,
                           uint8_t  cap)
{
        struct timespec     now;
        struct mb_ecn_ctx * ctx = _ctx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        mb_ecn_ece(ctx, ece, cap, TS_TO_UINT64(now));
}

int  mb_ecn_calc_ecn(size_t    queued,
                     uint8_t * ecn,
                     qoscube_t qc,
                     size_t    len)
{
        size_t  q;
        uint8_t mark;

        (void) len;
        (void) qc;

        /* Saturate: a queue past 255 quanta must not wrap to a low mark. */
        q = queued / CA_MARK_Q;
        mark = q > 255 ? (uint8_t) 255 : (uint8_t) q;

        if (mark > *ecn)
                *ecn = mark;

        return 0;
}

ssize_t  mb_ecn_print_stats(void * _ctx,
                            char * buf,
                            size_t len)
{
        struct mb_ecn_ctx * ctx = _ctx;
        char *              regime;
        uint64_t            rate;
        uint64_t            peak;
        int                 code;
        uint16_t            m;

        if (len < 1024)
                return 0;

        /* No signal seen: the rate is unconstrained drift, not a target. */
        rate = ctx->tx_cav ? ctx->rate : 0;
        peak = ctx->tx_cav ? ctx->ss_peak : 0;

        /* Match the controller: MD fires on m, incl. the local fallback. */
        m = ctx->tx_ece > 0 ? ctx->tx_ece
                            : (uint16_t) (ctx->tx_loc << CA_SHFT);

        if (!ctx->tx_cav) {
                regime = "Slow start";
                code   = 0;
        } else if (ctx->src_limited) {
                regime = "Source limited";
                code   = 3;
        } else if (m > 0) {
                regime = "Proportional dec";
                code   = 2;
        } else {
                regime = "Additive inc";
                code   = 1;
        }

        sprintf(buf,
                "Congestion avoidance algorithm:  %20s\n"
                "Upstream congestion level:       %20u\n"
                "Downstream congestion level:     %20u\n"
                "Paced rate (bytes/s):            %20" PRIu64 "\n"
                "Pacer lead (bytes):              %20" PRIu64 "\n"
                "Congestion regime (code):        %20d\n"
                "Current congestion regime:       %20s\n"
                "Control steps (count):           %20" PRIu64 "\n"
                "Control time elapsed (ns):       %20" PRIu64 "\n"
                "Control time banked (ns):        %20" PRIu64 "\n"
                "Feedback updates (count):        %20" PRIu64 "\n"
                "Feedback timeouts (count):       %20" PRIu64 "\n"
                "Path capacity (bytes/s):         %20" PRIu64 "\n"
                "Capacity rate floor (bytes/s):   %20" PRIu64 "\n"
                "Capacity updates (count):        %20" PRIu64 "\n"
                "Slow start peak rate (bytes/s):  %20" PRIu64 "\n",
                "Multi-bit ECN",
                ctx->tx_ece,
                ctx->rx_ece,
                rate, ctx->lead, code,
                regime,
                ctx->n_ctrl, ctx->t_ctrl, ctx->t_bank,
                ctx->n_fb, ctx->n_ttl,
                cap_dec(ctx->tx_cap), ctx->rate_min, ctx->n_cap,
                peak);

        return strlen(buf);
}
