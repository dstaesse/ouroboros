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
 * Multi-bit ECN congestion avoidance: a rate-based controller. The
 * sender paces a token bucket at a rate steered by graded ECN
 * feedback, so the backoff is proportional to the congestion. A
 * backlogged flow ramps in slow start to find the path capacity,
 * then settles into AIMD around its fair share. There is no sliding
 * window and no per-flow timer; the control runs on sends.
 *
 * Rate law, per control step of dt seconds (r bytes/s, m the mark
 * in ece units, m_ref = CA_ECE_REF, ai the additive slope):
 *
 *   slow start   dr = r * dt / ss_tc
 *   increase     dr = (ai + r / T_probe) * dt        while not held
 *   decrease     dr = -r * (min(m, CA_ECE_MAX) / m_ref) * dt + L,
 *                cut capped at r/2
 *   lead         L = -dm * r / (m_ref * CA_MD_KD_DIV)
 *
 * dm is the mark's step since the last decrease, clamped to
 * +-m_ref. On a rise L joins the cut before the r/2 cap; on a
 * fall it returns after that cap, bounded on its own to
 * +-r / CA_MD_KD_DIV, so a full cut is never handed back in one
 * step.
 *
 * Hold (ai_hold): the increase stops, and only CA_RATE_MIN is under
 * the rate. It engages on any of three signals and releases on one:
 *
 *   gate   m >= m_ref at a control step, with the increase capacity
 *          scaled (ai = C'/16). At the reference mark the decrease
 *          already asks for the whole rate within a second; adding
 *          to it there is what leaves n saturated controllers each
 *          parked at ai / (m_max / m_ref - 1 / T_probe) = C'/30,
 *          n / 30 of the link between them. Below ~2 Mb/s the slope
 *          sits at its compile-time floor, a quarter of the link a
 *          second, and the two-flow fixpoint is already near m_ref:
 *          holding there costs a quarter of the share every cycle
 *          and lifts nothing capacity-scaled, so the gate does not.
 *   stale  feedback ages out (ece_ttl) while backlogged. The mark
 *          clears as before, so the rate neither grows nor shrinks:
 *          silence on a busy path is packets not arriving, not a
 *          clear path, and mb_ecn_loss will halve it at CA_HB_LOSS
 *          horizons if it goes on. An idle flow is not held. It is
 *          deliberately not conditioned on the gate being reachable:
 *          a ring too short to express m_ref still reports, and
 *          silence there means what it means anywhere. Below the
 *          gate it is the whole of the hold, and what it catches is
 *          a controller the offered-load ceiling has already cut,
 *          before the increase climbs back onto the drop.
 *   loss   mb_ecn_loss, as before.
 *
 *   release  fresh feedback below m_ref (mb_ecn_ece); or no
 *            feedback at all for the loss horizon while liveness
 *            signals still arrive, i.e. the loss cut did not fire:
 *            a path that delivers and reports nothing is clear, and
 *            the one message that could say so, the ece 0 release,
 *            may be the one that was lost. The mark ageing out on
 *            its own never reopens the increase.
 *
 * Horizons: feedback ages out after ece_ttl, a few receiver windows
 * at the flow's rate. That cadence is the pricing window, not the
 * RTT (the window closes on bytes and time at the receiver and the
 * RTT only delays the report), so the stale trigger needs no RTT
 * term. The loss horizon is CA_HB_LOSS of the longer of ece_ttl and
 * the heartbeat interval: on a quiet path only pongs carry liveness,
 * one per heartbeat interval plus an RTT, so a horizon of four
 * intervals reads a long path as quiet and not as collapsed. The
 * interval derives from ss_tc, which is clamped at CA_SS_TC_MAX, so
 * the horizon stops at 8 s while the pong cadence keeps growing with
 * the RTT: the margin runs out around an RTT of 6 s, where a quiet
 * path takes periodic halvings again.
 *
 * Below the gate AIMD runs unchanged, which is what makes shares
 * converge; at it every controller sheds in proportion to its rate
 * until the queue drains and the mark falls below it, so past the
 * gate the standing queue is a limit cycle around m_ref instead of
 * the law's 2^((n+2)/4). The gate needs a queue of 16 packets to
 * reach it, so a link whose ring holds fewer (under ~20 Mb/s at
 * 1500 B, ~115 Mb/s at 9000 B) never engages it and stays passive
 * past n_max as before. The capacity test in mb_ecn_gate does not
 * say so: at 4 Mb/s cap_dec(tx_cap) >> CA_CAP_SHFT is 13792 B/s,
 * above CA_RATE_MIN, so the gate arms on a four-slot ring whose
 * mark tops out at ecn 8. Leaving the stale hold armed there is
 * deliberate and measures better: on the multi-hop chain lab at
 * 1500 B and n = 30, demand 4.85 x C against 5.32 without it, and
 * at 10 Mb/s byte fairness 0.995 against 0.781.
 * The hold outlives the drain by a pricing
 * window and the report that carries the news, so it forfeits
 * ai * (T_w + RTT/2) of increase a cycle. The RTT half is what
 * costs: measured against the same policy without the gate, 2.7
 * points of utilisation at an RTT of 2 ms, 12 at 300 ms and 21 at
 * 1 s, for a standing queue shorter by 54 % and 25 % at the ends of
 * that range.
 *
 * The capacity code sets cap_rate = C'/32, the seed of the slope
 * (ai = 2 * cap_rate = C'/16) and nothing else. It floored the rate
 * once; a floor a controller cannot shed below is the same n / 32
 * of the link as the park above, and snapped every released
 * controller straight back onto it, so it went with the gate. Below
 * the gate the increase keeps every probing controller at or above
 * C'/30 on its own, but only where it runs often enough to: while
 * held it does not, and the minimum measured share falls from
 * 1.2 * C'/32 at an RTT of 2 ms to 0.3 at 1 s. The absolute floor
 * CA_RATE_MIN stays.
 *
 * Every step scales by elapsed wall-clock time, not by packet
 * count, so the per-second dynamics are RTT-independent.
 *
 * Pacer: a virtual clock vt advances at r, the rate of the whole
 * path, and every flow on the ctx is paced against it. A packet
 * starts at its flow's tag, or now if the tag is behind the clock,
 * and books the flow's next slot a full round on: len for each flow
 * the pacer is holding back (start-time fair queueing), so n
 * backlogged flows get r / n each and r together. The count is
 * Little's law on the waits handed out over a utilisation window
 * (mb_ecn_bl). Admission is FIFO behind the work already admitted
 * (vw), so a round goes out one packet at a time at r rather than
 * as one burst at its start; the tag, not the FIFO slot, carries the
 * flow's entitlement, and a flow keeps up to a round of largest
 * packets of lag as credit, the lag the FIFO can force on it.
 *
 * Receiver: ece is the time integral of ecn over a pricing window,
 * ece = integral(ecn dt) / T. The window is a per-layer constant so
 * every flow prices one bottleneck alike; it stretches only for a
 * flow too slow to fill it with samples.
 *
 * Marking (mb_ecn_calc_ecn): ecn is the quarter-log2 of the queue
 * measured in mark units U (U = CA_MARK_KNEE * mean), so the mark is
 * a log-scale queue depth. Equilibrium is where increase balances
 * decrease:
 *
 *   ecn* = (m_ref / 32) * (ai * n / C + 1 / T_probe) = n + 2
 *
 * for n backlogged controllers, one per path whatever its flow
 * count, i.e. a standing queue of 2^((n+2)/4) * U, up to the gate
 * (n = 13; at n = 14 the fixpoint sits on m_ref and the hold takes
 * over). This is the zero-delay fixpoint; feedback delay raises the
 * real standing queue above it.
 */

/* ECE fixed point */
#define CA_SHFT      5                    /* ece fixed point: 32 * ecn  */

/* Receiver averaging window */
#define CA_TW        (1ULL << 26)         /* pricing window ~67 ms      */
#define CA_TW_MIN    (4ULL * MILLION)     /* pricing window floor 4 ms  */
#define CA_TW_RTT_MUL 2                   /* T_w = 2 * layer RTT        */
#define CA_TW_ABSMAX (1ULL << 32)         /* window ceiling ~4.3 s      */
/* Quiet horizon, in windows (1 << shift): gap restart and the TTLs.    */
#define CA_TW_GAP_SHFT 2
#define CA_RX_WBYTES 16000ULL             /* 16 pkts x 1000 B a window  */
#define CA_RX_WCLOSE (2 * CA_RX_WBYTES)   /* byte-triggered early close */
#define CA_TW_SM_SHFT 2                   /* window EWMA weight 1/4     */

/* Congestion marking */
#define CA_MARK_KNEE 1                    /* mark onset (packets)       */

/* Rate machine */
#define CA_RATE_MIN  (1ULL << 13)         /* 8 KiB/s rate floor         */
#define CA_RATE_INIT (1ULL << 16)         /* slow start seed 64 KiB/s   */
/* Rate cap; also keeps rate * dt and rate * rise below 2^64. */
#define CA_RATE_MAX  (1ULL << 37)
#define CA_INV_SHFT  32                   /* reciprocal-rate fixp       */
#define CA_AI_RATE   (1ULL << 17)         /* 128 KiB/s^2 additive inc   */
#define CA_PROBE_TC  (8ULL * BILLION)     /* proportional probe TC 8s   */
#define CA_ECE_REF   (16 << CA_SHFT)      /* full congestion, the gate  */
#define CA_ECE_MAX   (2 * CA_ECE_REF)     /* decrease saturation: ecn 32*/
#define CA_MD_KD_DIV 16                   /* lead gain 1/16             */

/* Control cadence */
#define CA_DT_CTRL   (BILLION / 1000)     /* min rate-update spacing    */
#define CA_DT_CAP    (BILLION / 20)       /* idle-resume Δt clamp 50ms  */
#define CA_IDLE_PKTS 4                    /* idle: gap over 4 packets   */
/* Feedback staleness floor; ctx->ece_ttl rides above it by rate. */
#define CA_ECE_TTL   (1ULL << 28)         /* ~268 ms                    */

/* Slow start */
#define CA_SS_RTT_MUL 2                   /* ss_tc = 2 * layer RTT      */
#define CA_SS_TC_MIN (BILLION / 1000)     /* ramp floor 1 ms            */
#define CA_SS_TC_MAX (4ULL * BILLION)     /* ramp ceiling 4 s           */
#define CA_RTT_SHFT  2                    /* ss_tc EWMA weight 1/4      */
#define CA_SS_TC_GRW 1                    /* ramp climb cap 2x a sample */
#define CA_SS_RTT_DEF 200                 /* default layer RTT (ms)     */

/* Heartbeat */
#define CA_HB_MIN    (40 * MILLION)       /* heartbeat interval floor   */
#define CA_HB_LOSS   4                    /* quiet horizons -> loss cut */

/* Path capacity */
#define CA_CAP_SHFT   5                   /* cap_rate = capacity / 32   */
#define CA_CAP_SM_SHFT 1                  /* capacity EWMA weight 1/2   */
/* Outlives ece_ttl 16x: onset-fresh fcap re-seeds each episode. */
#define CA_CAP_TTL_SHFT 4
#define CA_RMIN_MAX  (1ULL << 32)         /* cap_rate ceiling           */

/* Sender utilisation */
#define CA_SND_WIN   (1ULL << 26)         /* sender util window ~67 ms  */
#define CA_USE_NUM     3                  /* backlogged: offered >=     */
#define CA_USE_DEN     4                  /*   3/4 * window-start rate  */
#define CA_SND_DEC_SHFT 4                 /* offered max-filter 1/16    */
#define CA_SND_DEC_CAP 16                 /* bound gapped-close decay   */
#define CA_SND_BYT_MAX (1ULL << 33)       /* offered-byte saturation    */
#define CA_PAC_DEN     4                  /* backlogged: 1/4 deferred   */

/* Pacer fair share */
#define CA_BL_SHFT     8                  /* deferred-flows fixed point */
#define CA_BL_MAX      ((1ULL << 16) << CA_BL_SHFT) /* count ceiling    */
#define CA_SND_WT_MAX  (1ULL << 55)       /* summed-wait saturation     */

/*
 * Retuning invariants (pinned by the unit tests):
 * - (1 << CA_TW_GAP_SHFT) * CA_TW > S * BILLION / CA_RATE_MIN, or
 *   a floor-rate flow's onset restart-loops (S ~ one MTU; both ns).
 * - CA_RX_WBYTES * BILLION / CA_RATE_MIN < CA_TW_ABSMAX: the
 *   floor-rate window must clear the ceiling.
 * - CA_TW < CA_RX_WBYTES * BILLION / CA_RATE_MIN: at the rate
 *   floor the sample budget, not the horizon, sizes the window.
 * - CA_TW << CA_TW_GAP_SHFT <= CA_ECE_TTL: the estimator must
 *   not call a gap fresh that the sender still counts as live.
 * - CA_ECE_TTL > S * BILLION / CA_RATE_MIN: the idle cap clears a
 *   floor-rate flow's inter-send gap, so pacing never reads as idle.
 * - CA_DT_CAP < CA_ECE_TTL: the idle clamp needs the TTL above it,
 *   or every slow flow reads idle on every send.
 * - CA_HB_LOSS >= 4: a pong returns a heartbeat interval plus an RTT
 *   (two intervals) after the last signal, so the loss horizon in
 *   heartbeat intervals must clear two of them with margin.
 * - CA_RATE_MAX * CA_DT_CAP, the folded lead * inv_rate at
 *   CA_RATE_MIN, and owed * BILLION (owed clamped in mb_ecn_snd) all
 *   keep the pacer arithmetic below 2^64.
 * - CA_RATE_MIN <= CA_RATE_INIT and CA_RMIN_MAX < CA_RATE_MAX.
 * - CA_RATE_MIN is the only floor: cap_rate seeds the slope and
 *   never holds the rate up.
 * - cap_enc(16 * mean) - cap_enc(mean) == CA_ECE_REF >> CA_SHFT: a
 *   queue of 16 packets is what reads as full congestion.
 * - CA_MD_KD_DIV sets the lead gain. The term acts both ways (cut on
 *   a rise, give back on a fall), which cancels the DC bias a
 *   one-sided term would rectify into a standing rate difference
 *   between flows pricing one queue; that is what lets the gain run
 *   at 1/16 instead of the deadzone below 1/8.
 * - T_w = clamp(CA_TW_RTT_MUL * RTT, CA_TW_MIN, CA_TW) scales only
 *   the receiver pricing window; CA_ECE_TTL, CA_SND_WIN, CA_DT_CAP
 *   and CA_DT_CTRL are absolute and must not be derived from it.
 * - The gap-restart horizon is floored at CA_ECE_TTL, so a
 *   floor-rate flow's inter-packet gap never reads as an onset.
 * - The hold engages at CA_ECE_REF and releases below it, so a
 *   standing mark that is a legal AI equilibrium (below the gate)
 *   can always clear the hold, and one at or above it never can.
 * - CA_ECE_REF < CA_ECE_MAX: the gate closes before the decrease
 *   saturates, or the saturated floor C'/30 would be reachable.
 * - CA_SND_WT_MAX << CA_BL_SHFT and len * CA_BL_MAX stay below 2^64:
 *   the deferred-flow estimate and the round advance cannot wrap.
 *
 * Structural invariants (not exercised by the unit tests):
 * - CA_MARK_KNEE <= 4: the full decrease range must fit the ring
 *   (SSM_RBUFF_SIZE, not visible from this file).
 * - ecn* = 2 + n holds for n <= 13 (below the gate) and only with
 *   live capacity feedback; past it the hold cycles the queue.
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
        bool     tx_cav;      /* past slow start                      */
        bool     ai_hold;     /* increase held: gate, stale or loss   */
        uint64_t rate;        /* paced send rate (bytes/s)            */
        uint64_t cap_rate;    /* capacity / 32, seeds the slope (B/s) */
        uint64_t ai_rate;     /* additive-increase slope (B/s^2)      */
        uint64_t ece_ttl;     /* how long feedback stays valid (ns)   */
        uint64_t ss_tc;       /* slow-start time constant (ns)        */
        uint64_t dec_acc;     /* sub-ms decrease time carried (ns)    */
        uint64_t inv_rate;    /* fixed-point 1/rate for pacing        */
        uint64_t vt;          /* virtual service clock (bytes)        */
        uint64_t vw;          /* FIFO tail of admitted work (bytes)   */
        uint64_t lead;        /* pacer lead of last send (bytes)      */
        uint64_t last_ts;     /* last clock advance (ns)              */
        uint64_t last_ctrl;   /* last rate update (ns)                */
        uint64_t last_fb;     /* last congestion feedback (ns)        */
        uint64_t last_sig;    /* last liveness signal, incl. hb (ns)  */
        uint64_t n_fb;        /* feedback updates received            */
        uint64_t n_rtt;       /* heartbeat RTT samples folded         */
        uint64_t last_hb;     /* last heartbeat emitted (ns)          */
        uint64_t last_res;    /* liveness baseline: resume, cut (ns)  */
        uint64_t last_loc;    /* last local mark seen (ns)            */
        uint64_t last_cap;    /* last capacity applied (ns)           */

        uint64_t snd_byt;     /* bytes offered this window (capped)   */
        size_t   snd_flows;   /* flows sharing the ctx, >= 1          */
        uint64_t snd_pac;     /* bytes the pacer held back this win   */
        uint64_t snd_wt;      /* pacer waits handed out this win (ns) */
        uint64_t snd_bl;      /* flows the pacer holds back (fixp)    */
        size_t   snd_lmx;     /* largest packet this window (bytes)   */
        size_t   len_max;     /* largest packet, this and last window */
        uint64_t snd_win;     /* utilisation window start (ns)        */
        uint64_t snd_r0;      /* rate at window start                 */
        uint64_t snd_rate;    /* max-filter of offered rate (B/s)     */
        bool     backlogged;  /* offered load keeps the pacer busy    */
        bool     src_limited; /* rate held at offered-load ceiling    */
        bool     started;     /* a real send has occurred             */

        /* Diagnostics only, read by mb_ecn_print_stats. */
        uint8_t  tx_cap;      /* path capacity code fed back to us    */
        uint64_t n_ctrl;      /* control steps taken                  */
        uint64_t t_ctrl;      /* wall time covered by steps (ns)      */
        uint64_t t_bank;      /* increase time banked in steps (ns)   */
        uint64_t n_ttl;       /* feedback aged out (TTL)              */
        uint64_t n_cap;       /* capacity updates applied             */
        uint64_t n_loss;      /* signal-loss cuts (collapse)          */
        uint64_t n_hold;      /* increase holds engaged               */
        uint64_t ss_peak;     /* peak rate in slow start (bytes/s)    */
};

/* Layer slow-start time constant (ns), from the declared RTT. */
static uint64_t mb_ecn_ss_tc = (uint64_t) CA_SS_RTT_MUL *
                               CA_SS_RTT_DEF * MILLION;

/* Layer pricing window (ns), from the declared RTT. */
static uint64_t mb_ecn_tw = CA_TW;

struct ca_ops mb_ecn_ca_ops = {
        .ctx_create     = mb_ecn_ctx_create,
        .ctx_destroy    = mb_ecn_ctx_destroy,
        .ctx_update_snd = mb_ecn_ctx_update_snd,
        .ctx_update_rcv = mb_ecn_ctx_update_rcv,
        .ctx_update_ece = mb_ecn_ctx_update_ece,
        .ctx_hb_due     = mb_ecn_ctx_hb_due,
        .ctx_rtt        = mb_ecn_ctx_rtt,
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

/* Derive the layer slow-start slope from the declared RTT (ms). */
void mb_ecn_init(uint32_t rtt_ms)
{
        uint64_t tc;
        uint64_t rtt;
        uint64_t tw;

        if (rtt_ms == 0)          /* unspecified: safe default */
                rtt_ms = CA_SS_RTT_DEF;

        tc = (uint64_t) CA_SS_RTT_MUL * rtt_ms * MILLION;
        if (tc < (uint64_t) CA_SS_TC_MIN)
                tc = CA_SS_TC_MIN;

        mb_ecn_ss_tc = tc;

        rtt = (uint64_t) rtt_ms * MILLION;

        tw = (uint64_t) CA_TW_RTT_MUL * rtt;
        if (tw < CA_TW_MIN)
                tw = CA_TW_MIN;

        if (tw > CA_TW)
                tw = CA_TW;

        mb_ecn_tw = tw;
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
        ctx->cap_rate  = CA_RATE_MIN;
        ctx->ai_rate   = CA_AI_RATE;
        ctx->ss_tc     = mb_ecn_ss_tc;
        ctx->ece_ttl   = mb_ecn_ece_ttl(CA_RATE_INIT);
        ctx->inv_rate  = mb_ecn_rate_inv(CA_RATE_INIT);
        ctx->rx_ts     = t;
        ctx->rx_win    = t;
        ctx->rx_tw     = mb_ecn_tw;
        ctx->last_ts   = t;
        ctx->last_ctrl = t;
        ctx->last_fb   = t;
        ctx->last_sig  = t;
        ctx->last_loc  = t;
        ctx->last_cap  = t;

        /* snd_win/last_ts re-seeded lazily on the first real send. */
        ctx->snd_r0     = CA_RATE_INIT;
        ctx->snd_rate   = CA_RATE_INIT;
        ctx->snd_flows  = 1;
        ctx->snd_bl     = 1ULL << CA_BL_SHFT;
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
                ctx->rate += ctx->rate * dta / ctx->ss_tc;
}

/* The mark the controller acts on: feedback, else the local fallback. */
static uint16_t mb_ecn_mark(const struct mb_ecn_ctx * ctx)
{
        return ctx->tx_ece > 0 ? ctx->tx_ece
                               : (uint16_t) (ctx->tx_loc << CA_SHFT);
}

/* Hold the increase; only fresh feedback below the gate releases it. */
static void mb_ecn_hold(struct mb_ecn_ctx * ctx)
{
        if (ctx->ai_hold)
                return;

        ctx->ai_hold = true;
        ctx->n_hold++;
}

/*
 * The gate: at or above the reference mark the controller only
 * sheds. Only with the slope capacity scaled: at its compile-time
 * floor there is nothing scaled to lift, and the hold would cost a
 * slow link's two flows a quarter of their share every cycle.
 */
static void mb_ecn_gate(struct mb_ecn_ctx * ctx)
{
        /*
         * The raw code, not cap_rate: the EWMA closes half the gap a
         * window, so it stalls one below a target that is itself one
         * above the floor, and the gate would never arm on that path.
         */
        if (ctx->tx_cap == 0 ||
            (cap_dec(ctx->tx_cap) >> CA_CAP_SHFT) <= (uint64_t) CA_RATE_MIN)
                return;

        if (mb_ecn_mark(ctx) >= (uint16_t) CA_ECE_REF)
                mb_ecn_hold(ctx);
}

/* Additive increase plus a rate-independent proportional probe. */
static void mb_ecn_increase(struct mb_ecn_ctx * ctx,
                            uint64_t            dta)
{
        if (!ctx->backlogged)
                return;

        /* Gate, stale feedback or loss: wait for a clear signal. */
        if (ctx->ai_hold)
                return;

        ctx->rate += ctx->ai_rate * dta / BILLION;
        ctx->rate += ctx->rate * dta / CA_PROBE_TC;
}

/*
 * Multiplicative decrease: cut proportional to mark x elapsed time,
 * plus a lead term on the mark's step, clamped and acting both ways.
 */
static void mb_ecn_decrease(struct mb_ecn_ctx * ctx,
                            uint64_t            dtc)
{
        uint64_t dtm;
        uint64_t mark;
        uint64_t step;
        uint64_t lead;
        uint64_t cut;
        uint16_t m;
        bool     up;

        m = mb_ecn_mark(ctx);
        if (m == 0) {
                ctx->dec_acc = 0;      /* unmarked time is not banked */
                ctx->tx_ecp  = 0;
                return;
        }

        mark = MIN(m, CA_ECE_MAX);

        /* Lead on the mark step; the clamp bounds it to rate/KD. */
        up   = m > ctx->tx_ecp;
        step = up ? m - ctx->tx_ecp : ctx->tx_ecp - m;
        step = MIN(step, CA_ECE_REF);
        lead = ctx->rate * step / (CA_ECE_REF * CA_MD_KD_DIV);

        cut = up ? lead : 0;

        /*
         * Bank the remainder: at a 1 ms control cadence, truncating
         * to whole milliseconds would drop up to half of every cut.
         */
        ctx->dec_acc += dtc;
        dtm = ctx->dec_acc / MILLION;
        ctx->dec_acc -= dtm * MILLION;
        if (mark * dtm >= CA_ECE_REF * 500)
                cut += ctx->rate / 2;
        else
                cut += ctx->rate * mark * dtm / (CA_ECE_REF * 1000);

        if (cut > ctx->rate / 2)
                cut = ctx->rate / 2;

        ctx->rate -= cut;

        if (!up)
                ctx->rate += lead;

        ctx->tx_ecp = m;
}

/* Offered-load ceiling backstop while source-limited. */
static void mb_ecn_ceiling(struct mb_ecn_ctx * ctx)
{
        uint64_t hi;

        if (ctx->backlogged) {
                ctx->src_limited = false;
                return;
        }

        /* Land on the backlog level; a ceiling above it never clears. */
        hi = ctx->snd_rate > CA_RATE_MAX / CA_USE_DEN * CA_USE_NUM
             ? (uint64_t) CA_RATE_MAX
             : ctx->snd_rate * CA_USE_DEN / CA_USE_NUM;
        if (hi < CA_RATE_MIN)
                hi = CA_RATE_MIN;

        ctx->src_limited = ctx->rate > hi;
        if (ctx->src_limited)
                ctx->rate = hi;
}

static void mb_ecn_ctrl(struct mb_ecn_ctx * ctx,
                        uint64_t            dtc)
{
        uint64_t dta;

        /* AI and slow start bank at most CA_DT_CAP of idle time. */
        dta = MIN(dtc, (uint64_t) CA_DT_CAP);

        ctx->n_ctrl++;
        ctx->t_ctrl += dtc;
        ctx->t_bank += dta;

        if (ctx->tx_cav) {
                mb_ecn_gate(ctx);
                mb_ecn_increase(ctx, dta);
                mb_ecn_decrease(ctx, dtc);
        } else {
                mb_ecn_slow_start(ctx, dta);
        }

        mb_ecn_ceiling(ctx);

        /* The absolute floor is the only one: see cap_rate. */
        if (ctx->rate < (uint64_t) CA_RATE_MIN)
                ctx->rate = CA_RATE_MIN;

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

/* Open a fresh utilisation window at t. */
static void mb_ecn_win_open(struct mb_ecn_ctx * ctx,
                            uint64_t            t)
{
        ctx->snd_win = t;
        ctx->snd_byt = 0;
        ctx->snd_pac = 0;
        ctx->snd_wt  = 0;
        ctx->snd_lmx = 0;
        ctx->snd_r0  = ctx->rate;
}

/*
 * Note the flow count; a window spanning two populations measures
 * neither, so a change opens a fresh one. A joining flow is about to
 * compete, so the round widens for it at once rather than a window
 * late, when a round at the old share would oversubscribe the path.
 * A leave is left to the estimate: the flow may not have been one
 * the pacer was holding back.
 */
static void mb_ecn_flows(struct mb_ecn_ctx * ctx,
                         size_t              flows,
                         uint64_t            t)
{
        size_t n = flows > 0 ? flows : 1;

        if (n == ctx->snd_flows)
                return;

        if (n > ctx->snd_flows) {
                ctx->snd_bl += (uint64_t) (n - ctx->snd_flows) << CA_BL_SHFT;
                if (ctx->snd_bl > (uint64_t) CA_BL_MAX)
                        ctx->snd_bl = CA_BL_MAX;
        }

        ctx->snd_flows = n;

        mb_ecn_win_open(ctx, t);
}

/*
 * Flows the pacer holds back, by Little's law: the waits handed out
 * in a window sum to the time deferred flows spent waiting, so over
 * the window's length they are the mean number waiting. A backlogged
 * flow is read again at its deadline, so its waits tile the window
 * and count it once whatever its rate or packet size; a flow the
 * pacer never defers counts nothing and takes no share.
 */
static void mb_ecn_bl(struct mb_ecn_ctx * ctx,
                      uint64_t            elapsed)
{
        uint64_t bl = (ctx->snd_wt << CA_BL_SHFT) / elapsed;

        if (bl < (1ULL << CA_BL_SHFT))
                bl = 1ULL << CA_BL_SHFT;

        if (bl > (uint64_t) CA_BL_MAX)
                bl = CA_BL_MAX;

        ctx->snd_bl = bl;
}

/*
 * Close the utilisation window: set backlogged from the level test,
 * fold offered into the max filter, re-estimate the deferred flows,
 * then reset the window.
 */
static void mb_ecn_win(struct mb_ecn_ctx * ctx,
                       uint64_t            t)
{
        uint64_t elapsed = t - ctx->snd_win;
        uint64_t offered;
        bool     was = ctx->backlogged;

        /* Both the bytes and the rate are the whole ctx's: compare as is. */
        offered = ctx->snd_byt * BILLION / elapsed;

        /*
         * Offered load is counted past the pacer, so it cannot tell a
         * quiet source from one the pacer is holding back, and idle
         * flows on the context drag it down. A window the pacer had to
         * defer is rate-limited whatever the bytes say.
         */
        ctx->backlogged = offered * CA_USE_DEN >= ctx->snd_r0 * CA_USE_NUM
                          || ctx->snd_pac * CA_PAC_DEN >= ctx->snd_byt;

        if (!was && ctx->backlogged)   /* resume: fresh liveness baseline */
                ctx->last_res = t;

        mb_ecn_offered(ctx, offered, elapsed);

        if (ctx->backlogged)
                ctx->src_limited = false;

        mb_ecn_bl(ctx, elapsed);

        ctx->len_max = ctx->snd_lmx;   /* the closing window's, till it grows */

        mb_ecn_win_open(ctx, t);
}

/* Age out congestion, local-mark and capacity signals once stale. */
/* Heartbeat interval: ~1 RTT, floored so fast links don't over-probe. */
static uint64_t mb_ecn_t_hb(const struct mb_ecn_ctx * ctx)
{
        uint64_t t = ctx->ss_tc >> 1;

        return t > (uint64_t) CA_HB_MIN ? t : CA_HB_MIN;
}

/*
 * Feedback collapsed while backlogged: halve like an RTO, stay in
 * AIMD. The cut re-arms the horizon through the liveness baseline,
 * not the signal clock: last_sig stays what the path last said.
 */
static void mb_ecn_loss(struct mb_ecn_ctx * ctx,
                        uint64_t            t)
{
        ctx->rate -= ctx->rate / 2;
        if (ctx->rate < (uint64_t) CA_RATE_MIN)
                ctx->rate = CA_RATE_MIN;

        ctx->inv_rate = mb_ecn_rate_inv(ctx->rate);
        ctx->ece_ttl  = mb_ecn_ece_ttl(ctx->rate);
        ctx->last_res = t;
        ctx->n_loss++;

        mb_ecn_hold(ctx);
}

static void mb_ecn_age(struct mb_ecn_ctx * ctx,
                       uint64_t            t)
{
        uint64_t ttl = ctx->ece_ttl;
        uint64_t hzn = (uint64_t) CA_HB_LOSS * MAX(ttl, mb_ecn_t_hb(ctx));
        uint64_t ref = ctx->last_sig > ctx->last_res
                       ? ctx->last_sig : ctx->last_res;
        uint64_t gap = t - ref;

        /*
         * Sustained silence while backlogged is feedback collapse: cut
         * the rate in half and stay in AIMD, so a recovering flow climbs
         * back additively instead of re-ramping. Repeated silence decays
         * it geometrically toward the floor. The horizon spans the
         * heartbeat as well as the feedback cadence: a quiet long path
         * has only pongs to show for itself.
         */
        if (ctx->backlogged && ctx->n_fb + ctx->n_rtt > 0 && gap > hzn) {
                mb_ecn_loss(ctx, t);
                return;
        }

        /*
         * Stale feedback clears the mark, as an idle flow's must. On a
         * flow still sending it means packets are not arriving, so the
         * increase is held with it: the rate stands until fresh
         * feedback below the gate, or the loss cut above, decides.
         */
        if (t - ctx->last_fb > ctx->ece_ttl) {
                if (ctx->tx_ece > 0) {
                        ctx->n_ttl++;
                        if (ctx->backlogged)
                                mb_ecn_hold(ctx);
                }
                ctx->tx_ece = 0;
        }

        /*
         * Held through a whole loss horizon without feedback, yet the
         * cut above did not fire, so signals did arrive: the path
         * delivers and has nothing to report. Silence with liveness is
         * a clear path; only silence without it is congestion.
         */
        if (ctx->ai_hold && t - ctx->last_fb > hzn && t - ctx->last_sig <= hzn
            && mb_ecn_mark(ctx) < (uint16_t) CA_ECE_REF)
                ctx->ai_hold = false;

        if (t - ctx->last_loc > ctx->ece_ttl)
                ctx->tx_loc = 0;

        /* Stale capacity: fall back to the compile-time defaults. */
        if (t - ctx->last_cap > ctx->ece_ttl << CA_CAP_TTL_SHFT) {
                ctx->cap_rate = CA_RATE_MIN;
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
        uint64_t idle;
        uint64_t cred;
        uint64_t s;
        uint64_t adm;
        uint64_t wait;

        /* Lazy warm-up seed: packet #1 is never an idle resume. */
        if (!ctx->started) {
                ctx->started  = true;
                ctx->last_ts  = t;
                ctx->last_res = t;
                ctx->snd_win  = t;
                ctx->snd_r0   = ctx->rate;
        }

        dt = t - ctx->last_ts;
        ctx->last_ts = t;

        /*
         * Idle gap clears backlog before aging: no false loss on resume.
         * Measured against the pacer's own spacing, so a flow paced
         * slower than CA_DT_CAP per packet does not read as idle on
         * every send, and bounded by the staleness horizon.
         */
        idle = CA_IDLE_PKTS * len * BILLION / ctx->rate;
        idle = MAX(idle, (uint64_t) CA_DT_CAP);
        idle = MIN(idle, (uint64_t) CA_ECE_TTL);
        if (dt > idle)
                ctx->backlogged = false;

        mb_ecn_age(ctx, t);

        /* Offered-load estimator: accumulate, gate growth, size ceiling. */
        ctx->snd_byt += len;
        if (ctx->snd_byt > (uint64_t) CA_SND_BYT_MAX)
                ctx->snd_byt = CA_SND_BYT_MAX;

        if (t - ctx->snd_win >= (uint64_t) CA_SND_WIN)
                mb_ecn_win(ctx, t);

        /* Rate update before the vt advance: burst uses the clamped rate. */
        dtc = t - ctx->last_ctrl;
        if (dtc >= (uint64_t) CA_DT_CTRL) {
                ctx->last_ctrl = t;
                mb_ecn_ctrl(ctx, dtc);
        }

        mb_ecn_advance(ctx, dt, len, *ftag);

        /* The FIFO tail cannot trail the clock: idle service is gone. */
        if (ctx->vw < ctx->vt)
                ctx->vw = ctx->vt;

        if (len > ctx->snd_lmx)
                ctx->snd_lmx = len;

        if (len > ctx->len_max)
                ctx->len_max = len;

        /*
         * SFQ start tag: ahead of the clock waits for its slot. Behind
         * it keeps up to a round of largest packets as credit, the lag
         * the FIFO below can force on a small-packet flow, and starts
         * now past that. The tag books the flow's next slot a round on,
         * len for each deferred flow, so the flows divide the rate.
         */
        cred = (ctx->len_max * ctx->snd_bl) >> CA_BL_SHFT;

        s = *ftag;
        if (s + cred < ctx->vt)
                s = ctx->vt - cred;

        *ftag = s + ((len * ctx->snd_bl) >> CA_BL_SHFT);

        /*
         * Only a tag ahead of the clock is the pacer holding a flow to
         * its share; a burst the FIFO below spreads out is not.
         */
        if (s > ctx->vt)
                ctx->snd_pac += len;

        /* Admit FIFO behind the work already in the server. */
        adm = s > ctx->vw ? s : ctx->vw;
        ctx->vw += len;

        ctx->lead = adm - ctx->vt;

        if (adm <= ctx->vt)
                return 0;

        /* Reciprocal pacing; folded so any lead * rate stays in range. */
        wait = (ctx->lead * (ctx->inv_rate >> 16)) >> (CA_INV_SHFT - 16);

        ctx->snd_wt += wait;
        if (ctx->snd_wt > (uint64_t) CA_SND_WT_MAX)
                ctx->snd_wt = CA_SND_WT_MAX;

        return (time_t) wait;
}

time_t mb_ecn_ctx_update_snd(void *     _ctx,
                             size_t     len,
                             uint8_t    lecn,
                             size_t     flows,
                             uint64_t * ftag)
{
        struct timespec     now;
        uint64_t            t;
        struct mb_ecn_ctx * ctx = _ctx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        t = TS_TO_UINT64(now);

        mb_ecn_flows(ctx, flows, t);

        mb_ecn_loc(ctx, lecn, t);

        return mb_ecn_snd(ctx, len, t, ftag);
}

/* Estimator idle, or a quiet gap past the horizon: restart fresh. */
static bool mb_ecn_rcv_fresh(const struct mb_ecn_ctx * ctx,
                             uint64_t                  dt)
{
        uint64_t gap;

        if (ctx->rx_ece == 0 && ctx->rx_acc == 0)
                return true;

        gap = ctx->rx_tw << CA_TW_GAP_SHFT;

        return dt > MAX(gap, (uint64_t) CA_ECE_TTL);
}

/*
 * Size the next averaging window to ~16 packets at this rate, floored
 * at the price horizon: a flow fast enough to fill the horizon
 * integrates over CA_TW, a slower one stretches for its samples.
 */
static void mb_ecn_resize(struct mb_ecn_ctx * ctx,
                          uint64_t            win)
{
        uint64_t tw = CA_RX_WBYTES * win / ctx->rx_byt;

        if (tw > ctx->rx_tw)
                ctx->rx_tw += (tw - ctx->rx_tw) >> CA_TW_SM_SHFT;
        else
                ctx->rx_tw -= (ctx->rx_tw - tw) >> CA_TW_SM_SHFT;

        if (ctx->rx_tw < mb_ecn_tw)
                ctx->rx_tw = mb_ecn_tw;

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
        win = t - ctx->rx_win;
        if (win < ctx->rx_tw) {
                /* Early close once 2x target bytes arrive (speed-up). */
                if (ctx->rx_byt < CA_RX_WCLOSE || win < mb_ecn_tw) {
                        *ece = ctx->rx_ece;
                        return false;
                }
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
        ctx->tx_cav  = true;   /* closed-loop feedback: leave slow start */

        /*
         * Fresh feedback below the gate: the path has room, resume --
         * unless our own egress says otherwise. Releasing on a remote
         * all-clear while the local mark is at the gate just re-opens
         * the increase into a queue we are still filling.
         */
        if (ece < (uint16_t) CA_ECE_REF
            && (uint16_t) (ctx->tx_loc << CA_SHFT) < (uint16_t) CA_ECE_REF)
                ctx->ai_hold = false;

        ctx->last_fb  = t;
        ctx->last_sig = t;
        ctx->n_fb++;

        /* Scale the slope to the path bottleneck. */
        if (cap != 0) {
                tgt = cap_dec(cap) >> CA_CAP_SHFT;
                if (tgt < CA_RATE_MIN)
                        tgt = CA_RATE_MIN;

                if (tgt > CA_RMIN_MAX)
                        tgt = CA_RMIN_MAX;

                if (tgt > ctx->cap_rate)
                        ctx->cap_rate += (tgt - ctx->cap_rate)
                                         >> CA_CAP_SM_SHFT;
                else
                        ctx->cap_rate -= (ctx->cap_rate - tgt)
                                         >> CA_CAP_SM_SHFT;

                ctx->ai_rate  = 2 * ctx->cap_rate;
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

/* Due when the path stayed quiet for a heartbeat interval; arms the gap. */
bool mb_ecn_ctx_hb_due(void *   _ctx,
                       uint64_t now)
{
        struct mb_ecn_ctx * ctx  = _ctx;
        uint64_t            t_hb = mb_ecn_t_hb(ctx);
        uint64_t            last;

        last = ctx->last_sig > ctx->last_hb ? ctx->last_sig : ctx->last_hb;
        if (now - last < t_hb)
                return false;

        ctx->last_hb = now;

        return true;
}

/* Fold a heartbeat RTT sample into the ramp clock; also counts as life. */
void mb_ecn_ctx_rtt(void *   _ctx,
                    uint64_t now,
                    uint64_t rtt)
{
        struct mb_ecn_ctx * ctx = _ctx;
        uint64_t            tgt;

        tgt = (uint64_t) CA_SS_RTT_MUL * rtt;
        if (tgt < (uint64_t) CA_SS_TC_MIN)   /* track the true RTT both  */
                tgt = CA_SS_TC_MIN;          /* ways: overshoot ~e^{1/2} */

        if (tgt > (uint64_t) CA_SS_TC_MAX)   /* at the real RTT, not the */
                tgt = CA_SS_TC_MAX;          /* declared worst case      */

        /*
         * A control packet stuck behind a stalled reader returns an RTT
         * worth seconds on a path worth milliseconds. Cap how far one
         * sample carries the ramp, so a stall costs a step and a rise
         * that holds still arrives within a few samples.
         */
        if (tgt > ctx->ss_tc << CA_SS_TC_GRW)
                tgt = ctx->ss_tc << CA_SS_TC_GRW;

        ctx->ss_tc += (tgt >> CA_RTT_SHFT) - (ctx->ss_tc >> CA_RTT_SHFT);

        ctx->last_sig = now;   /* liveness only: never ages the ece signal */
        ctx->n_rtt++;
}

int  mb_ecn_calc_ecn(size_t    queued,
                     uint8_t * ecn,
                     qoscube_t qc,
                     size_t    mean)
{
        uint64_t u;
        int      q;
        uint8_t  mark;

        (void) qc;

        if (queued == 0 || mean == 0)
                return 0;

        u = (uint64_t) CA_MARK_KNEE * mean;

        /*
         * Difference of two quarter-log2 codes is a log-scale ratio:
         * the same queue in units of U marks the same on any link.
         */
        q = (int) cap_enc(queued) - (int) cap_enc(u);
        if (q <= 0)
                return 0;

        /* Saturate: a deeper queue must not wrap to a low mark. */
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

        if (len < CA_STATS_STRLEN)
                return 0;

        /* No signal seen: the rate is unconstrained drift, not a target. */
        rate = ctx->tx_cav ? ctx->rate : 0;
        peak = ctx->tx_cav ? ctx->ss_peak : 0;

        /* Match the controller: MD fires on m, incl. the local fallback. */
        m = mb_ecn_mark(ctx);

        if (!ctx->tx_cav) {
                regime = "Slow start";
                code   = 0;
        } else if (ctx->ai_hold) {
                regime = "Increase held";
                code   = 4;
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
                "Pacer deferred flows (count):    %20" PRIu64 "\n"
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
                "Slow start peak rate (bytes/s):  %20" PRIu64 "\n"
                "Signal-loss cuts (count):        %20" PRIu64 "\n"
                "Increase holds (count):          %20" PRIu64 "\n"
                "Heartbeat RTT samples (count):   %20" PRIu64 "\n"
                "Ramp time constant (ns):         %20" PRIu64 "\n",
                "Multi-bit ECN",
                ctx->tx_ece,
                ctx->rx_ece,
                rate, ctx->lead,
                (uint64_t) ((ctx->snd_bl + (1ULL << (CA_BL_SHFT - 1)))
                            >> CA_BL_SHFT),
                code,
                regime,
                ctx->n_ctrl, ctx->t_ctrl, ctx->t_bank,
                ctx->n_fb, ctx->n_ttl,
                cap_dec(ctx->tx_cap), ctx->cap_rate, ctx->n_cap,
                peak,
                ctx->n_loss, ctx->n_hold, ctx->n_rtt, ctx->ss_tc);

        return strlen(buf);
}
