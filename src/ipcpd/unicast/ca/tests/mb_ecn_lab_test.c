/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Shared-bottleneck lab for multi-bit ECN congestion avoidance
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

/*
 * Packet-level shared-bottleneck simulator for mb-ecn.
 *
 * An exact-time FIFO link of capacity cap: a packet departs at
 * max(enqueue, last departure) + len / cap. Packets are marked at
 * enqueue from the instantaneous byte queue by mb_ecn_calc_ecn, the
 * function the forwarding path calls. Delivered packets drive a
 * per-flow receiver estimator (mb_ecn_rcv); every window close,
 * including the ece 0 release (fa.c), reaches the sender as ece after
 * a one-way lag. The sender takes the mark on its own last packet as
 * the local fallback (fa.c l_ecn) and heartbeat pongs keep liveness.
 * Greedy flows send whenever the pacer allows; CBR flows follow an
 * absolute schedule. A tick every LAB_SAMPLE drains the link between
 * sends, so feedback queued by a departure is due on time even while
 * every flow sits idle. With cfg.shared, each group of flows runs on
 * one ctx as a production build does, and the flow count follows t0,
 * t1 and the churn period. A full buffer blocks the writer, as a ring
 * on the same host does; with cfg.lossy it drops the packet, as the
 * far side of a physical link does (poa_rx_pkt), and the sender hears
 * nothing of it.
 *
 * The sweep in test_mb_ecn_lab only reports; the other tests assert.
 */

#include "mb-ecn.c"
#include <test/test.h>

#include <math.h>

#define MS (MILLION) /* one millisecond in ns */
#define LEN 1000    /* default packet size (bytes) */

#define LAB_MAXF   256                /* most flows on one link     */
#define LAB_MSKF   64                 /* flows a flow mask reaches  */
#define LAB_N8     8                  /* flows in the n8 fixpoints  */
#define LAB_FIFO   16384              /* bottleneck ring, packets   */
#define LAB_FBQ    64                 /* pending feedback ring      */
#define LAB_NONE   UINT64_MAX         /* no pending event           */
#define LAB_SAMPLE (5 * MS)           /* service tick               */

#define LAB_SHR_JN      0.98  /* even split across one ctx's flows */
#define LAB_GATE_DEMAND 1.25  /* aggregate demand held on the link */
#define LAB_GATE_UTIL   0.85  /* utilisation a gated set delivers  */
#define LAB_GATE_JN     0.95  /* even split, controllers alike     */

struct lab_pkt {
        uint64_t dep;                 /* departure time (ns)        */
        uint8_t  ecn;
        uint16_t f;                   /* flow index                 */
};

struct lab_fb {
        uint64_t t;
        uint16_t ece;
        uint8_t  fcap;
};

struct lab_flow {
        struct mb_ecn_ctx * snd;
        struct mb_ecn_ctx * rcv;
        uint64_t            t_snd;          /* next send attempt (ns)     */
        uint64_t            last;           /* ctx clock high-water (ns)  */
        uint64_t            ftag;
        uint64_t            ia;             /* app interval, 0 = greedy   */
        uint64_t            app;            /* next app slot (ns)         */
        uint64_t            lag;            /* feedback one-way lag (ns)  */
        uint8_t             lecn;           /* own last packet's mark     */
        struct lab_fb       fbq[LAB_FBQ];
        size_t              fb_h;
        size_t              fb_n;
        uint64_t            hb_t;           /* pong due, LAB_NONE = none  */
        uint64_t            hb_rtt;
        uint64_t            m_t;            /* last accounting time       */
        uint64_t            dlv;            /* delivered bytes            */
        uint64_t            dlv2;           /* delivered in score window  */
        uint64_t            r_int;          /* integral of rate dt        */
        uint64_t            r_lo;
        uint64_t            r_hi;
        uint64_t            lead_B;         /* lead-term cut volume       */
        uint64_t            prop_B;         /* proportional cut volume    */
        uint64_t            cuts;           /* >45% single-event cuts     */
        uint64_t            hold_ns;        /* time with ai_hold set      */
        uint64_t            lim_ns;         /* time src_limited (latch)   */
        uint64_t            idl_ns;         /* time the backlog test off  */
        uint64_t            n_loss;         /* loss cuts, kept past free  */
};

struct lab_link {
        uint64_t       cap;           /* bytes/s                    */
        uint8_t        cc;            /* stamped capacity code      */
        uint64_t       t_srv;         /* line busy until (ns)       */
        uint64_t       q;             /* queued bytes               */
        uint64_t       qmax;          /* blocking threshold (bytes) */
        struct lab_pkt pk[LAB_FIFO];
        size_t         h;
        size_t         n;
        /* metrics */
        uint64_t       q_t;           /* last q-change time         */
        uint64_t       q_int;         /* integral of q dt           */
        uint64_t       mk_int;        /* integral of ece(q) dt      */
        uint64_t       e_from;        /* empty-dwell start          */
        uint64_t       e_ns;          /* empty time past warmup     */
        size_t         e_eps;         /* empty episodes past warmup */
        uint64_t       dlv;           /* delivered bytes            */
        uint64_t       drops;         /* dropped bytes past warmup  */
};

struct lab_cfg {
        const char * name;
        uint64_t     cap;           /* bytes/s                     */
        uint64_t     dur;           /* run length (ns)             */
        uint64_t     wu;            /* warmup excluded (ns)        */
        size_t       len;           /* packet size (bytes)         */
        uint64_t     qmax;          /* bytes                       */
        bool         lossy;         /* full buffer drops, no block */
        size_t       n;             /* flows, up to LAB_MAXF       */
        uint64_t     ia[LAB_MAXF];  /* app interval, 0 = greedy    */
        uint64_t     lag[LAB_MAXF]; /* one-way feedback lag (ns)   */
        bool         no_loc;        /* disable local-mark path     */
        uint64_t     st_d;          /* service stall length (ns)   */
        uint64_t     st_p;          /* stall period, 0 = never     */
        uint64_t     st_f;          /* stalled-flow mask, 0 = all  */
        uint64_t     t0[LAB_MAXF];  /* flow start offsets (ns)     */
        uint64_t     t1[LAB_MAXF];  /* flow stop, 0 = runs to end  */
        uint64_t     r0[LAB_MAXF];  /* seed rate, 0 = slow start   */
        uint64_t     sc_lo;         /* score window (ns), as the   */
        uint64_t     sc_hi;         /* integration test scores     */
        bool         shared;        /* one ctx per group of flows  */
        uint8_t      grp[LAB_MAXF]; /* ctx group when shared       */
        uint64_t     ch_p;          /* churn period, 0 = never     */
        uint64_t     ch_f;          /* churning flow mask          */
};

static struct lab_link lab_lnk;
static struct lab_flow lab_fl[LAB_MAXF];
static uint64_t        lab_sc_lo;
static uint64_t        lab_sc_hi;
static size_t          lab_len;
static bool            lab_lossy;

/* Seed weights: even, graded, and graded reversed. */
static const unsigned lab_n8_w[3][LAB_N8] = {
        { 1, 1, 1, 1, 1, 1, 1, 1 },
        { 1, 2, 3, 4, 5, 6, 7, 8 },
        { 8, 7, 6, 5, 4, 3, 2, 1 }
};

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
 * Does flow i hold the ctx at t? A churning flow holds it for the
 * first half of every ch_p and is gone for the second.
 */
static bool lab_is_up(const struct lab_cfg * c,
                      size_t                 i,
                      uint64_t               t)
{
        if (t < c->t0[i])
                return false;

        if (c->t1[i] > 0 && t >= c->t1[i])
                return false;

        if (c->ch_p == 0 || i >= LAB_MSKF || ((c->ch_f >> i) & 1) == 0)
                return true;

        return t % c->ch_p < c->ch_p / 2;
}

/* Flows holding flow i's ctx at t, the count ca_ctx_get refcounts. */
static size_t lab_live(const struct lab_cfg * c,
                       size_t                 i,
                       uint64_t               t)
{
        size_t n = 0;
        size_t j;

        for (j = 0; j < c->n; j++)
                if (c->grp[j] == c->grp[i] && lab_is_up(c, j, t))
                        n++;

        return n > 0 ? n : 1;
}

/* The first flow of i's group owns the group's ctx pair. */
static size_t lab_owner(const struct lab_cfg * c,
                        size_t                 i)
{
        size_t j;

        for (j = 0; j < i; j++)
                if (c->grp[j] == c->grp[i])
                        return j;

        return i;
}

/* The bottleneck marks with the production function, nothing else. */
static uint8_t lab_mark(uint64_t q)
{
        uint8_t e = 0;

        if (q == 0)
                return 0;

        mb_ecn_calc_ecn(q, &e, QOS_CUBE_BE, lab_len);

        return e;
}

/* Track the queue integral, the mark integral and empty dwells. */
static void lab_q_acct(struct lab_link * l,
                       uint64_t          now,
                       uint64_t          wu)
{
        uint64_t dt = now - l->q_t;

        if (l->q_t >= wu && dt > 0) {
                l->q_int  += l->q * dt;
                l->mk_int += (uint64_t) lab_mark(l->q) * 32 * dt;
        }

        if (l->q == 0) {
                if (l->e_from == LAB_NONE)
                        l->e_from = l->q_t;
        } else if (l->e_from != LAB_NONE) {
                if (now >= wu) {
                        uint64_t f = l->e_from > wu ? l->e_from : wu;
                        l->e_ns += l->q_t > f ? l->q_t - f : 0;
                        l->e_eps++;
                }
                l->e_from = LAB_NONE;
        }

        l->q_t = now;
}

/* Deliver everything due; receiver estimator feeds the fb ring. */
static void lab_service(struct lab_link * l,
                        uint64_t          now,
                        uint64_t          wu)
{
        uint16_t ece;
        uint8_t  fcap;
        bool     due;

        while (l->n > 0 && l->pk[l->h].dep <= now) {
                struct lab_pkt * p = &l->pk[l->h];
                struct lab_flow * f = &lab_fl[p->f];

                lab_q_acct(l, p->dep, wu);

                l->q -= lab_len;

                if (p->dep >= wu) {
                        l->dlv += lab_len;
                        f->dlv += lab_len;
                }

                if (p->dep >= lab_sc_lo && p->dep < lab_sc_hi)
                        f->dlv2 += lab_len;

                due = mb_ecn_rcv(f->rcv, lab_len, p->ecn, l->cc, &ece,
                                 &fcap, p->dep);

                if (due && f->fb_n < LAB_FBQ) {
                        size_t i = (f->fb_h + f->fb_n++) % LAB_FBQ;
                        f->fbq[i].t    = p->dep + f->lag;
                        f->fbq[i].ece  = ece;
                        f->fbq[i].fcap = fcap;
                }

                l->h = (l->h + 1) % LAB_FIFO;
                l->n--;
        }
}

/* Integrate rate, regime dwell and extrema between a flow's events. */
static void lab_f_acct(struct lab_flow * f,
                       uint64_t          now,
                       uint64_t          wu)
{
        struct mb_ecn_ctx * c = f->snd;
        uint64_t            dt;
        uint16_t            m;

        if (now < f->m_t)
                now = f->m_t;

        dt = now - f->m_t;
        if (f->m_t >= wu && dt > 0) {
                f->r_int += c->rate * dt;

                if (c->ai_hold)
                        f->hold_ns += dt;

                if (c->src_limited)
                        f->lim_ns += dt;

                if (!c->backlogged)
                        f->idl_ns += dt;

                if (c->tx_ece > 0)
                        m = c->tx_ece;
                else
                        m = (uint16_t) (c->tx_loc << CA_SHFT);

                if (m > CA_ECE_MAX)
                        m = CA_ECE_MAX;

                f->prop_B += c->rate / CA_ECE_REF * m * dt / BILLION;
                if (c->rate < f->r_lo)
                        f->r_lo = c->rate;

                if (c->rate > f->r_hi)
                        f->r_hi = c->rate;
        }

        f->m_t = now;
}

/* One send attempt; a full buffer blocks until the head departs. */
static void lab_send(struct lab_link * l,
                     struct lab_flow * f,
                     size_t            fi,
                     size_t            nf,
                     uint64_t          wu,
                     bool              no_loc)
{
        uint64_t t = f->t_snd;
        uint64_t r0;
        uint64_t dep;
        uint8_t  ecn;
        time_t   w;
        bool     full;

        lab_service(l, t, wu);

        full = l->q + lab_len > l->qmax;
        if (full && !lab_lossy) {           /* blocking write */
                f->t_snd = l->pk[l->h].dep;
                return;
        }

        lab_f_acct(f, t, wu);

        ecn = lab_mark(l->q);

        r0 = f->snd->rate;

        mb_ecn_flows(f->snd, nf, t);

        if (!no_loc)
                mb_ecn_loc(f->snd, f->lecn, t);

        w = mb_ecn_snd(f->snd, lab_len, t, &f->ftag);

        if (f->snd->rate * 100 < r0 * 55)
                f->cuts++;

        f->lecn = ecn;
        f->last = t;

        lab_q_acct(l, t, wu);

        if (full) {                         /* lossy: paced, then lost */
                if (t >= wu)
                        l->drops += lab_len;
        } else {
                dep = (t > l->t_srv ? t : l->t_srv)
                      + lab_len * BILLION / l->cap;
                l->t_srv = dep;
                l->pk[(l->h + l->n) % LAB_FIFO].dep = dep;
                l->pk[(l->h + l->n) % LAB_FIFO].ecn = ecn;
                l->pk[(l->h + l->n) % LAB_FIFO].f   = (uint16_t) fi;
                l->n++;
                l->q += lab_len;
        }

        if (mb_ecn_ctx_hb_due(f->snd, t) && f->hb_t == LAB_NONE) {
                f->hb_rtt = l->q * BILLION / l->cap + 2 * f->lag;
                f->hb_t   = t + f->hb_rtt;
        }

        if (f->ia == 0) {
                f->t_snd = t + (w > 0 ? (uint64_t) w : 1);
        } else {
                f->app  += f->ia;
                f->t_snd = t + (uint64_t) w;
                if (f->app > f->t_snd)
                        f->t_snd = f->app;
        }
}

/* Apply one queued feedback to the sender, with lead accounting. */
static void lab_fb_apply(struct lab_flow * f,
                         uint64_t          wu)
{
        struct lab_fb * fb = &f->fbq[f->fb_h];
        uint64_t        t  = fb->t > f->last ? fb->t : f->last;
        uint64_t        r0 = f->snd->rate;
        uint16_t        step;
        bool            up;

        lab_f_acct(f, t, wu);

        if (t >= wu) {
                up = fb->ece > f->snd->tx_ecp;
                if (up)
                        step = fb->ece - f->snd->tx_ecp;
                else
                        step = f->snd->tx_ecp - fb->ece;

                if (step > CA_ECE_REF)
                        step = CA_ECE_REF;

                if (up)
                        f->lead_B += r0 * step
                                     / (CA_ECE_REF * CA_MD_KD_DIV);
        }

        mb_ecn_ece(f->snd, fb->ece, fb->fcap, t);

        if (f->snd->rate * 100 < r0 * 55)
                f->cuts++;

        f->last = t;
        f->fb_h = (f->fb_h + 1) % LAB_FBQ;
        f->fb_n--;
}

/*
 * Sender stall at st_t (dsched untrack/starve model): the queue
 * drains for st_d and the resume bursts the backlog through the
 * marker. Returns the next stall, jittered so it cannot phase-lock.
 */
static uint64_t lab_stall(const struct lab_cfg * c,
                          uint64_t               st_t)
{
        uint64_t end = st_t + c->st_d;
        uint64_t msk = c->st_f == 0 ? 3 : c->st_f;
        size_t   i;

        for (i = 0; i < c->n && i < LAB_MSKF; i++)
                if (((msk >> i) & 1) && lab_fl[i].t_snd < end)
                        lab_fl[i].t_snd = end;

        return st_t + c->st_p + (st_t / c->st_p % 3) * c->st_p / 5;
}

/* Free the ctx pairs, once per group when the flows share them. */
static void lab_flows_fini(const struct lab_cfg * c)
{
        size_t i;

        for (i = 0; i < c->n; i++) {
                if (c->shared && lab_owner(c, i) != i)
                        continue;

                mb_ecn_ctx_destroy(lab_fl[i].snd);
                mb_ecn_ctx_destroy(lab_fl[i].rcv);
        }
}

/*
 * Shared flows take the group owner's ctx pair, as production interns
 * one per (peer, qos cube). The RTT seeds at the layer default, and a
 * seeded flow starts in AIMD, so the sweep probes the attractor.
 */
static int lab_flows_init(const struct lab_cfg * c)
{
        struct lab_flow * f;
        size_t            i;

        memset(lab_fl, 0, sizeof(lab_fl));

        for (i = 0; i < c->n; i++) {
                f = &lab_fl[i];

                if (c->shared && lab_owner(c, i) != i) {
                        f->snd = lab_fl[lab_owner(c, i)].snd;
                        f->rcv = lab_fl[lab_owner(c, i)].rcv;
                } else {
                        f->snd = mk_ctx();
                        f->rcv = mk_ctx();
                }

                if (f->snd == NULL || f->rcv == NULL) {
                        printf("lab: no memory.\n");
                        goto fail;
                }

                f->ia    = c->ia[i];
                f->lag   = c->lag[i];
                f->hb_t  = LAB_NONE;
                f->r_lo  = UINT64_MAX;
                f->t_snd = c->t0[i];
                f->app   = c->t0[i];
                f->m_t   = c->t0[i];

                f->snd->ss_tc = 2 * CA_SS_RTT_DEF * MILLION;

                if (c->r0[i] == 0)
                        continue;

                f->snd->rate      = c->r0[i];
                f->snd->inv_rate  = mb_ecn_rate_inv(c->r0[i]);
                f->snd->snd_r0    = c->r0[i];
                f->snd->snd_rate  = c->r0[i];
                f->snd->tx_cav    = true;
        }

        return 0;
 fail:
        lab_flows_fini(c);
        return -1;
}

/*
 * The earliest event as flow * 4 + kind, or -2 for the service tick,
 * with its time in nxt. A churning flow that is gone resumes its app
 * at the next period.
 */
static int lab_next_ev(const struct lab_cfg * c,
                       uint64_t               smp,
                       uint64_t *             nxt)
{
        struct lab_flow * f;
        int               ev = -1;
        size_t            i;

        *nxt = LAB_NONE;

        for (i = 0; i < c->n; i++) {
                f = &lab_fl[i];
                if (c->t1[i] > 0 && f->t_snd >= c->t1[i]) {
                        f->t_snd = LAB_NONE;
                } else if (c->ch_p > 0 && !lab_is_up(c, i, f->t_snd)) {
                        f->t_snd = (f->t_snd / c->ch_p + 1) * c->ch_p;
                        f->app   = f->t_snd;
                }

                if (f->t_snd < *nxt) {
                        *nxt = f->t_snd;
                        ev   = (int) i * 4;
                }

                if (f->fb_n > 0 && f->fbq[f->fb_h].t < *nxt) {
                        *nxt = f->fbq[f->fb_h].t;
                        ev   = (int) i * 4 + 1;
                }

                if (f->hb_t < *nxt) {
                        *nxt = f->hb_t;
                        ev   = (int) i * 4 + 2;
                }
        }

        if (smp < *nxt) {
                *nxt = smp;
                ev   = -2;
        }

        return ev;
}

/* Close the flow accounting and print the link and per-flow report. */
static void lab_report(const struct lab_cfg * c)
{
        struct lab_link *   l    = &lab_lnk;
        uint64_t            span = c->dur - c->wu;
        double              secs = (double) span / BILLION;
        struct lab_flow *   f;
        struct mb_ecn_ctx * s;
        size_t              i;

        printf("%-14s C %5.2f MB/s n %zu | util %5.1f%% "
               "q %6.1f pkt mk %5.1f e%% %4.1f eps %3zu\n",
               c->name, (double) c->cap / MILLION, c->n,
               100.0 * (double) l->dlv / ((double) c->cap * secs),
               (double) l->q_int / ((double) span * c->len),
               (double) l->mk_int / (double) span,
               100.0 * (double) l->e_ns / (double) span,
               l->e_eps);

        for (i = 0; i < c->n; i++) {
                f = &lab_fl[i];
                s = f->snd;

                lab_f_acct(f, c->dur, c->wu);

                if (c->sc_hi > c->sc_lo)
                        printf("  f%zu score %.3f Mb/s in [%llu,%llu)s\n",
                               i, 8.0 * (double) f->dlv2 /
                               ((double) (c->sc_hi - c->sc_lo) / BILLION
                                * MILLION),
                               (unsigned long long) (c->sc_lo / BILLION),
                               (unsigned long long) (c->sc_hi / BILLION));
                printf("  f%zu %s dlv %5.3f Mb/s rate mean %8.0f "
                       "lo %8" PRIu64 " hi %8" PRIu64 "\n"
                       "     lead %8" PRIu64 " prop %8" PRIu64
                       " cuts %4" PRIu64 " hold %4.1f%% lim %4.1f%%"
                       " idl %4.1f%% loss %" PRIu64 "\n",
                       i, f->ia == 0 ? "gdy" : "cbr",
                       8.0 * (double) f->dlv / ((double) secs * MILLION),
                       (double) f->r_int / (double) span,
                       f->r_lo == UINT64_MAX ? 0 : f->r_lo, f->r_hi,
                       f->lead_B, f->prop_B, f->cuts,
                       100.0 * (double) f->hold_ns / (double) span,
                       100.0 * (double) f->lim_ns / (double) span,
                       100.0 * (double) f->idl_ns / (double) span,
                       s->n_loss);

                f->n_loss = s->n_loss;
        }
}

static void lab_run(const struct lab_cfg * c)
{
        struct lab_link * l = &lab_lnk;
        uint64_t          smp = 0;
        uint64_t          st_t;
        uint64_t          nxt;
        size_t            i;
        int               ev;

        memset(l, 0, sizeof(*l));

        l->cap    = c->cap;
        l->cc     = cap_enc(c->cap);
        l->qmax   = c->qmax;
        l->e_from = LAB_NONE;

        if (lab_flows_init(c) < 0)
                return;

        lab_len   = c->len;
        lab_lossy = c->lossy;
        lab_sc_lo = c->sc_lo;
        lab_sc_hi = c->sc_hi;

        st_t = c->st_p > 0 ? c->st_p : LAB_NONE;

        while (true) {
                if (st_t != LAB_NONE && smp >= st_t)
                        st_t = lab_stall(c, st_t);

                ev = lab_next_ev(c, smp, &nxt);

                if (nxt >= c->dur)
                        break;

                if (ev == -2) {
                        lab_service(l, smp, c->wu);

                        smp += LAB_SAMPLE;
                        continue;
                }

                i = (size_t) (ev / 4);
                switch (ev % 4) {
                case 0:
                        lab_send(l, &lab_fl[i], i,
                                 c->shared ? lab_live(c, i, nxt) : 1,
                                 c->wu, c->no_loc);
                        break;
                case 1:
                        lab_fb_apply(&lab_fl[i], c->wu);
                        break;
                default:
                        lab_f_acct(&lab_fl[i], lab_fl[i].hb_t, c->wu);
                        if (lab_fl[i].hb_t > lab_fl[i].last)
                                lab_fl[i].last = lab_fl[i].hb_t;
                        mb_ecn_ctx_rtt(lab_fl[i].snd, lab_fl[i].last,
                                       lab_fl[i].hb_rtt);
                        lab_fl[i].hb_t = LAB_NONE;
                        break;
                }
        }

        lab_service(l, c->dur, c->wu);
        lab_q_acct(l, c->dur, c->wu);

        lab_report(c);

        lab_flows_fini(c);
}

/*
 * The integration tests' cbr_protection (n = 2) and
 * single_flow_slow_link (n = 1): bottleneck one hop past the sender,
 * 2 ms feedback, scored over the integration test's own window.
 */
static void lab_cfg_std(struct lab_cfg * c,
                        const char *     name,
                        uint64_t         cap,
                        size_t           n)
{
        size_t i;

        memset(c, 0, sizeof(*c));

        c->name   = name;
        c->cap    = cap;
        c->n      = n;
        c->len    = LEN;
        c->qmax   = 1024 * c->len;     /* SSM_RBUFF_SIZE */
        c->no_loc = true;

        for (i = 0; i < n; i++)
                c->lag[i] = 2 * MS;

        if (n == 2) {                  /* cbr_protection          */
                c->ia[1]  = c->len * BILLION / 375000;
                c->t0[0]  = 300 * MS;
                c->dur    = 35ULL * BILLION;
                c->wu     = 30ULL * BILLION;
                c->sc_lo  = 5ULL * BILLION;
                c->sc_hi  = 30ULL * BILLION;
        } else {                       /* single_flow_slow_link   */
                c->dur    = 95ULL * BILLION;
                c->wu     = 55ULL * BILLION;
                c->sc_lo  = 20ULL * BILLION;
                c->sc_hi  = 50ULL * BILLION;
        }
}

/* From 1 Gb/s up the path carries 9000 B frames; below, 1000 B. */
static size_t lab_frame(uint64_t cap)
{
        return cap >= 125000000 ? 9000 : LEN;
}

/* Spread the seeds may end on and still count as one attractor. */
#define LAB_FIX_TOL 0.10

/*
 * Two flows on one bottleneck reach one split from any seed, as the
 * difference mode contracts. Seeds that disagree show a second
 * attractor; agreement away from 1 shows a bias.
 */
static int test_mb_ecn_lab_fixpoint(uint64_t cap,
                                    uint64_t lag)
{
        static struct lab_cfg c;
        static const unsigned num[] = { 1, 1, 4 };
        static const unsigned den[] = { 4, 1, 1 };
        uint64_t              kb = cap * 8 / 1000;
        uint64_t              ms = lag / MS;
        double                r[3];
        double                lo;
        double                hi;
        size_t                i;

        TEST_START("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);

        for (i = 0; i < 3; i++) {
                lab_cfg_std(&c, "fixpoint", cap, 2);

                c.len  = lab_frame(cap);
                c.qmax = 1024 * c.len;

                c.ia[1]  = 0;            /* both greedy */
                c.t0[0]  = 0;
                c.lag[0] = lag;
                c.lag[1] = lag;
                c.dur    = 60ULL * BILLION;
                c.wu     = 30ULL * BILLION;
                c.sc_lo  = 30ULL * BILLION;
                c.sc_hi  = 60ULL * BILLION;
                c.r0[0]  = cap * num[i] / (num[i] + den[i]);
                c.r0[1]  = cap * den[i] / (num[i] + den[i]);

                lab_run(&c);

                if (lab_fl[1].dlv2 == 0) {
                        printf("seed %u:%u starved a flow.\n", num[i], den[i]);
                        goto fail;
                }

                r[i] = (double) lab_fl[0].dlv2 / (double) lab_fl[1].dlv2;
        }

        lo = hi = r[0];

        for (i = 1; i < 3; i++) {
                if (r[i] < lo)
                        lo = r[i];

                if (r[i] > hi)
                        hi = r[i];
        }

        if (hi > lo * (1.0 + LAB_FIX_TOL)) {
                printf("seeds disagree: %.3f %.3f %.3f.\n", r[0], r[1], r[2]);
                goto fail;
        }

        if (lo < 1.0 - LAB_FIX_TOL || hi > 1.0 + LAB_FIX_TOL) {
                printf("split %.3f..%.3f is not fair.\n", lo, hi);
                goto fail;
        }

        TEST_SUCCESS("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);
        return TEST_RC_FAIL;
}

static int test_mb_ecn_lab_fixpoint_all(void)
{
#ifdef MB_ECN_LAB_FULL
        static const uint64_t cap[] = { 1250000000, 12500000,
                                        1250000, 62500 };
#else
        static const uint64_t cap[] = { 1250000, 62500 };
#endif
        static const uint64_t lag[] = { 2 * MS, 42 * MS };
        int                   ret = 0;
        size_t                i;
        size_t                j;

        for (i = 0; i < sizeof(cap) / sizeof(cap[0]); i++)
                for (j = 0; j < sizeof(lag) / sizeof(lag[0]); j++)
                        ret |= test_mb_ecn_lab_fixpoint(cap[i], lag[j]);

        return ret;
}

/* Spread across eight flows that still counts as one even split. */
#define LAB_N8_TOL 0.10

/*
 * Below this, packet-size quantisation dominates the spread, so the
 * split is not scored here; starvation (lo == 0) and the utilisation
 * gate still apply, so the exemption is narrow.
 */
#define LAB_N8_FAIR 125000            /* bytes/s, 1 Mb/s */

/* Aggregate the link has to carry for a run to say anything at all. */
#define LAB_N8_UTIL 2                 /* divisor: half of capacity */

/*
 * Eight flows on one bottleneck. The additive increase is per flow, so
 * both the aggregate probe and the contraction rate scale with the flow
 * count, and this is where that scaling shows.
 */
static int test_mb_ecn_lab_fixpoint_n8(uint64_t cap,
                                       uint64_t lag)
{
        static struct lab_cfg c;
        uint64_t              kb    = cap * 8 / 1000;
        uint64_t              ms    = lag / MS;
        double                worst = 1.0;
        uint64_t              want;
        uint64_t              tot;
        uint64_t              sum;
        uint64_t              lo;
        uint64_t              hi;
        size_t                i;
        size_t                j;

        TEST_START("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);

        for (i = 0; i < 3; i++) {
                lab_cfg_std(&c, "fixpoint-n8", cap, LAB_N8);

                c.len  = lab_frame(cap);
                c.qmax = 1024 * c.len;

                sum = 0;

                for (j = 0; j < LAB_N8; j++)
                        sum += lab_n8_w[i][j];

                for (j = 0; j < LAB_N8; j++) {
                        c.ia[j]  = 0;          /* all greedy */
                        c.t0[j]  = 0;
                        c.lag[j] = lag;
                        c.r0[j]  = cap * lab_n8_w[i][j] / sum;
                }

                c.dur   = 400ULL * BILLION;
                c.wu    = 200ULL * BILLION;
                c.sc_lo = 200ULL * BILLION;
                c.sc_hi = 400ULL * BILLION;

                lab_run(&c);

                tot = 0;
                lo  = lab_fl[0].dlv2;
                hi  = lab_fl[0].dlv2;

                for (j = 0; j < LAB_N8; j++) {
                        tot += lab_fl[j].dlv2;
                        if (lab_fl[j].dlv2 < lo)
                                lo = lab_fl[j].dlv2;

                        if (lab_fl[j].dlv2 > hi)
                                hi = lab_fl[j].dlv2;
                }

                if (lo == 0) {
                        printf("seed %zu wedged a flow.\n", i);
                        goto fail;
                }

                want = cap * ((c.sc_hi - c.sc_lo) / BILLION);
                if (tot < want / LAB_N8_UTIL) {
                        printf("seed %zu carried %" PRIu64 " of %" PRIu64
                               " bytes.\n", i, tot, want);
                        goto fail;
                }

                if ((double) hi / (double) lo > worst)
                        worst = (double) hi / (double) lo;
        }

        if (cap >= LAB_N8_FAIR && worst > 1.0 + LAB_N8_TOL) {
                printf("widest split %.3f across eight flows.\n", worst);
                goto fail;
        }

        TEST_SUCCESS("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);
        return TEST_RC_FAIL;
}

static int test_mb_ecn_lab_fixpoint_n8_all(void)
{
#ifdef MB_ECN_LAB_FULL
        static const uint64_t cap[] = { 1250000000, 12500000,
                                        1250000, 62500 };
#else
        static const uint64_t cap[] = { 1250000, 62500 };
#endif
        static const uint64_t lag[] = { 2 * MS, 42 * MS };
        int                   ret = 0;
        size_t                i;
        size_t                j;

        for (i = 0; i < sizeof(cap) / sizeof(cap[0]); i++)
                for (j = 0; j < sizeof(lag) / sizeof(lag[0]); j++)
                        ret |= test_mb_ecn_lab_fixpoint_n8(cap[i], lag[j]);

        return ret;
}

/* Jain's fairness index over the score bytes of flows [lo, hi). */
static double lab_jain(size_t lo,
                       size_t hi)
{
        double s  = 0.0;
        double s2 = 0.0;
        double x;
        size_t i;

        for (i = lo; i < hi; i++) {
                x   = (double) lab_fl[i].dlv2;
                s  += x;
                s2 += x * x;
        }

        if (s2 == 0.0)
                return 0.0;

        return s * s / ((double) (hi - lo) * s2);
}

/* Greedy flows on one ctx, all from t = 0, short feedback path. */
static void lab_cfg_shared(struct lab_cfg * c,
                           const char *     name,
                           uint64_t         cap,
                           size_t           n)
{
        size_t i;

        lab_cfg_std(c, name, cap, n);

        c->shared = true;

        for (i = 0; i < n; i++) {
                c->ia[i]  = 0;
                c->t0[i]  = 0;
                c->lag[i] = 2 * MS;
        }
}

/*
 * ca_ctx_get interns one ctx per (peer, qos cube): its flows share one
 * rate, which settles at the path's C whatever n, with C / n per flow.
 * Spread that rate may sit in and still count as the path rate.
 */
#define LAB_SHR_LO 0.90
#define LAB_SHR_HI 1.05

/* Peak of the rate over the settled window. */
#define LAB_SHR_PK 1.25

/*
 * Greedy flows on one ctx; with churn, half of them join at tc and
 * leave at 2 * tc. Warmup ends at the last change, so r_hi is the
 * peak of the epoch that has to settle back to the path rate.
 */
static int test_mb_ecn_lab_shared(uint64_t cap,
                                  size_t   n,
                                  bool     churn)
{
        static struct lab_cfg c;
        const char *          ch   = churn ? ", churn" : "";
        uint64_t              kb   = cap * 8 / 1000;
        uint64_t              tc   = 20ULL * BILLION;
        uint64_t              fair;
        uint64_t              mean;
        double                jain;
        size_t                nl;
        size_t                i;

        TEST_START("(%" PRIu64 " kb/s, %zu flows%s)", kb, n, ch);

        lab_cfg_shared(&c, churn ? "shr-churn" : "shr-gdy", cap, n);

        nl = churn ? n / 2 : n;
        for (i = nl; i < n; i++) {
                c.t0[i] = tc;
                c.t1[i] = 2 * tc;
        }

        fair = cap;   /* the ctx's rate is the path's, whatever nl */

        c.dur   = 2 * tc + 60ULL * BILLION;
        c.wu    = churn ? 2 * tc : 40ULL * BILLION;
        c.sc_lo = c.wu + 20ULL * BILLION;
        c.sc_hi = c.dur;

        lab_run(&c);

        mean = lab_fl[0].r_int / (c.dur - c.wu);
        jain = lab_jain(0, nl);

        if (mean < (uint64_t) (LAB_SHR_LO * (double) fair)
            || mean > (uint64_t) (LAB_SHR_HI * (double) fair)) {
                printf("rate %" PRIu64 " is not a %" PRIu64 " share.\n",
                       mean, fair);
                goto fail;
        }

        if (lab_fl[0].r_hi > (uint64_t) (LAB_SHR_PK * (double) fair)) {
                printf("rate peaked at %.2f of the share.\n",
                       (double) lab_fl[0].r_hi / (double) fair);
                goto fail;
        }

        if (jain < LAB_SHR_JN) {
                printf("fairness %.4f across %zu flows.\n", jain, nl);
                goto fail;
        }

        TEST_SUCCESS("(%" PRIu64 " kb/s, %zu flows%s)", kb, n, ch);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, %zu flows%s)", kb, n, ch);
        return TEST_RC_FAIL;
}

/*
 * Offered load per flow, as a divisor of the fair share. Low enough
 * that the aggregate never fills the link, so nothing marks and the
 * offered-load path is the only thing bounding the rate.
 */
#define LAB_SRC_DIV 4

/*
 * mb_ecn_ceiling admits 4/3 of the load the ctx offers, plus the
 * increase banked between window closes. A per-flow read of the load
 * sits n times higher, so a wide slack still tells the two apart.
 */
#define LAB_SRC_CEIL 2.0

/* Churn half-period; below CA_SND_WIN no window would ever close. */
#define LAB_SRC_CHP (100 * MS)

/*
 * Source-limited flows on one ctx, each well under its share, so only
 * mb_ecn_ceiling and the backlog level bound the rate. With churn,
 * flows n / 4 and up come and go every LAB_SRC_CHP and are scored.
 */
static int test_mb_ecn_lab_shared_load(uint64_t cap,
                                       size_t   n,
                                       bool     churn)
{
        static struct lab_cfg c;
        const char *          ch  = churn ? ", churn" : "";
        uint64_t              kb  = cap * 8 / 1000;
        uint64_t              off = cap / (LAB_SRC_DIV * n);
        uint64_t              hi;
        double                jain;
        size_t                ns;
        size_t                i;

        TEST_START("(%" PRIu64 " kb/s, %zu flows%s)", kb, n, ch);

        lab_cfg_shared(&c, churn ? "src-churn" : "src-cbr", cap, n);

        for (i = 0; i < n; i++)
                c.ia[i] = c.len * BILLION / off;

        if (churn) {
                c.ch_p = 2 * LAB_SRC_CHP;
                c.ch_f = ~0u << (n / 4);
        }

        c.dur   = 120ULL * BILLION;
        c.wu    = 60ULL * BILLION;
        c.sc_lo = 60ULL * BILLION;
        c.sc_hi = 120ULL * BILLION;

        lab_run(&c);

        hi = lab_fl[0].r_hi;

        ns   = churn ? n / 4 : 0;
        jain = lab_jain(ns, n);

        if (hi > (uint64_t) (LAB_SRC_CEIL * (double) (n * off))) {
                printf("rate peaked at %.2f of the %" PRIu64 " offered "
                       "together, %.2f of the %" PRIu64 " path.\n",
                       (double) hi / (double) (n * off), n * off,
                       (double) hi / (double) cap, cap);
                goto fail;
        }

        if (jain < LAB_SHR_JN) {
                printf("fairness %.4f across %zu flows.\n", jain, n - ns);
                goto fail;
        }

        TEST_SUCCESS("(%" PRIu64 " kb/s, %zu flows%s)", kb, n, ch);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, %zu flows%s)", kb, n, ch);
        return TEST_RC_FAIL;
}

/* Split each ctx may sit at: the integration tests' own criterion. */
#define LAB_FORK_TOL 0.25

/* Did a ctx carry half the link, to the fork tolerance? */
static bool lab_is_half(uint64_t bytes,
                        uint64_t link)
{
        double lo = (1.0 - LAB_FORK_TOL) * (double) link / 2;
        double hi = (1.0 + LAB_FORK_TOL) * (double) link / 2;

        return (double) bytes >= lo && (double) bytes <= hi;
}

/* Aggregate the fork has to carry for a run to say anything at all. */
#define LAB_FORK_UTIL 0.90

/*
 * The integration fork: one greedy flow on ctx a, nb on ctx b. The ctxs
 * split the link evenly and b's flows split its half; a pacer handing
 * each flow the whole rate gives b nb / (nb + 1) of the link.
 */
static int test_mb_ecn_lab_fork(uint64_t cap,
                                size_t   nb)
{
        static struct lab_cfg c;
        uint64_t              kb = cap * 8 / 1000;
        uint64_t              a;
        uint64_t              b = 0;
        uint64_t              link;
        double                jain;
        size_t                i;

        TEST_START("(%" PRIu64 " kb/s, 1 + %zu flows)", kb, nb);

        lab_cfg_shared(&c, "fork", cap, 1 + nb);

        for (i = 1; i <= nb; i++)
                c.grp[i] = 1;

        c.dur   = 60ULL * BILLION;
        c.wu    = 30ULL * BILLION;
        c.sc_lo = 30ULL * BILLION;
        c.sc_hi = 60ULL * BILLION;

        lab_run(&c);

        a = lab_fl[0].dlv2;

        for (i = 1; i <= nb; i++)
                b += lab_fl[i].dlv2;

        link = cap * ((c.sc_hi - c.sc_lo) / BILLION);
        if (a + b < (uint64_t) (LAB_FORK_UTIL * (double) link)) {
                printf("fork carried %.2f of the link.\n",
                       (double) (a + b) / (double) link);
                goto fail;
        }

        if (!lab_is_half(a, link) || !lab_is_half(b, link)) {
                printf("ctx split %.2f / %.2f of the link.\n",
                       (double) a / (double) link, (double) b / (double) link);
                goto fail;
        }

        jain = lab_jain(1, 1 + nb);
        if (jain < LAB_SHR_JN) {
                printf("fairness %.4f across %zu flows on one ctx.\n",
                       jain, nb);
                goto fail;
        }

        TEST_SUCCESS("(%" PRIu64 " kb/s, 1 + %zu flows)", kb, nb);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, 1 + %zu flows)", kb, nb);
        return TEST_RC_FAIL;
}

/* Summary of the last run: demand, utilisation, hold fraction. */
struct lab_sum {
        double   demand;                /* sum of mean rates / cap    */
        double   util;                  /* link bytes delivered / cap */
        double   hold;                  /* time held, per controller  */
        double   mark;                  /* mean mark (ecn)            */
        double   jain;                  /* over the score window      */
        double   loss;                  /* dropped / offered at link  */
        size_t   starved;               /* flows with no score bytes  */
        uint64_t cuts;                  /* loss cuts, all flows       */
};

static void lab_summary(const struct lab_cfg * c,
                        struct lab_sum *       s)
{
        uint64_t span = c->dur - c->wu;
        double   secs = (double) span / BILLION;
        double   sum  = 0.0;
        double   hold = 0.0;
        size_t   i;

        s->starved = 0;
        s->cuts    = 0;

        for (i = 0; i < c->n; i++) {
                sum  += (double) lab_fl[i].r_int / (double) span;
                hold += (double) lab_fl[i].hold_ns / (double) span;
                s->cuts += lab_fl[i].n_loss;

                if (lab_fl[i].dlv2 == 0)
                        s->starved++;
        }

        s->demand = sum / (double) c->cap;
        s->util   = (double) lab_lnk.dlv / ((double) c->cap * secs);
        s->hold   = hold / (double) c->n;
        s->mark   = (double) lab_lnk.mk_int / (double) span / 32.0;
        s->jain   = lab_jain(0, c->n);
        s->loss   = (double) lab_lnk.drops
                    / (double) (lab_lnk.dlv + lab_lnk.drops + 1);

        printf("  n %2zu demand %.3f util %.3f loss %4.1f%% mark %5.1f "
               "hold %4.1f%% jain %.4f empty %4.1f%% (%zu eps) cuts %"
               PRIu64 "\n",
               c->n, s->demand, s->util, 100.0 * s->loss, s->mark,
               100.0 * s->hold, s->jain,
               100.0 * (double) lab_lnk.e_ns / (double) span,
               lab_lnk.e_eps, s->cuts);
}

/* The production ring's ceiling: 10 ms of drain, 4 to 959 slots. */
static size_t lab_ring(uint64_t cap,
                       size_t   len)
{
        uint64_t slots = cap / 100 / len;

        if (slots < 4)
                return 4;

        return slots > 959 ? 959 : (size_t) slots;
}

/*
 * Greedy controllers on their own ctxs, seeded at the split, across
 * a lossy boundary with qpkts of buffer: nothing but the mark tells
 * them they are too many.
 */
static void lab_cfg_gate(struct lab_cfg * c,
                         const char *     name,
                         uint64_t         cap,
                         size_t           n,
                         size_t           qpkts)
{
        size_t i;

        lab_cfg_std(c, name, cap, n);

        c->qmax  = qpkts * c->len;
        c->lossy = true;

        for (i = 0; i < n; i++) {
                c->ia[i]  = 0;
                c->t0[i]  = 0;
                c->lag[i] = 2 * MS;
                c->r0[i]  = cap / n;
        }

        c->dur   = 60ULL * BILLION;
        c->wu    = 30ULL * BILLION;
        c->sc_lo = 30ULL * BILLION;
        c->sc_hi = 60ULL * BILLION;
}

/*
 * Sweep n across the gate, where the increase holds and n controllers
 * shed until the queue drains. Up to nmax the release burst fits the
 * buffer; past it drops ration, and only starvation and drain count.
 */
static int test_mb_ecn_lab_gate_sweep(uint64_t cap,
                                      size_t   qpkts,
                                      size_t   nmax)
{
        static const size_t   n[] = { 2, 4, 8, 16, 32, 64 };
        static struct lab_cfg c;
        struct lab_sum        s;
        uint64_t              kb  = cap * 8 / 1000;
        size_t                bad = 0;
        size_t                i;

        TEST_START("(%" PRIu64 " kb/s, %zu pkt, n <= %zu)", kb, qpkts, nmax);

        for (i = 0; i < sizeof(n) / sizeof(n[0]); i++) {
                lab_cfg_gate(&c, "gate-sweep", cap, n[i], qpkts);

                lab_run(&c);

                lab_summary(&c, &s);

                if (s.starved > 0) {
                        printf("n %zu starved %zu flows.\n", n[i], s.starved);
                        bad++;
                }

                if (lab_lnk.e_eps == 0) {
                        printf("n %zu never drained the queue.\n", n[i]);
                        bad++;
                }

                if (n[i] > nmax)
                        continue;

                if (s.demand > LAB_GATE_DEMAND) {
                        printf("n %zu demands %.2f of the link.\n",
                               n[i], s.demand);
                        bad++;
                }

                if (s.util < LAB_GATE_UTIL) {
                        printf("n %zu carried %.2f of the link.\n",
                               n[i], s.util);
                        bad++;
                }

                if (s.jain < LAB_GATE_JN) {
                        printf("n %zu fairness %.4f.\n", n[i], s.jain);
                        bad++;
                }
        }

        if (bad > 0)
                goto fail;

        TEST_SUCCESS("(%" PRIu64 " kb/s, %zu pkt, n <= %zu)", kb, qpkts, nmax);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, %zu pkt, n <= %zu)", kb, qpkts, nmax);
        return TEST_RC_FAIL;
}

/* Split n controllers reach from a geometric spread of seeds. */
#define LAB_GATE_CONV 0.95

/*
 * Past the gate from a geometric spread of seeds: only the increase
 * below the gate brings the shares together.
 */
static int test_mb_ecn_lab_gate_converge(uint64_t cap,
                                         size_t   n,
                                         double   spread)
{
        static struct lab_cfg c;
        struct lab_sum        s;
        uint64_t              kb = cap * 8 / 1000;
        double                fair = (double) cap / (double) n;
        double                e;
        size_t                i;

        TEST_START("(%" PRIu64 " kb/s, %zu flows, %.0fx)", kb, n, spread);

        lab_cfg_gate(&c, "gate-conv", cap, n, lab_ring(cap, LEN));

        for (i = 0; i < n; i++) {
                e = 2.0 * (double) i / (double) (n - 1) - 1.0;
                c.r0[i] = (uint64_t) (fair * pow(spread, e));
        }

        c.dur   = 90ULL * BILLION;
        c.wu    = 60ULL * BILLION;
        c.sc_lo = 60ULL * BILLION;
        c.sc_hi = 90ULL * BILLION;

        lab_run(&c);

        lab_summary(&c, &s);

        if (s.starved > 0) {
                printf("starved %zu flows.\n", s.starved);
                goto fail;
        }

        if (s.demand > LAB_GATE_DEMAND) {
                printf("demands %.2f of the link.\n", s.demand);
                goto fail;
        }

        if (s.jain < LAB_GATE_CONV) {
                printf("fairness %.4f from a %.0fx spread.\n", s.jain, spread);
                goto fail;
        }

        TEST_SUCCESS("(%" PRIu64 " kb/s, %zu flows, %.0fx)", kb, n, spread);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, %zu flows, %.0fx)", kb, n, spread);
        return TEST_RC_FAIL;
}

/* Share of the run a controller on a live long path may sit held. */
#define LAB_GATE_HOLD 0.5

/*
 * Two greedy flows behind a feedback lag of a few hundred ms, where
 * the liveness horizon follows the heartbeat: the uncongested path
 * takes no loss cuts, rarely sits held and claims the link.
 */
static int test_mb_ecn_lab_long_rtt(uint64_t cap,
                                    uint64_t lag)
{
        static struct lab_cfg c;
        struct lab_sum        s;
        uint64_t              kb = cap * 8 / 1000;
        uint64_t              ms = lag / MS;
        size_t                i;

        TEST_START("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);

        lab_cfg_gate(&c, "long-rtt", cap, 2, lab_ring(cap, LEN));

        for (i = 0; i < 2; i++)
                c.lag[i] = lag;

        lab_run(&c);

        lab_summary(&c, &s);

        if (s.starved > 0) {
                printf("starved %zu flows.\n", s.starved);
                goto fail;
        }

        if (s.cuts > 0) {
                printf("%" PRIu64 " loss cuts on an uncongested path.\n",
                       s.cuts);
                goto fail;
        }

        if (s.hold > LAB_GATE_HOLD) {
                printf("held %.0f%% of the run on a live path.\n",
                       100.0 * s.hold);
                goto fail;
        }

        if (s.util < LAB_GATE_UTIL) {
                printf("carried %.2f of the link.\n", s.util);
                goto fail;
        }

        TEST_SUCCESS("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, lag %" PRIu64 " ms)", kb, ms);
        return TEST_RC_FAIL;
}

/* Largest light demand over the smallest. */
#define LAB_SKEW_SPREAD 32.0

/* Weight of light controller i of nl: geometric across the spread. */
static double lab_skew_w(size_t i,
                         size_t nl)
{
        if (nl < 2)
                return 1.0;

        return pow(LAB_SKEW_SPREAD, (double) i / (double) (nl - 1));
}

/* Link share the light controllers offer together. */
#define LAB_SKEW_LOAD 0.5

/*
 * An exchange port: ng greedy controllers, then nl app-limited ones
 * whose demands spread geometrically and add up to LAB_SKEW_LOAD.
 */
static void lab_cfg_skew(struct lab_cfg * c,
                         uint64_t         cap,
                         size_t           ng,
                         size_t           nl)
{
        double load = LAB_SKEW_LOAD * (double) cap;
        double w    = 0.0;
        size_t i;

        lab_cfg_gate(c, "gate-skew", cap, ng + nl, lab_ring(cap, LEN));

        for (i = 0; i < nl; i++)
                w += lab_skew_w(i, nl);

        for (i = 0; i < nl; i++)
                c->ia[ng + i] = (uint64_t) ((double) c->len * BILLION * w
                                            / (load * lab_skew_w(i, nl)));
}

/* Share of its offered load the light class has to get through. */
#define LAB_SKEW_LIGHT 0.95

/*
 * Hundreds of controllers, few of them backlogged: the light ones get
 * what they offer and the greedy ones split what is left evenly.
 */
static int test_mb_ecn_lab_gate_skew(uint64_t cap,
                                     size_t   ng,
                                     size_t   nl)
{
        static struct lab_cfg c;
        struct lab_sum        s;
        uint64_t              kb  = cap * 8 / 1000;
        uint64_t              off = 0;
        uint64_t              dlv = 0;
        uint64_t              span;
        double                jain;
        size_t                i;

        TEST_START("(%" PRIu64 " kb/s, %zu + %zu flows)", kb, ng, nl);

        lab_cfg_skew(&c, cap, ng, nl);

        lab_run(&c);

        lab_summary(&c, &s);

        span = c.sc_hi - c.sc_lo;

        for (i = ng; i < ng + nl; i++) {
                off += span / c.ia[i] * c.len;
                dlv += lab_fl[i].dlv2;
        }

        jain = lab_jain(0, ng);

        printf("  light %.3f of offered, greedy jain %.4f\n",
               (double) dlv / (double) off, jain);

        if (s.starved > 0) {
                printf("starved %zu flows.\n", s.starved);
                goto fail;
        }

        if (lab_lnk.e_eps == 0) {
                printf("never drained the queue.\n");
                goto fail;
        }

        if (s.util < LAB_GATE_UTIL) {
                printf("carried %.2f of the link.\n", s.util);
                goto fail;
        }

        if ((double) dlv < LAB_SKEW_LIGHT * (double) off) {
                printf("light class got %.3f of its offered load.\n",
                       (double) dlv / (double) off);
                goto fail;
        }

        if (jain < LAB_GATE_JN) {
                printf("fairness %.4f across %zu greedy flows.\n", jain, ng);
                goto fail;
        }

        TEST_SUCCESS("(%" PRIu64 " kb/s, %zu + %zu flows)", kb, ng, nl);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%" PRIu64 " kb/s, %zu + %zu flows)", kb, ng, nl);
        return TEST_RC_FAIL;
}

/*
 * Report only: cbr_protection and single_flow_slow_link over capacity,
 * two greedy flows over equal and unequal lag, service stalls, and a
 * greedy flow joining a settled CBR flow or a greedy incumbent.
 */
static int test_mb_ecn_lab(void)
{
        static const uint64_t gc_cap[] = { 625000, 1250000, 12500000 };
        static const char *   gc_nm[]  = { "gc-5M", "gc-10M", "gc-100M" };
        static const uint64_t sf_cap[] = { 62500, 125000, 1250000 };
        static const char *   sf_nm[]  = { "sf-500k", "sf-1M", "sf-10M" };
        static const uint64_t g2_cap[] = {
                1250000, 1250000, 1250000, 62500, 62500, 62500
        };
        static const uint64_t g2_lag[] = {
                2 * MS, 20 * MS, 42 * MS, 2 * MS, 20 * MS, 42 * MS
        };
        static const char *   g2_nm[]  = {
                "g2-10M-2", "g2-10M-20", "g2-10M-42",
                "g2-500k-2", "g2-500k-20", "g2-500k-42"
        };
        static const uint64_t ul_lag[] = { 20 * MS, 42 * MS };
        static const char *   ul_nm[]  = { "g2-ul20", "g2-ul42" };
        static struct lab_cfg c;
        size_t                i;

        TEST_START();

        for (i = 0; i < 3; i++) {
                lab_cfg_std(&c, gc_nm[i], gc_cap[i], 2);
                lab_run(&c);
        }

        for (i = 0; i < 3; i++) {
                lab_cfg_std(&c, sf_nm[i], sf_cap[i], 1);
                lab_run(&c);
        }

        for (i = 0; i < 6; i++) {
                lab_cfg_std(&c, g2_nm[i], g2_cap[i], 2);

                c.ia[1]  = 0;
                c.lag[0] = g2_lag[i];
                c.lag[1] = g2_lag[i];
                c.dur    = 65ULL * BILLION;
                c.wu     = 35ULL * BILLION;

                lab_run(&c);
        }

        for (i = 0; i < 2; i++) {
                lab_cfg_std(&c, ul_nm[i], 1250000, 2);

                c.ia[1]  = 0;
                c.lag[1] = ul_lag[i];
                c.dur    = 65ULL * BILLION;
                c.wu     = 35ULL * BILLION;

                lab_run(&c);
        }

        lab_cfg_std(&c, "st-gc", 1250000, 2);

        c.st_d = 60 * MS;
        c.st_p = 400 * MS;

        lab_run(&c);

        lab_cfg_std(&c, "st-sf", 125000, 1);

        c.st_d = 200 * MS;
        c.st_p = BILLION;

        lab_run(&c);

        lab_cfg_std(&c, "st-pf", 1250000, 2);

        c.st_d = 100 * MS;
        c.st_p = 300 * MS;
        c.st_f = 2;

        lab_run(&c);

        lab_cfg_std(&c, "gc-late", 1250000, 2);

        c.t0[0] = 10ULL * BILLION;
        c.dur   = 45ULL * BILLION;
        c.wu    = 40ULL * BILLION;
        c.sc_lo = 15ULL * BILLION;
        c.sc_hi = 40ULL * BILLION;

        lab_run(&c);

        lab_cfg_std(&c, "g2-stag", 1250000, 2);

        c.ia[1] = 0;
        c.t0[0] = 0;
        c.t0[1] = 5ULL * BILLION;
        c.dur   = 65ULL * BILLION;
        c.wu    = 35ULL * BILLION;

        lab_run(&c);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
}

#define CAP 1250000
int mb_ecn_lab_test(int     argc,
                    char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_mb_ecn_lab_shared(CAP, 5, false);
        ret |= test_mb_ecn_lab_shared(CAP, 8, false);
        ret |= test_mb_ecn_lab_shared(CAP, 8, true);
        ret |= test_mb_ecn_lab_shared_load(CAP, 5, false);
        ret |= test_mb_ecn_lab_shared_load(CAP, 8, false);
        ret |= test_mb_ecn_lab_shared_load(CAP, 5, true);
        ret |= test_mb_ecn_lab_shared_load(CAP, 8, true);
        ret |= test_mb_ecn_lab_fork(CAP, 5);
        ret |= test_mb_ecn_lab_gate_sweep(CAP, lab_ring(CAP, LEN), 64);
        ret |= test_mb_ecn_lab_gate_sweep(CAP, 90, 16);
        ret |= test_mb_ecn_lab_gate_converge(CAP, 16, 32.0);
        ret |= test_mb_ecn_lab_gate_converge(CAP, 32, 32.0);
        ret |= test_mb_ecn_lab_long_rtt(CAP, 300 * MS);
        ret |= test_mb_ecn_lab_long_rtt(CAP, 400 * MS);
        ret |= test_mb_ecn_lab_gate_skew(CAP, 16, 240);
        ret |= test_mb_ecn_lab_fixpoint_all();
        ret |= test_mb_ecn_lab_fixpoint_n8_all();
        ret |= test_mb_ecn_lab();

        return ret;
}
