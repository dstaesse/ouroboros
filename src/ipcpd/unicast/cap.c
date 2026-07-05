/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Link capacity estimation
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

#include <ouroboros/atomics.h>
#include <ouroboros/time.h>

#include "cap.h"

#include <string.h>

/*
 * Link-capacity estimation by watching the egress queue drain.
 *
 * A saturated link drains its queue at exactly its capacity, so we
 * estimate capacity by measuring the drain rate of the ring buffer
 * toward an n-1 flow (the flow to the layer below) while that ring
 * is backlogged.
 *
 * Sampling is lock-free and off the fast path: the ring depth is
 * read only at enqueue time, concurrently by many sender threads.
 * Each enqueue bumps relaxed counters (packets, bytes, empty-ring
 * hits). At most once per CAP_T_MIN, one thread wins a try-lock and
 * closes a measurement window.
 *
 * Over a window, packet conservation gives the slots that drained:
 *   drained = queue at start (q0) + enqueued - queue now (q1)
 * A window stays open until CAP_N_MIN slots have drained, so its
 * length self-scales with the link rate (~1 ms at 1 Gbit, ~19 ms at
 * 10 Mbit). CAP_T_MAX discards a window that spanned a traffic gap.
 *
 * Only a backlogged link measures its own capacity, so a window
 * whose ring ran mostly idle is discarded (a few empty samples, as
 * from a token-bucket shaper, are tolerated). The drain rate feeds a
 * max filter that jumps up at once but decays slowly, converging on
 * the capacity from below. A window that touched an empty ring at
 * either edge may have drained into downstream buffers faster than
 * the wire, so it may only lower the estimate, never raise it.
 *
 * The estimate is published as a quarter-log2 code: capacity is only
 * ever needed to order-of-magnitude accuracy.
 */

#define CAP_T_MIN    (BILLION / 1000)     /* min fold spacing ~1 ms   */
#define CAP_T_MAX    (1ULL << 27)         /* stale window cap ~134 ms */
#define CAP_N_MIN    16                   /* drained slots to close   */
#define CAP_DEC_SHFT 4                    /* max-filter decay 1/16    */
#define CAP_IDL_SHFT 3                    /* idle tolerance 1/8       */

/* Try-lock on the busy flag: test-and-set acquire, store release.    */
#define CAP_TRY(p) (__atomic_exchange_n(p, 1, __ATOMIC_ACQUIRE) == 0)
#define CAP_REL(p) (__atomic_store_n(p, 0, __ATOMIC_RELEASE))

struct cap_est {
        uint64_t c_pkt;  /* total packets enqueued (relaxed)  */
        uint64_t c_byt;  /* total bytes enqueued (relaxed)    */
        uint64_t c_idl;  /* times ring seen empty (relaxed)   */

        uint64_t t_gate; /* last fold timestamp (ns)          */
        uint8_t  busy;   /* fold in progress (try-lock)       */

        uint64_t t0;     /* window start (ns), 0 = no window  */
        uint64_t q0;     /* ring occupancy at window start    */
        uint64_t pkt0;   /* c_pkt snapshot at window start    */
        uint64_t byt0;   /* c_byt snapshot at window start    */
        uint64_t idl0;   /* c_idl snapshot at window start    */
        uint64_t rate;   /* filtered drain rate (bytes/s)     */

        uint8_t  cap;    /* published capacity code (0=none)  */
};

struct {
        struct cap_est est[PROC_MAX_FLOWS];
} cap;

int cap_init(void)
{
        memset(&cap, 0, sizeof(cap));

        return 0;
}

void cap_fini(void)
{
}

void cap_reset(int fd)
{
        /* A racing update seeds one bogus window; the filter absorbs. */
        memset(&cap.est[fd], 0, sizeof(cap.est[fd]));
}

/*
 * Rate <-> 8-bit code (cap_enc / cap_dec). The code is a tiny float:
 * the high 6 bits are a band e = floor(log2 rate), the low 2 bits a
 * quarter k that splits each band [2^e, 2^(e+1)) into four, so
 * code = 4 * e + k. Each step is ~19% in rate; that coarseness is
 * deliberate, capacity only needs order-of-magnitude accuracy.
 *
 * The quarter cut points are 256 * 2^(k/4) rounded to an integer:
 * {256, 304, 362, 431} over the normalized range [256, 512).
 */
uint8_t cap_enc(uint64_t rate)
{
        static const uint16_t thr[3] = {304, 362, 431};
        uint64_t r = rate;         /* copy halved to find band  */
        unsigned e = 0;            /* band: floor log2 rate     */
        unsigned k = 0;            /* quarter within band 0..3  */
        unsigned c;                /* code = 4 * band + quarter */
        uint16_t top;              /* rate scaled to [256, 512) */

        if (rate == 0)
                return 0;

        while (r > 1) {
                r >>= 1;
                e++;
        }

        /* Top 9 bits: rate normalized to [256, 512). */
        top = e >= 8 ? (uint16_t) (rate >> (e - 8))
                     : (uint16_t) (rate << (8 - e));

        while (k < 3 && top >= thr[k])
                k++;

        c = 4 * e + k;
        if (c == 0)
                c = 1; /* 0 means unknown */

        return (uint8_t) c;
}

uint64_t cap_dec(uint8_t c)
{
        static const uint16_t m[4] = {256, 304, 362, 431};
        unsigned e = c >> 2;       /* band = c >> 2   */
        unsigned k = c & 3;        /* quarter = c & 3 */

        if (c == 0)
                return 0;

        if (e >= 8)
                return (uint64_t) m[k] << (e - 8);

        return ((uint64_t) m[k] << e) >> 8;
}

uint8_t cap_min(uint8_t a,
                uint8_t b)
{
        if (a == 0)
                return b;

        if (b == 0)
                return a;

        return a < b ? a : b;
}

void cap_stamp(uint8_t * pci,
               uint8_t   own)
{
        if (own == 0)
                return;

        if (*pci == 0 || own < *pci)
                *pci = own;
}

/* Fold flag held; q1 is the caller's pre-write ring sample. */
static void cap_fold(struct cap_est * e,
                     uint64_t         q1,
                     uint64_t         now)
{
        uint64_t pkt;              /* current c_pkt snapshot      */
        uint64_t byt;              /* current c_byt snapshot      */
        uint64_t idl;              /* current c_idl snapshot      */
        uint64_t dt;               /* window duration (ns)        */
        uint64_t enq;              /* packets enqueued in window  */
        uint64_t avg;              /* mean packet size (bytes)    */
        uint64_t r;                /* window drain rate (bytes/s) */
        int64_t  drained;          /* slots drained over window   */

        pkt = LOAD_RELAXED(&e->c_pkt);
        byt = LOAD_RELAXED(&e->c_byt);
        idl = LOAD_RELAXED(&e->c_idl);

        dt  = now - e->t0;
        enq = pkt - e->pkt0;

        drained = (int64_t) (e->q0 + enq - q1);

        if (e->t0 == 0 || dt > CAP_T_MAX || enq == 0)
                goto reopen;

        if (drained < (int64_t) CAP_N_MIN)
                return; /* extend the window until enough drains */

        if ((idl - e->idl0) << CAP_IDL_SHFT > enq)
                goto reopen; /* mostly idle ring: not saturated */

        avg = (byt - e->byt0) / enq;
        r   = (uint64_t) drained * avg * MILLION / (dt / 1000);

        if (r >= e->rate) {
                /* Empty-edged windows drain into buffers below. */
                if (e->q0 > 0 && q1 > 0)
                        e->rate = r;
        } else {
                e->rate -= (e->rate - r) >> CAP_DEC_SHFT;
        }

        STORE_RELAXED(&e->cap, cap_enc(e->rate));
 reopen:
        e->t0   = now;
        e->q0   = q1;
        e->pkt0 = pkt;
        e->byt0 = byt;
        e->idl0 = idl;
}

/* Internal, timestamped entry point; tests drive this directly. */
static void cap_update_at(int      fd,
                          size_t   qlen,
                          size_t   len,
                          uint64_t now)
{
        struct cap_est * e = &cap.est[fd]; /* this flow's estimator */

        FETCH_ADD_RELAXED(&e->c_pkt, 1);
        FETCH_ADD_RELAXED(&e->c_byt, len);

        if (qlen == 0)
                FETCH_ADD_RELAXED(&e->c_idl, 1);

        if (now - LOAD_RELAXED(&e->t_gate) < CAP_T_MIN)
                return;

        if (!CAP_TRY(&e->busy))
                return;

        if (now - e->t_gate >= CAP_T_MIN) {
                cap_fold(e, qlen, now);
                STORE_RELAXED(&e->t_gate, now);
        }

        CAP_REL(&e->busy);
}

void cap_update(int    fd,
                size_t qlen,
                size_t len)
{
        struct timespec now;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        cap_update_at(fd, qlen, len, TS_TO_UINT64(now));
}

uint8_t cap_get(int fd)
{
        return LOAD_RELAXED(&cap.est[fd].cap);
}
