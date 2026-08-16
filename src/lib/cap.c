/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Link capacity estimation
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

/*
 * Link-capacity estimation by watching the egress queue drain.
 *
 * A saturated link drains its queue at exactly its capacity, so we
 * estimate capacity by measuring the drain rate of the transmit
 * queue toward an n-1 flow (the flow to the layer below) while that
 * queue is backlogged.
 *
 * Sampling is lock-free and off the fast path: the queue depth is
 * read only at enqueue time, concurrently by many sender threads.
 * Each enqueue bumps relaxed counters (packets, bytes, empty-queue
 * hits). At most once per CAP_T_MIN, one thread wins a try-lock and
 * closes a measurement window.
 *
 * Over a window, byte conservation gives the bytes that drained:
 *   drained = queue at start (q0) + enqueued - queue now (q1)
 * A window stays open until CAP_N_MIN packets' worth has drained, so
 * its length self-scales with the link rate (~1 ms at 1 Gbit, ~19 ms
 * at 10 Mbit). CAP_T_MAX discards a window that spanned a traffic gap.
 *
 * Only a backlogged link measures its own capacity, so a window
 * whose ring ran mostly idle is discarded (a few empty samples, as
 * from a token-bucket shaper, are tolerated). The drain rate feeds a
 * max filter that jumps up at once but decays slowly, converging on
 * the capacity from below. A window that touched an empty ring at
 * either edge may have drained into downstream buffers faster than
 * the wire, so it may only lower the estimate, never raise it.
 */

#if defined(__linux__) || defined(__CYGWIN__)
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#else
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "config.h"

#include <ouroboros/atomics.h>
#include <ouroboros/time.h>

#include "cap.h"

#include <string.h>

#define CAP_T_MIN    (BILLION / 1000)     /* min close spacing ~1 ms  */
#define CAP_T_MAX    (1ULL << 27)         /* voiding traffic gap ~134 ms */
#define CAP_N_MIN    16                   /* drained packets to close */
#define CAP_DEC_SHFT 4                    /* max-filter decay 1/16    */
#define CAP_IDL_SHFT 3                    /* idle tolerance 1/8       */

/* Busy-flag try-lock: test-and-set acquire, store release.           */
#define CAP_TAS(p) __atomic_exchange_n(p, 1, __ATOMIC_ACQUIRE)
#define CAP_REL(p) (__atomic_store_n(p, 0, __ATOMIC_RELEASE))

void cap_clear(struct cap_est * e)
{
        memset(e, 0, sizeof(*e));
}

uint64_t cap_rate(const struct cap_est * e)
{
        return LOAD_RELAXED(&e->est);
}

/* Busy flag held; q1 is the caller's pre-write ring sample. */
static void cap_close(struct cap_est * e,
                      uint64_t         q1,
                      uint64_t         now,
                      uint64_t         gap)
{
        uint64_t pkt;              /* current c_pkt snapshot      */
        uint64_t byt;              /* current c_byt snapshot      */
        uint64_t idl;              /* current c_idl snapshot      */
        uint64_t dt;               /* window duration (ns)        */
        uint64_t enq;              /* packets enqueued in window  */
        uint64_t avg;              /* mean packet size (bytes)    */
        uint64_t r;                /* window drain rate (bytes/s) */
        int64_t  drained;          /* bytes drained over window   */

        pkt = LOAD_RELAXED(&e->c_pkt);
        byt = LOAD_RELAXED(&e->c_byt);
        idl = LOAD_RELAXED(&e->c_idl);

        dt  = now - e->t0;
        enq = pkt - e->pkt0;

        drained = (int64_t) (e->q0 + (byt - e->byt0) - q1);

        if (e->t0 == 0 || enq == 0)
                goto reopen;

        if (gap > CAP_T_MAX)
                goto reopen; /* traffic stopped: window void */

        avg = (byt - e->byt0) / enq;
        if (drained < (int64_t) (CAP_N_MIN * avg))
                return; /* extend the window until enough drains */

        if ((idl - e->idl0) << CAP_IDL_SHFT > enq)
                goto reopen; /* mostly idle ring: not saturated */

        r = (uint64_t) drained * MILLION / (dt / 1000);
        if (r >= e->rate) {
                if (e->q0 > 0 && q1 > 0) /* empty edge drains below */
                        e->rate = r;
        } else {
                e->rate -= (e->rate - r) >> CAP_DEC_SHFT;
        }

        STORE_RELAXED(&e->est, e->rate);
 reopen:
        e->t0   = now;
        e->q0   = q1;
        e->pkt0 = pkt;
        e->byt0 = byt;
        e->idl0 = idl;
}

void cap_update_at(struct cap_est * e,
                   size_t           qlen,
                   size_t           len,
                   uint64_t         now)
{
        uint64_t prev;

        FETCH_ADD_RELAXED(&e->c_pkt, 1);
        FETCH_ADD_RELAXED(&e->c_byt, len);

        if (qlen == 0)
                FETCH_ADD_RELAXED(&e->c_idl, 1);

        prev = LOAD_RELAXED(&e->t_last);
        if (prev > now)
                prev = now; /* a racing writer stamped ahead */

        STORE_RELAXED(&e->t_last, now);

        if (now - LOAD_RELAXED(&e->t_gate) < CAP_T_MIN)
                return;

        if (CAP_TAS(&e->busy) != 0)
                return;

        if (now - e->t_gate >= CAP_T_MIN) {
                cap_close(e, qlen, now, now - prev);
                STORE_RELAXED(&e->t_gate, now);
        }

        CAP_REL(&e->busy);
}

void cap_update(struct cap_est * e,
                size_t           qlen,
                size_t           len)
{
        struct timespec now;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        cap_update_at(e, qlen, len, TS_TO_UINT64(now));
}
