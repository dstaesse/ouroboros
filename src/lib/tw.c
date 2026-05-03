/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Generic deadline-ordered callback queue (timing wheel)
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include <ouroboros/list.h>
#include <ouroboros/pthread.h>
#include <ouroboros/time.h>
#include <ouroboros/tw.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

/* 3 levels × 256 slots, 1 ms / 16 ms / 256 ms per-slot resolution. */
#define TW_LVLS  3
#define TW_SLOTS 256
#define TW_BUMP  4
#define TW_RES   20  /* 2^20 ns ≈ 1 ms per slot at level 0. */

#define TW_SLOT(x) ((x) & (TW_SLOTS - 1))

static struct {
        struct list_head levels[TW_LVLS][TW_SLOTS];
        size_t           prv[TW_LVLS];
        pthread_mutex_t  mtx;
        pthread_mutex_t  move_mtx;
        bool             initialised;
} tw;

static size_t tw_lvl_res(size_t lvl)
{
        return TW_RES + TW_BUMP * lvl;
}

/* Smallest level whose slot range covers the deadline. */
static size_t tw_pick_lvl(uint64_t now_ns,
                          uint64_t deadline_ns)
{
        uint64_t delta;
        size_t   lvl;

        delta = deadline_ns > now_ns ? deadline_ns - now_ns : 0;
        lvl = 0;

        while (lvl < TW_LVLS - 1 && (delta >> tw_lvl_res(lvl)) >= TW_SLOTS)
                ++lvl;

        return lvl;
}

static size_t tw_slot(uint64_t ns,
                      size_t   lvl)
{
        return TW_SLOT(ns >> tw_lvl_res(lvl));
}

int tw_init(void)
{
        struct timespec now;
        size_t          i;
        size_t          j;

        assert(!tw.initialised);

        if (pthread_mutex_init(&tw.mtx, NULL))
                goto fail_mtx;

        if (pthread_mutex_init(&tw.move_mtx, NULL))
                goto fail_move_mtx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        for (i = 0; i < TW_LVLS; ++i) {
                tw.prv[i] = TW_SLOT(tw_slot(TS_TO_UINT64(now), i) - 1);
                for (j = 0; j < TW_SLOTS; ++j)
                        list_head_init(&tw.levels[i][j]);
        }

        tw.initialised = true;

        return 0;

 fail_move_mtx:
        pthread_mutex_destroy(&tw.mtx);
 fail_mtx:
        return -1;
}

void tw_fini(void)
{
        size_t i;
        size_t j;

        assert(tw.initialised);

        for (i = 0; i < TW_LVLS; ++i) {
                for (j = 0; j < TW_SLOTS; ++j)
                        assert(list_is_empty(&tw.levels[i][j]));
        }

        pthread_mutex_destroy(&tw.move_mtx);
        pthread_mutex_destroy(&tw.mtx);

        tw.initialised = false;
}

void tw_init_entry(struct tw_entry * e)
{
        list_head_init(&e->next);

        e->deadline_ns = 0;
        e->fire        = NULL;
        e->arg         = NULL;
        e->lvl         = 0;
}

void tw_post(struct tw_entry * e,
             uint64_t          deadline_ns,
             tw_fire_fn_t      fire,
             void *            arg)
{
        struct timespec now;
        size_t          lvl;
        size_t          slot;

        assert(tw.initialised);

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        lvl  = tw_pick_lvl(TS_TO_UINT64(now), deadline_ns);
        /* +1 so deadline <= slot_start; lands later in slot. */
        slot = TW_SLOT(tw_slot(deadline_ns, lvl) + 1);

        e->deadline_ns = deadline_ns;
        e->fire        = fire;
        e->arg         = arg;
        e->lvl         = lvl;

        pthread_mutex_lock(&tw.mtx);

        if (!list_is_empty(&e->next))
                list_del(&e->next);

        list_add_tail(&e->next, &tw.levels[lvl][slot]);

        pthread_mutex_unlock(&tw.mtx);
}

void tw_cancel(struct tw_entry * e)
{
        if (e == NULL)
                return;

        assert(tw.initialised);

        pthread_mutex_lock(&tw.mtx);

        if (!list_is_empty(&e->next)) {
                list_del(&e->next);
                list_head_init(&e->next);
        }

        pthread_mutex_unlock(&tw.mtx);
}

void tw_move(void)
{
        struct timespec    now;
        struct list_head   deferred;
        struct list_head * p;
        uint64_t           now_ns;
        size_t             i;
        size_t             j;
        size_t             cur;

        assert(tw.initialised);

        if (pthread_mutex_trylock(&tw.move_mtx) != 0)
                return;

        pthread_cleanup_push(__cleanup_mutex_unlock, &tw.move_mtx);

        pthread_mutex_lock(&tw.mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, &tw.mtx);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        for (i = 0; i < TW_LVLS; ++i) {
                cur = tw_slot(now_ns, i);

                j = tw.prv[i];
                if (cur < j)
                        cur += TW_SLOTS;

                while (j++ < cur) {
                        size_t s = TW_SLOT(j);

                        /* Pop-front so fire may mutate any entry. */
                        list_head_init(&deferred);

                        while (!list_is_empty(&tw.levels[i][s])) {
                                struct tw_entry * e;
                                p = tw.levels[i][s].nxt;
                                e = list_entry(p, struct tw_entry, next);
                                list_del(&e->next);

                                if (e->deadline_ns > now_ns) {
                                        list_add_tail(&e->next, &deferred);
                                        continue;
                                }

                                pthread_mutex_unlock(&tw.mtx);
                                e->fire(e->arg);
                                pthread_mutex_lock(&tw.mtx);
                        }

                        while (!list_is_empty(&deferred)) {
                                p = deferred.nxt;
                                list_del(p);
                                list_add_tail(p, &tw.levels[i][s]);
                        }
                }

                tw.prv[i] = TW_SLOT(cur);
        }

        pthread_cleanup_pop(true); /* tw.mtx */
        pthread_cleanup_pop(true); /* tw.move_mtx */
}

/* Earliest pending deadline at level lvl, INT64_MAX if level is empty. */
static int64_t tw_lvl_earliest(size_t   lvl,
                               uint64_t now_ns)
{
        size_t cur = tw_slot(now_ns, lvl);
        size_t j;

        for (j = 1; j <= TW_SLOTS; ++j) {
                size_t s = TW_SLOT(cur + j);

                if (list_is_empty(&tw.levels[lvl][s]))
                        continue;

                return (int64_t)(now_ns + ((uint64_t) j << tw_lvl_res(lvl)));
        }

        return INT64_MAX;
}

void tw_next_expiry(struct timespec * out)
{
        struct timespec now;
        uint64_t        now_ns;
        int64_t         earliest = INT64_MAX;
        size_t          i;

        assert(tw.initialised);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        pthread_mutex_lock(&tw.mtx);

        for (i = 0; i < TW_LVLS; ++i) {
                int64_t dl = tw_lvl_earliest(i, now_ns);
                if (dl < earliest)
                        earliest = dl;
        }

        pthread_mutex_unlock(&tw.mtx);

        if (earliest == INT64_MAX) {
                /* Empty wheel: tv_nsec=-1 is an invalid normalised value. */
                out->tv_sec  = 0;
                out->tv_nsec = -1;
        } else {
                UINT64_TO_TS((uint64_t) earliest, out);
        }
}
