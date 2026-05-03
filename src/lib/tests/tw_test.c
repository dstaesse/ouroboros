/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Generic timing-wheel tests
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

#include <test/test.h>

#include <ouroboros/time.h>
#include <ouroboros/tw.h>

#include <stdint.h>
#include <stdio.h>
#include <time.h>

struct payload {
        struct tw_entry tw;
        int             fired;
};

struct cancel_payload {
        struct tw_entry   tw;
        int               fired;
        struct tw_entry * sibling;
};

struct repost_payload {
        struct tw_entry   tw;
        int               fired;
        struct payload *  sibling;
        uint64_t          repost_at;
};

static void cb_count(void * arg)
{
        struct payload * p = arg;
        p->fired++;
}

static void cb_cancel_sibling(void * arg)
{
        struct cancel_payload * p = arg;
        p->fired++;
        tw_cancel(p->sibling);
}

static void cb_repost_sibling(void * arg)
{
        struct repost_payload * p = arg;
        p->fired++;
        tw_post(&p->sibling->tw, p->repost_at, cb_count, p->sibling);
}

static uint64_t now_ns(void)
{
        struct timespec ts;
        clock_gettime(PTHREAD_COND_CLOCK, &ts);
        return TS_TO_UINT64(ts);
}

static void sleep_ns(uint64_t ns)
{
        struct timespec ts;
        UINT64_TO_TS(ns, &ts);
        nanosleep(&ts, NULL);
}

static int test_tw_init_fini(void)
{
        TEST_START();

        if (tw_init() < 0) {
                printf("tw_init failed.\n");
                goto fail;
        }

        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tw_post_fires_after_deadline(void)
{
        struct payload p;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&p.tw);
        p.fired = 0;

        tw_post(&p.tw, now_ns() + 5 * MILLION, cb_count, &p);

        sleep_ns(20 * MILLION);
        tw_move();

        if (p.fired != 1) {
                printf("expected 1 fire, got %d\n", p.fired);
                goto fail_post;
        }

        tw_cancel(&p.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&p.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tw_no_fire_before_deadline(void)
{
        struct payload p;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&p.tw);
        p.fired = 0;

        tw_post(&p.tw, now_ns() + 100 * MILLION, cb_count, &p);

        sleep_ns(2 * MILLION);
        tw_move();

        if (p.fired != 0) {
                printf("expected 0 fires, got %d\n", p.fired);
                goto fail_post;
        }

        tw_cancel(&p.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&p.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tw_cancel_prevents_fire(void)
{
        struct payload p;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&p.tw);
        p.fired = 0;

        tw_post(&p.tw, now_ns() + 5 * MILLION, cb_count, &p);
        tw_cancel(&p.tw);

        sleep_ns(20 * MILLION);
        tw_move();

        if (p.fired != 0) {
                printf("cancelled entry fired %d times\n", p.fired);
                goto fail_init;
        }

        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tw_cancel_unposted_is_noop(void)
{
        struct tw_entry e;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&e);
        tw_cancel(&e);
        tw_cancel(&e);

        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tw_fire_only_once(void)
{
        struct payload p;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&p.tw);
        p.fired = 0;

        tw_post(&p.tw, now_ns() + 3 * MILLION, cb_count, &p);

        sleep_ns(20 * MILLION);
        tw_move();
        tw_move();
        tw_move();

        if (p.fired != 1) {
                printf("expected 1 fire, got %d after 3 moves\n", p.fired);
                goto fail_post;
        }

        tw_cancel(&p.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&p.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Multi-level: post a level-1 (>= 256ms) deadline; should still fire. */
static int test_tw_post_level1_fires(void)
{
        struct payload p;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&p.tw);
        p.fired = 0;

        tw_post(&p.tw, now_ns() + 300 * MILLION, cb_count, &p);

        if (p.tw.lvl != 1) {
                printf("expected level 1 placement, got %zu\n", p.tw.lvl);
                goto fail_post;
        }

        sleep_ns(320 * MILLION);
        tw_move();

        if (p.fired != 1) {
                printf("level-1 entry didn't fire (got %d)\n", p.fired);
                goto fail_post;
        }

        tw_cancel(&p.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&p.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tw_many_entries_all_fire(void)
{
        struct payload pl[16];
        size_t         i;
        size_t         total = 0;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        for (i = 0; i < 16; ++i) {
                tw_init_entry(&pl[i].tw);
                pl[i].fired = 0;
                tw_post(&pl[i].tw, now_ns() + (1 + i) * MILLION,
                        cb_count, &pl[i]);
        }

        sleep_ns(40 * MILLION);
        tw_move();

        for (i = 0; i < 16; ++i)
                total += pl[i].fired;

        if (total != 16) {
                printf("expected 16 fires, got %zu\n", total);
                goto fail_post;
        }

        for (i = 0; i < 16; ++i)
                tw_cancel(&pl[i].tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        for (i = 0; i < 16; ++i)
                tw_cancel(&pl[i].tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* tw_next_expiry signals empty wheel via tv_nsec == -1. */
static int test_tw_next_expiry_empty(void)
{
        struct timespec out;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_next_expiry(&out);
        if (out.tv_nsec != -1) {
                printf("expected tv_nsec=-1, got %ld\n", (long) out.tv_nsec);
                goto fail_init;
        }

        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* tw_next_expiry returns a deadline within the right ballpark. */
static int test_tw_next_expiry_returns_deadline(void)
{
        struct payload  p;
        struct timespec out;
        uint64_t        target;
        uint64_t        out_ns;
        int64_t         skew;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&p.tw);
        p.fired = 0;

        target = now_ns() + 50 * MILLION;
        tw_post(&p.tw, target, cb_count, &p);

        tw_next_expiry(&out);
        out_ns = TS_TO_UINT64(out);

        /* Level-0 quantization gives ±1 slot of skew. */
        skew = (int64_t)(out_ns) - (int64_t)(target);
        if (skew < -2 * MILLION || skew > 4 * MILLION) {
                printf("deadline not in -2..+4 ms, skew=%ld ns\n", (long) skew);
                goto fail_post;
        }

        tw_cancel(&p.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&p.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Repost: fire, then post again. */
static int test_tw_repost_after_fire(void)
{
        struct payload p;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&p.tw);
        p.fired = 0;

        tw_post(&p.tw, now_ns() + 3 * MILLION, cb_count, &p);
        sleep_ns(20 * MILLION);
        tw_move();
        if (p.fired != 1) {
                printf("first fire missed\n");
                goto fail_post;
        }

        tw_post(&p.tw, now_ns() + 3 * MILLION, cb_count, &p);
        sleep_ns(20 * MILLION);
        tw_move();
        if (p.fired != 2) {
                printf("second fire missed (fired=%d)\n", p.fired);
                goto fail_post;
        }

        tw_cancel(&p.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&p.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Double-post replaces the schedule; only the second fires. */
static int test_tw_double_post_replaces(void)
{
        struct payload p;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&p.tw);
        p.fired = 0;

        tw_post(&p.tw, now_ns() + 30 * MILLION, cb_count, &p);
        tw_post(&p.tw, now_ns() + 3 * MILLION, cb_count, &p);

        sleep_ns(20 * MILLION);
        tw_move();

        if (p.fired != 1) {
                printf("expected 1 fire after replace, got %d\n", p.fired);
                goto fail_post;
        }

        sleep_ns(40 * MILLION);
        tw_move();

        if (p.fired != 1) {
                printf("first schedule fired after replace (got %d)\n",
                       p.fired);
                goto fail_post;
        }

        tw_cancel(&p.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&p.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Fire callback may safely cancel a sibling in the same slot. */
static int test_tw_fire_cancels_sibling(void)
{
        struct cancel_payload a;
        struct payload        b;
        uint64_t              deadline;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&a.tw);
        tw_init_entry(&b.tw);
        a.fired   = 0;
        a.sibling = &b.tw;
        b.fired   = 0;

        deadline = now_ns() + 3 * MILLION;
        tw_post(&a.tw, deadline, cb_cancel_sibling, &a);
        tw_post(&b.tw, deadline, cb_count, &b);

        sleep_ns(20 * MILLION);
        tw_move();

        if (a.fired != 1) {
                printf("a expected 1 fire, got %d\n", a.fired);
                goto fail_post;
        }
        if (b.fired != 0) {
                printf("b should not have fired (got %d)\n", b.fired);
                goto fail_post;
        }

        tw_cancel(&a.tw);
        tw_cancel(&b.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&a.tw);
        tw_cancel(&b.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Fire callback may safely repost a sibling to a future slot. */
static int test_tw_fire_posts_sibling(void)
{
        struct repost_payload a;
        struct payload        b;
        uint64_t              deadline;

        TEST_START();

        if (tw_init() < 0)
                goto fail;

        tw_init_entry(&a.tw);
        tw_init_entry(&b.tw);
        a.fired     = 0;
        a.sibling   = &b;
        a.repost_at = now_ns() + 30 * MILLION;
        b.fired     = 0;

        deadline = now_ns() + 3 * MILLION;
        tw_post(&a.tw, deadline, cb_repost_sibling, &a);
        tw_post(&b.tw, deadline, cb_count, &b);

        sleep_ns(20 * MILLION);
        tw_move();

        if (a.fired != 1) {
                printf("a expected 1 fire, got %d\n", a.fired);
                goto fail_post;
        }
        if (b.fired != 0) {
                printf("b fired before reposted deadline (got %d)\n",
                       b.fired);
                goto fail_post;
        }

        sleep_ns(25 * MILLION);
        tw_move();

        if (b.fired != 1) {
                printf("b expected 1 fire after repost, got %d\n",
                       b.fired);
                goto fail_post;
        }

        tw_cancel(&a.tw);
        tw_cancel(&b.tw);
        tw_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_post:
        tw_cancel(&a.tw);
        tw_cancel(&b.tw);
        tw_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int tw_test(int     argc,
            char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_tw_init_fini();
        ret |= test_tw_post_fires_after_deadline();
        ret |= test_tw_no_fire_before_deadline();
        ret |= test_tw_cancel_prevents_fire();
        ret |= test_tw_cancel_unposted_is_noop();
        ret |= test_tw_fire_only_once();
        ret |= test_tw_post_level1_fires();
        ret |= test_tw_many_entries_all_fire();
        ret |= test_tw_next_expiry_empty();
        ret |= test_tw_next_expiry_returns_deadline();
        ret |= test_tw_repost_after_fire();
        ret |= test_tw_double_post_replaces();
        ret |= test_tw_fire_cancels_sibling();
        ret |= test_tw_fire_posts_sibling();

        return ret;
}
