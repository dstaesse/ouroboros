/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Unit tests for link capacity estimation
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

#include "../cap.c"

#include <test/test.h>

#include <inttypes.h>
#include <stdbool.h>

#define TICK     (50 * 1000ULL) /* 50 us between packets     */
#define LEN      1000ULL        /* default packet size (B)   */
#define QLEN     (8 * LEN)      /* steady backlog (bytes)    */
#define RATE     (LEN * BILLION / TICK) /* LEN per TICK = 20 MB/s */

#define SHP_LEN  1250ULL        /* shaped-link packet (B)    */
#define SHP_STEP 20             /* packets per shaped window */
#define SHP_RATE (SHP_LEN * BILLION / (SHP_STEP * TICK))

/* Draining CAP_N_MIN of these outlasts CAP_T_MAX without a gap. */
#define LOW_STEP (250 * TICK)   /* 12.5 ms between packets   */
#define LOW_RATE (LEN * BILLION / LOW_STEP)

/* Within the quarter-log2 band the wire code publishes. */
static bool rate_is_near(uint64_t got,
                         uint64_t exp)
{
        return got >= exp - exp / 8 && got <= exp + exp / 8;
}

static int test_cap_est_clear(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        if (cap_rate(&e) != 0) {
                printf("Fresh estimator not unknown.\n");
                goto fail;
        }

        for (i = 1; i <= 40; i++)
                cap_update_at(&e, QLEN, LEN, i * TICK);

        if (cap_rate(&e) == 0) {
                printf("No estimate to clear.\n");
                goto fail;
        }

        cap_clear(&e);

        if (cap_rate(&e) != 0) {
                printf("Clear did not drop the estimate.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* 1000 B every 50 us, ring steady at 8: drain = 20 MB/s. */
static int test_cap_est_busy_window(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        for (i = 1; i <= 40; i++)
                cap_update_at(&e, QLEN, LEN, i * TICK);

        if (!rate_is_near(cap_rate(&e), RATE)) {
                printf("Estimated rate: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) RATE, cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_idle_tolerated(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        for (i = 1; i <= 40; i++)
                cap_update_at(&e, i == 21 ? 0 : QLEN, LEN, i * TICK);

        if (!rate_is_near(cap_rate(&e), RATE)) {
                printf("Grazed window: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) RATE, cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_mostly_idle_rejects(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        for (i = 1; i <= 100; i++)
                cap_update_at(&e, 0, LEN, i * TICK);

        if (cap_rate(&e) != 0) {
                printf("Idle ring estimated %" PRIu64 ".\n", cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* 1000 B every 100 us: 10 slots/ms closes on a 2 ms window. */
static int test_cap_est_slow_link_extends(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        for (i = 1; i <= 30; i++)
                cap_update_at(&e, QLEN, LEN, i * 2 * TICK);

        if (!rate_is_near(cap_rate(&e), RATE / 2)) {
                printf("Slow link: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) (RATE / 2), cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* 1250 B every ms; one empty observation per 20 packets. */
static int test_cap_est_shaped_link(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        for (i = 1; i <= 100; i++)
                cap_update_at(&e, i % SHP_STEP == 0 ? 0 : 6 * SHP_LEN,
                                  SHP_LEN, i * SHP_STEP * TICK);

        if (!rate_is_near(cap_rate(&e), SHP_RATE)) {
                printf("Shaped link: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) SHP_RATE, cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Open a window, trickle 4 slots, then ~200 ms of silence. */
static int test_cap_est_stale_discard(void)
{
        struct cap_est e;
        uint64_t       t;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        for (i = 1; i <= 5; i++)
                cap_update_at(&e, QLEN, LEN, i * CAP_T_MIN);

        t = 205 * CAP_T_MIN;

        cap_update_at(&e, QLEN, LEN, t);

        if (cap_rate(&e) != 0) {
                printf("Gap window estimated %" PRIu64 ".\n", cap_rate(&e));
                goto fail;
        }

        for (i = 1; i <= 40; i++)
                cap_update_at(&e, QLEN, LEN, t + i * TICK);

        if (!rate_is_near(cap_rate(&e), RATE)) {
                printf("Post-gap: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) RATE, cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_empty_start_no_raise(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        cap_update_at(&e, 0, LEN, CAP_T_MIN);

        for (i = 1; i <= 40; i++)
                cap_update_at(&e, QLEN, LEN, CAP_T_MIN + i * TICK);

        if (cap_rate(&e) != 0) {
                printf("Empty-start window raised to %" PRIu64 ".\n",
                       cap_rate(&e));
                goto fail;
        }

        for (i = 41; i <= 60; i++)
                cap_update_at(&e, QLEN, LEN, CAP_T_MIN + i * TICK);

        if (!rate_is_near(cap_rate(&e), RATE)) {
                printf("Backlogged window: exp %" PRIu64 ", got %" PRIu64
                       ".\n", (uint64_t) RATE, cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * Max filter: fast attack on a high sample, slow release on the
 * lower samples from a halved packet size (10 MB/s).
 */
static int test_cap_est_max_filter(void)
{
        struct cap_est e;
        uint64_t       high;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        for (i = 1; i <= 40; i++)
                cap_update_at(&e, QLEN, LEN, i * TICK);

        high = cap_rate(&e);
        if (!rate_is_near(high, RATE)) {
                printf("Attack missed: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) RATE, high);
                goto fail;
        }

        for (i = 41; i <= 80; i++)
                cap_update_at(&e, QLEN, LEN / 2, i * TICK);

        if (cap_rate(&e) >= high) {
                printf("Release did not decay: %" PRIu64 ".\n", cap_rate(&e));
                goto fail;
        }

        if (cap_rate(&e) <= RATE / 2) {
                printf("Release collapsed to %" PRIu64 ".\n", cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* No window close within CAP_T_MIN of the last one. */
static int test_cap_est_gate(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        cap_update_at(&e, QLEN, LEN, CAP_T_MIN);

        for (i = 0; i < 5; i++)
                cap_update_at(&e, QLEN, LEN, CAP_T_MIN + CAP_T_MIN / 2);

        if (e.t_gate != CAP_T_MIN) {
                printf("Window closed inside the gate.\n");
                goto fail;
        }

        if (LOAD_RELAXED(&e.c_pkt) != 6) {
                printf("Gated packets not counted.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * A link slow enough that CAP_N_MIN packets take longer than
 * CAP_T_MAX to drain still publishes, as long as the sender keeps
 * offering: only silence voids a window.
 */
static int test_cap_est_low_rate_publishes(void)
{
        struct cap_est e;
        size_t         i;

        TEST_START();

        cap_clear(&e);

        for (i = 1; i <= 20; i++)
                cap_update_at(&e, QLEN, LEN, i * LOW_STEP);

        if (!rate_is_near(cap_rate(&e), LOW_RATE)) {
                printf("Low rate: exp %" PRIu64 ", got %" PRIu64 ".\n",
                       (uint64_t) LOW_RATE, cap_rate(&e));
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int cap_test(int     argc,
             char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_cap_est_clear();
        ret |= test_cap_est_busy_window();
        ret |= test_cap_est_idle_tolerated();
        ret |= test_cap_est_mostly_idle_rejects();
        ret |= test_cap_est_slow_link_extends();
        ret |= test_cap_est_shaped_link();
        ret |= test_cap_est_stale_discard();
        ret |= test_cap_est_empty_start_no_raise();
        ret |= test_cap_est_max_filter();
        ret |= test_cap_est_gate();
        ret |= test_cap_est_low_rate_publishes();

        return ret;
}
