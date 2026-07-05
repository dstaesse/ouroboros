/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Unit tests for link capacity estimation
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

#include "cap.c"

#include <test/test.h>

#define TICK     (50 * 1000ULL) /* 50 us between packets     */
#define LEN      1000ULL        /* default packet size (B)   */
#define QLEN     8              /* steady ring backlog       */
#define RATE     (LEN * BILLION / TICK) /* LEN per TICK = 20 MB/s */

#define SHP_LEN  1250ULL        /* shaped-link packet (B)    */
#define SHP_STEP 20             /* packets per shaped window */
#define SHP_RATE (SHP_LEN * BILLION / (SHP_STEP * TICK))

static int test_cap_init_fini(void)
{
        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        if (cap_get(0) != 0 || cap_get(PROC_MAX_FLOWS - 1) != 0) {
                printf("Fresh estimator not unknown.\n");
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Exact roundtrip holds for codes >= 32 (rates >= 256 B/s). */
static int test_cap_codec_roundtrip(void)
{
        unsigned c;

        TEST_START();

        for (c = 32; c <= 255; c++) {
                if (cap_enc(cap_dec((uint8_t) c)) != c) {
                        printf("Code %u does not roundtrip.\n", c);
                        goto fail;
                }

                if (cap_dec((uint8_t) c) <= cap_dec((uint8_t) (c - 1))) {
                        printf("Decode not monotone at %u.\n", c);
                        goto fail;
                }
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_codec_bounds(void)
{
        TEST_START();

        if (cap_enc(0) != 0 || cap_dec(0) != 0) {
                printf("Zero is not unknown.\n");
                goto fail;
        }

        if (cap_enc(1) != 1) {
                printf("Rate 1 encoded as %u.\n", cap_enc(1));
                goto fail;
        }

        if (cap_enc(UINT64_MAX) != 255) {
                printf("Max rate encoded as %u.\n", cap_enc(UINT64_MAX));
                goto fail;
        }

        if (cap_dec(255) <= cap_dec(254)) {
                printf("Top code does not decode.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_min(void)
{
        TEST_START();

        if (cap_min(0, 42) != 42 || cap_min(42, 0) != 42) {
                printf("Unknown not skipped in min.\n");
                goto fail;
        }

        if (cap_min(0, 0) != 0) {
                printf("Two unknowns not unknown.\n");
                goto fail;
        }

        if (cap_min(97, 42) != 42 || cap_min(42, 97) != 42) {
                printf("Min not taken.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_stamp(void)
{
        uint8_t pci;

        TEST_START();

        pci = 42;
        cap_stamp(&pci, 0);
        if (pci != 42) {
                printf("Unknown own code overwrote the byte.\n");
                goto fail;
        }

        pci = 0;
        cap_stamp(&pci, 97);
        if (pci != 97) {
                printf("Own code not written into unknown.\n");
                goto fail;
        }

        pci = 97;
        cap_stamp(&pci, 42);
        if (pci != 42) {
                printf("Lower own code did not lower the byte.\n");
                goto fail;
        }

        pci = 42;
        cap_stamp(&pci, 97);
        if (pci != 42) {
                printf("Higher own code raised the byte.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_busy_window(void)
{
        size_t i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        /* 1000 B every 50 us, ring steady at 8: drain = 20 MB/s. */
        for (i = 1; i <= 40; i++)
                cap_update_at(0, QLEN, LEN, i * TICK);

        if (cap_get(0) != cap_enc(RATE)) {
                printf("Estimated code: exp %u, got %u.\n",
                       cap_enc(RATE), cap_get(0));
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_idle_tolerated(void)
{
        size_t i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        for (i = 1; i <= 40; i++)
                cap_update_at(0, i == 21 ? 0 : QLEN, LEN, i * TICK);

        if (cap_get(0) != cap_enc(RATE)) {
                printf("Grazed window: exp %u, got %u.\n",
                       cap_enc(RATE), cap_get(0));
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_mostly_idle_rejects(void)
{
        size_t i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        for (i = 1; i <= 100; i++)
                cap_update_at(0, 0, LEN, i * TICK);

        if (cap_get(0) != 0) {
                printf("Idle ring estimated %u.\n", cap_get(0));
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_slow_link_extends(void)
{
        size_t i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        /* 1000 B every 100 us: 10 slots/ms closes on a 2 ms window. */
        for (i = 1; i <= 30; i++)
                cap_update_at(0, QLEN, LEN, i * 2 * TICK);

        if (cap_get(0) != cap_enc(RATE / 2)) {
                printf("Slow link: exp %u, got %u.\n",
                       cap_enc(RATE / 2), cap_get(0));
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_shaped_link(void)
{
        size_t i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        /* 1250 B every ms; one empty observation per 20 packets. */
        for (i = 1; i <= 100; i++)
                cap_update_at(0, i % SHP_STEP == 0 ? 0 : 6, SHP_LEN,
                              i * SHP_STEP * TICK);

        if (cap_get(0) != cap_enc(SHP_RATE)) {
                printf("Shaped link: exp %u, got %u.\n",
                       cap_enc(SHP_RATE), cap_get(0));
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_stale_discard(void)
{
        uint64_t t;
        size_t   i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        /* Open a window, trickle 4 slots, then ~200 ms of silence. */
        for (i = 1; i <= 5; i++)
                cap_update_at(0, QLEN, LEN, i * CAP_T_MIN);

        t = 205 * CAP_T_MIN;

        cap_update_at(0, QLEN, LEN, t);

        if (cap_get(0) != 0) {
                printf("Gap window estimated %u.\n", cap_get(0));
                goto fail_init;
        }

        for (i = 1; i <= 40; i++)
                cap_update_at(0, QLEN, LEN, t + i * TICK);

        if (cap_get(0) != cap_enc(RATE)) {
                printf("Post-gap: exp %u, got %u.\n",
                       cap_enc(RATE), cap_get(0));
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_est_empty_start_no_raise(void)
{
        size_t i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        cap_update_at(0, 0, LEN, CAP_T_MIN);

        for (i = 1; i <= 40; i++)
                cap_update_at(0, QLEN, LEN, CAP_T_MIN + i * TICK);

        if (cap_get(0) != 0) {
                printf("Empty-start window raised to %u.\n",
                       cap_get(0));
                goto fail_init;
        }

        for (i = 41; i <= 60; i++)
                cap_update_at(0, QLEN, LEN, CAP_T_MIN + i * TICK);

        if (cap_get(0) != cap_enc(RATE)) {
                printf("Backlogged window: exp %u, got %u.\n",
                       cap_enc(RATE), cap_get(0));
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Max filter: fast attack on a high sample, slow release on lower. */
static int test_cap_est_max_filter(void)
{
        uint8_t high;
        size_t  i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        for (i = 1; i <= 40; i++)
                cap_update_at(0, QLEN, LEN, i * TICK);

        high = cap_get(0);
        if (high != cap_enc(RATE)) {
                printf("Attack missed: exp %u, got %u.\n", cap_enc(RATE),
                       high);
                goto fail_init;
        }

        /* Halved packet size: valid samples at 10 MB/s. */
        for (i = 41; i <= 80; i++)
                cap_update_at(0, QLEN, LEN / 2, i * TICK);

        if (cap_get(0) >= high) {
                printf("Release did not decay: %u.\n", cap_get(0));
                goto fail_init;
        }

        if (cap_get(0) <= cap_enc(RATE / 2)) {
                printf("Release collapsed to %u.\n", cap_get(0));
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* No fold within CAP_T_MIN of the previous one. */
static int test_cap_est_gate(void)
{
        size_t i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        cap_update_at(0, QLEN, LEN, CAP_T_MIN);

        for (i = 0; i < 5; i++)
                cap_update_at(0, QLEN, LEN, CAP_T_MIN + CAP_T_MIN / 2);

        if (cap.est[0].t_gate != CAP_T_MIN) {
                printf("Fold ran inside the gate.\n");
                goto fail_init;
        }

        if (LOAD_RELAXED(&cap.est[0].c_pkt) != 6) {
                printf("Gated packets not counted.\n");
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_reset(void)
{
        size_t i;

        TEST_START();

        if (cap_init() < 0) {
                printf("Failed to init cap.\n");
                goto fail;
        }

        for (i = 1; i <= 40; i++)
                cap_update_at(0, QLEN, LEN, i * TICK);

        if (cap_get(0) == 0) {
                printf("No estimate to reset.\n");
                goto fail_init;
        }

        cap_reset(0);

        if (cap_get(0) != 0) {
                printf("Reset did not clear the estimate.\n");
                goto fail_init;
        }

        cap_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        cap_fini();
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

        ret |= test_cap_init_fini();
        ret |= test_cap_codec_roundtrip();
        ret |= test_cap_codec_bounds();
        ret |= test_cap_min();
        ret |= test_cap_stamp();
        ret |= test_cap_est_busy_window();
        ret |= test_cap_est_idle_tolerated();
        ret |= test_cap_est_mostly_idle_rejects();
        ret |= test_cap_est_slow_link_extends();
        ret |= test_cap_est_shaped_link();
        ret |= test_cap_est_stale_discard();
        ret |= test_cap_est_empty_start_no_raise();
        ret |= test_cap_est_max_filter();
        ret |= test_cap_est_gate();
        ret |= test_cap_reset();

        return ret;
}
