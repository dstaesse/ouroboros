/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the time utilities
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

#define _POSIX_C_SOURCE 200809L

#include <test/test.h>
#include <ouroboros/time.h>

#include <stdio.h>

static int ts_check(struct timespec * s,
                    time_t            sec,
                    time_t            nsec)
{
        return s->tv_sec == sec && s->tv_nsec == nsec;
}

static int tv_check(struct timeval * v,
                    time_t           sec,
                    time_t           usec)
{
        return v->tv_sec == sec && v->tv_usec == usec;
}


static int test_time_ts_init(void)
{
        struct timespec s  = TIMESPEC_INIT_S (100);
        struct timespec ms = TIMESPEC_INIT_MS(100);
        struct timespec us = TIMESPEC_INIT_US(100);
        struct timespec ns = TIMESPEC_INIT_NS(100);

        TEST_START();

        if (!ts_check(&s, 100, 0)) {
                printf("timespec_init_s failed.\n");
                goto fail;
        }

        if (!ts_check(&ms, 0, 100 * MILLION)) {
                printf("timespec_init_ms failed.\n");
                goto fail;
        }

        if (!ts_check(&us, 0, 100* 1000L)) {
                printf("timespec_init_us failed.\n");
                goto fail;
        }

        if (!ts_check(&ns, 0, 100)) {
                printf("timespec_init_ns failed.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_time_tv_init(void)
{
        struct timeval s  = TIMEVAL_INIT_S (100);
        struct timeval ms = TIMEVAL_INIT_MS(100);
        struct timeval us = TIMEVAL_INIT_US(100);

        TEST_START();

        if (!tv_check(&s, 100, 0)) {
                printf("timeval_init_s failed.\n");
                goto fail;
        }

        if (!tv_check(&ms, 0, 100 * 1000L)) {
                printf("timeval_init_ms failed.\n");
                goto fail;
        }

        if (!tv_check(&us, 0, 100)) {
                printf("timeval_init_us failed.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ts_diff(void)
{
        struct timespec s0  = TIMESPEC_INIT_S (100);
        struct timespec s1  = TIMESPEC_INIT_S (200);
        struct timespec ms0 = TIMESPEC_INIT_MS(100);
        struct timespec ms1 = TIMESPEC_INIT_MS(200);
        struct timespec us0 = TIMESPEC_INIT_US(100);
        struct timespec us1 = TIMESPEC_INIT_US(200);
        struct timespec ns0 = TIMESPEC_INIT_NS(100);
        struct timespec ns1 = TIMESPEC_INIT_NS(200);
        struct timespec res;

        TEST_START();

        ts_diff(&s0, &s1, &res);
        if (!ts_check(&res, -100, 0)) {
                printf("timespec_diff failed at s0 - s1.\n");
                goto fail;
        }

        ts_diff(&s1, &s0, &res);
        if (!ts_check(&res, 100, 0)) {
                printf("timespec_diff failed at s1 - s0.\n");
                goto fail;
        }

        ts_diff(&ms0, &ms1, &res);
        if (!ts_check(&res, -1, 900 * MILLION)) {
                printf("timespec_diff failed at ms0 - ms1.\n");
                goto fail;
        }

        ts_diff(&ms1, &ms0, &res);
        if (!ts_check(&res, 0, 100 * MILLION)) {
                printf("timespec_diff failed at ms1 - ms0.\n");
                goto fail;
        }

        ts_diff(&us0, &us1, &res);
        if (!ts_check(&res, -1, 999900 * 1000L)) {
                printf("timespec_diff failed at us0 - us1.\n");
                goto fail;
        }

        ts_diff(&us1, &us0, &res);
        if (!ts_check(&res, 0, 100 * 1000L)) {
                printf("timespec_diff failed at us1 - us0.\n");
                goto fail;
        }

        ts_diff(&ns0, &ns1, &res);
        if (!ts_check(&res, -1, 999999900)) {
                printf("timespec_diff failed at ns0 - ns1.\n");
                goto fail;
        }

        ts_diff(&ns1, &ns0, &res);
        if (!ts_check(&res, 0, 100)) {
                printf("timespec_diff failed at ns1 - ns0.\n");
                goto fail;
        }

        ts_diff(&s0, &ms0, &res);
        if (!ts_check(&res, 99, 900 * MILLION)) {
                printf("timespec_diff failed at s0 - ms0.\n");
                goto fail;
        }

        ts_diff(&s0, &us0, &res);
        if (!ts_check(&res, 99, 999900 * 1000L)) {
                printf("timespec_diff failed at s0 - us0.\n");
                goto fail;
        }

        ts_diff(&s0, &ns0, &res);
        if (!ts_check(&res, 99, 999999900)) {
                printf("timespec_diff failed at s0 - ns0.\n");
                goto fail;
        }

        ts_diff(&ms0, &us0, &res);
        if (!ts_check(&res, 0, 99900 * 1000L)) {
                printf("timespec_diff failed at ms0 - us0.\n");
                goto fail;
        }

        ts_diff(&ms0, &ns0, &res);
        if (!ts_check(&res, 0, 99999900)) {
                printf("timespec_diff failed at ms0 - ns0.\n");
                goto fail;
        }

        ts_diff(&us0, &ns0, &res);
        if (!ts_check(&res, 0, 99900)) {
                printf("timespec_diff failed at us0 - ns0.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tv_diff(void)
{
        struct timeval s0  = TIMEVAL_INIT_S (100);
        struct timeval s1  = TIMEVAL_INIT_S (200);
        struct timeval ms0 = TIMEVAL_INIT_MS(100);
        struct timeval ms1 = TIMEVAL_INIT_MS(200);
        struct timeval us0 = TIMEVAL_INIT_US(100);
        struct timeval us1 = TIMEVAL_INIT_US(200);
        struct timeval res;

        TEST_START();

        tv_diff(&s0, &s1, &res);
        if (!tv_check(&res, -100, 0)) {
                printf("timeval_diff failed at s0 - s1.\n");
                goto fail;
        }

        tv_diff(&s1, &s0, &res);
        if (!tv_check(&res, 100, 0)) {
                printf("timeval_diff failed at s1 - s0.\n");
                goto fail;
        }

        tv_diff(&ms0, &ms1, &res);
        if (!tv_check(&res, -1, 900 * 1000L)) {
                printf("timeval_diff failed at ms0 - ms1.\n");
                goto fail;
        }

        tv_diff(&ms1, &ms0, &res);
        if (!tv_check(&res, 0, 100 * 1000L)) {
                printf("timeval_diff failed at ms1 - ms0.\n");
                goto fail;
        }

        tv_diff(&us0, &us1, &res);
        if (!tv_check(&res, -1, 999900)) {
                printf("timeval_diff failed at us0 - us1.\n");
                goto fail;
        }

        tv_diff(&us1, &us0, &res);
        if (!tv_check(&res, 0, 100)) {
                printf("timeval_diff failed at us1 - us0.\n");
                goto fail;
        }

        tv_diff(&s0, &ms0, &res);
        if (!tv_check(&res, 99, 900 * 1000L)) {
                printf("timeval_diff failed at s0 - ms0.\n");
                goto fail;
        }

        tv_diff(&s0, &us0, &res);
        if (!tv_check(&res, 99, 999900)) {
                printf("timeval_diff failed at s0 - us0.\n");
                goto fail;
        }

        tv_diff(&ms0, &us0, &res);
        if (!tv_check(&res, 0, 99900)) {
                printf("timeval_diff failed at ms0 - us0.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ts_diff_time(void)
{
        struct timespec s0  = TIMESPEC_INIT_S (100);
        struct timespec s1  = TIMESPEC_INIT_S (200);
        struct timespec ms0 = TIMESPEC_INIT_MS(100);
        struct timespec ms1 = TIMESPEC_INIT_MS(200);
        struct timespec us0 = TIMESPEC_INIT_US(100);
        struct timespec us1 = TIMESPEC_INIT_US(200);
        struct timespec ns0 = TIMESPEC_INIT_NS(100);
        struct timespec ns1 = TIMESPEC_INIT_NS(200);

        TEST_START();

        if (ts_diff_ms(&s0, &s1) != -100 * 1000L) {
                printf("timespec_diff_ms failed at s0 - s1.\n");
                goto fail;
        }

        if (ts_diff_ms(&s1, &s0) != 100 * 1000L) {
                printf("timespec_diff_ms failed at s1 - s0.\n");
                goto fail;
        }

        if (ts_diff_us(&s0, &s1) != -100 * MILLION) {
                printf("timespec_diff_us failed at s1 - s0.\n");
                goto fail;
        }

        if (ts_diff_us(&s1, &s0) != 100 * MILLION) {
                printf("timespec_diff_us failed at s0 - s1.\n");
                goto fail;
        }

        if (ts_diff_ns(&s0, &s1) != -100 * BILLION) {
                printf("timespec_diff_ns failed at s0 - s1.\n");
                goto fail;
        }

        if (ts_diff_ns(&s1, &s0) != 100 * BILLION) {
                printf("timespec_diff_ns failed at s1 - s0.\n");
                goto fail;
        }

        if (ts_diff_ms(&ms0, &ms1) != -100) {
                printf("timespec_diff_ms failed at ms0 - ms1.\n");
                goto fail;
        }

        if (ts_diff_ms(&ms1, &ms0) != 100) {
                printf("timespec_diff_ms failed at ms1 - ms0.\n");
                goto fail;
        }

        if (ts_diff_us(&ms0, &ms1) != -100 * 1000L) {
                printf("timespec_diff_us failed at ms0 - ms1.\n");
                goto fail;
        }

        if (ts_diff_us(&ms1, &ms0) != 100 * 1000L) {
                printf("timespec_diff_us failed at ms1 - ms0.\n");
                goto fail;
        }

        if (ts_diff_ns(&ms0, &ms1) != -100 * MILLION) {
                printf("timespec_diff_ns failed at ms0 - ms1.\n");
                goto fail;
        }

        if (ts_diff_ns(&ms1, &ms0) != 100 * MILLION) {
                printf("timespec_diff_ns failed at ms1 - ms0.\n");
                goto fail;
        }

        if (ts_diff_ms(&us0, &us1) != 0) {
                printf("timespec_diff_ms failed at us0 - us1.\n");
                goto fail;
        }

        if (ts_diff_ms(&us1, &us0) != 0) {
                printf("timespec_diff_ms failed at us1 - us0.\n");
                goto fail;
        }

        if (ts_diff_us(&us0, &us1) != -100) {
                printf("timespec_diff_us failed at us0 - us1.\n");
                goto fail;
        }

        if (ts_diff_us(&us1, &us0) != 100) {
                printf("timespec_diff_us failed at us1 - us0.\n");
                goto fail;
        }

        if (ts_diff_ns(&us0, &us1) != -100 * 1000L) {
                printf("timespec_diff_ns failed at us0 - us1.\n");
                goto fail;
        }

        if (ts_diff_ns(&us1, &us0) != 100 * 1000L) {
                printf("timespec_diff_ns failed at us1 - us0.\n");
                goto fail;
        }

        if (ts_diff_ms(&ns0, &ns1) != 0) {
                printf("timespec_diff_ms failed at ns0 - ns1.\n");
                goto fail;
        }

        if (ts_diff_ms(&ns1, &ns0) != 0) {
                printf("timespec_diff_ms failed at ns1 - ns0.\n");
                goto fail;
        }

        if (ts_diff_us(&ns0, &ns1) != 0) {
                printf("timespec_diff_us failed at ns0 - ns1.\n");
                goto fail;
        }

        if (ts_diff_us(&ns1, &ns0) != 0) {
                printf("timespec_diff_us failed at ns1 - ns0.\n");
                goto fail;
        }

        if (ts_diff_ns(&ns0, &ns1) != -100) {
                printf("timespec_diff_ns failed at ns0 - ns1.\n");
                goto fail;
        }

        if (ts_diff_ns(&ns1, &ns0) != 100) {
                printf("timespec_diff_ns failed at ns1 - ns0.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tv_diff_time(void)
{
        struct timeval s0  = TIMEVAL_INIT_S (100);
        struct timeval s1  = TIMEVAL_INIT_S (200);
        struct timeval ms0 = TIMEVAL_INIT_MS(100);
        struct timeval ms1 = TIMEVAL_INIT_MS(200);
        struct timeval us0 = TIMEVAL_INIT_US(100);
        struct timeval us1 = TIMEVAL_INIT_US(200);

        TEST_START();

        if (tv_diff_ms(&s0, &s1) != -100 * 1000L) {
                printf("timeval_diff_ms failed at s0 - s1.\n");
                goto fail;
        }

        if (tv_diff_ms(&s1, &s0) != 100 * 1000L) {
                printf("timeval_diff_ms failed at s1 - s0.\n");
                goto fail;
        }

        if (tv_diff_us(&s0, &s1) != -100 * MILLION) {
                printf("timeval_diff_us failed at s0 - s1.\n");
                goto fail;
        }

        if (tv_diff_us(&s1, &s0) != 100 * MILLION) {
                printf("timeval_diff_us failed at s1 - s0.\n");
                goto fail;
        }

        if (tv_diff_ms(&ms0, &ms1) != -100) {
                printf("timeval_diff_ms failed at ms0 - ms1.\n");
                goto fail;
        }

        if (tv_diff_ms(&ms1, &ms0) != 100) {
                printf("timeval_diff_ms failed at ms1 - ms0.\n");
                goto fail;
        }

        if (tv_diff_us(&ms0, &ms1) != -100 * 1000L) {
                printf("timeval_diff_us failed at ms0 - ms1.\n");
                goto fail;
        }

        if (tv_diff_us(&ms1, &ms0) != 100 * 1000L) {
                printf("timeval_diff_us failed at ms1 - ms0.\n");
                goto fail;
        }

        if (tv_diff_ms(&us0, &us1) != 0) {
                printf("timeval_diff_ms failed at us0 - us1.\n");
                goto fail;
        }

        if (tv_diff_ms(&us1, &us0) != 0) {
                printf("timeval_diff_ms failed at us1 - us0.\n");
                goto fail;
        }

        if (tv_diff_us(&us0, &us1) != -100) {
                printf("timeval_diff_us failed at us0 - us1.\n");
                goto fail;
        }

        if (tv_diff_us(&us1, &us0) != 100) {
                printf("timeval_diff_us failed at us1 - us0.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int time_test(int argc,
              char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_time_ts_init();
        ret |= test_time_tv_init();
        ret |= test_ts_diff();
        ret |= test_tv_diff();
        ret |= test_ts_diff_time();
        ret |= test_tv_diff_time();

        return ret;
}
