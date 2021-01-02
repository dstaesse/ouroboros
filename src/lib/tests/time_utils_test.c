/*
 * Ouroboros - Copyright (C) 2016 - 2021
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

#include <ouroboros/time_utils.h>

#include <stdio.h>

static void ts_print(struct timespec * s)
{
        printf("timespec is %zd:%ld.\n", (ssize_t) s->tv_sec, s->tv_nsec);
}

static void tv_print(struct timeval * v)
{
        printf("timeval is %zd:%zu.\n", (ssize_t) v->tv_sec, (size_t) v->tv_usec);
}

static void ts_init(struct timespec * s,
                    time_t            sec,
                    time_t            nsec)
{
        s->tv_sec  = sec;
        s->tv_nsec = nsec;
}

static void tv_init(struct timeval * v,
                    time_t           sec,
                    time_t           usec)
{
        v->tv_sec  = sec;
        v->tv_usec = usec;
}

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

int time_utils_test(int     argc,
                    char ** argv)
{
        struct timespec s0;
        struct timespec s1;
        struct timespec s2;

        struct timeval v0;
        struct timeval v1;
        struct timeval v2;

        (void) argc;
        (void) argv;

        ts_init(&s0, 0, 0);
        ts_init(&s1, 5, 0);

        ts_add(&s0, &s1, &s2);
        if (!ts_check(&s2, 5, 0)) {
                printf("ts_add failed.\n");
                ts_print(&s2);
                return -1;
        }

        tv_init(&v0, 0, 0);
        tv_init(&v1, 5, 0);

        tv_add(&v0, &v1, &v2);
        if (!tv_check(&v2, 5, 0)) {
                printf("tv_add failed.\n");
                tv_print(&v2);
                return -1;
        }

        ts_init(&s0, 0, 500 * MILLION);
        ts_init(&s1, 0, 600 * MILLION);

        ts_add(&s0, &s1, &s2);
        if (!ts_check(&s2, 1, 100 * MILLION)) {
                printf("ts_add with nano overflow failed.\n");
                ts_print(&s2);
                return -1;
        }

        tv_init(&v0, 0, 500 * 1000);
        tv_init(&v1, 0, 600 * 1000);

        tv_add(&v0, &v1, &v2);
        if (!tv_check(&v2, 1, 100 * 1000)) {
                printf("tv_add with nano overflow failed.\n");
                tv_print(&v2);
                return -1;
        }

        ts_init(&s0, 0, 0);
        ts_init(&s1, 5, 0);

        ts_diff(&s0, &s1, &s2);
        if (!ts_check(&s2, -5, 0)) {
                printf("ts_diff failed.\n");
                ts_print(&s2);
                return -1;
        }

        tv_init(&v0, 0, 0);
        tv_init(&v1, 5, 0);

        tv_diff(&v0, &v1, &v2);
        if (!tv_check(&v2, -5, 0)) {
                printf("tv_diff failed.\n");
                tv_print(&v2);
                return -1;
        }

        ts_init(&s0, 0, 500 * MILLION);
        ts_init(&s1, 0, 600 * MILLION);

        ts_diff(&s0, &s1, &s2);
        if (!ts_check(&s2, -1, 900 * MILLION)) {
                printf("ts_diff with nano underflow failed.\n");
                ts_print(&s2);
                return -1;
        }

        tv_init(&v0, 0, 500 * 1000);
        tv_init(&v1, 0, 600 * 1000);

        tv_diff(&v0, &v1, &v2);
        if (!tv_check(&v2, -1, 900 * 1000)) {
                printf("tv_diff with nano underflow failed.\n");
                tv_print(&v2);
                return -1;
        }

        return 0;
}
