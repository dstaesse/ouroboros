/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the SSM notification ring buffer
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
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"
#include "ssm.h"

#include <test/test.h>
#include <ouroboros/ssm_rbuff.h>
#include <ouroboros/errno.h>
#include <ouroboros/time.h>

/* Mirrors TXQ_MIN_SLOTS in ssm/rbuff.c; keep in sync. */
#define FLOOR_SLOTS 4
#define CEIL_SLOTS  (SSM_RBUFF_SIZE - 1 - SSM_RBUFF_TXQ_RESERVE)

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

static int test_ssm_rbuff_create_destroy(void)
{
        struct ssm_rbuff * rb;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 1);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_write_read(void)
{
        struct ssm_rbuff * rb;
        ssize_t            idx;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 2);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        if (ssm_rbuff_write(rb, 42) < 0) {
                printf("Failed to write value.\n");
                goto fail_rb;
        }

        if (ssm_rbuff_queued(rb) != 1) {
                printf("Queue length should be 1, got %zu.\n",
                       ssm_rbuff_queued(rb));
                goto fail_rb;
        }

        idx = ssm_rbuff_read(rb);
        if (idx != 42) {
                printf("Expected 42, got %zd.\n", idx);
                goto fail_rb;
        }

        if (ssm_rbuff_queued(rb) != 0) {
                printf("Queue should be empty, got %zu.\n",
                       ssm_rbuff_queued(rb));
                goto fail_rb;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_read_empty(void)
{
        struct ssm_rbuff * rb;
        ssize_t            ret;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 3);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        ret = ssm_rbuff_read(rb);
        if (ret != -EAGAIN) {
                printf("Expected -EAGAIN, got %zd.\n", ret);
                goto fail_rb;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_fill_drain(void)
{
        struct ssm_rbuff * rb;
        size_t             i;
        ssize_t            ret;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 4);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        for (i = 0; i < SSM_RBUFF_SIZE - 1; ++i) {
                if (ssm_rbuff_queued(rb) != i) {
                        printf("Expected %zu queued, got %zu.\n",
                               i, ssm_rbuff_queued(rb));
                        goto fail_rb;
                }

                if (ssm_rbuff_write(rb, i) < 0) {
                        printf("Failed to write at index %zu.\n", i);
                        goto fail_rb;
                }
        }

        if (ssm_rbuff_queued(rb) != SSM_RBUFF_SIZE - 1) {
                printf("Expected %d queued, got %zu.\n",
                       SSM_RBUFF_SIZE - 1, ssm_rbuff_queued(rb));
                goto fail_rb;
        }

        ret = ssm_rbuff_write(rb, 999);
        if (ret != -EAGAIN) {
                printf("Expected -EAGAIN on full buffer, got %zd.\n", ret);
                goto fail_rb;
        }

        for (i = 0; i < SSM_RBUFF_SIZE - 1; ++i) {
                ret = ssm_rbuff_read(rb);
                if (ret != (ssize_t) i) {
                        printf("Expected %zu, got %zd.\n", i, ret);
                        goto fail_rb;
                }
        }

        if (ssm_rbuff_queued(rb) != 0) {
                printf("Expected empty queue, got %zu.\n",
                       ssm_rbuff_queued(rb));
                goto fail_rb;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_flags(void)
{
        struct ssm_rbuff * rb;
        uint32_t           flags;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 5);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        flags = ssm_rbuff_get_flags(rb);
        if (flags != RB_RDWR) {
                printf("Expected RB_RDWR, got %u.\n", flags);
                goto fail_rb;
        }

        ssm_rbuff_clr_flags(rb, RB_WR);

        flags = ssm_rbuff_get_flags(rb);
        if (flags != RB_RD) {
                printf("Expected RB_RD, got %u.\n", flags);
                goto fail_rb;
        }

        if (ssm_rbuff_write(rb, 1) != -ENOTALLOC) {
                printf("Expected -ENOTALLOC on RDONLY.\n");
                goto fail_rb;
        }

        ssm_rbuff_set_flags(rb, RB_FLOWDOWN);

        if (ssm_rbuff_write(rb, 1) != -EFLOWDOWN) {
                printf("Expected -EFLOWDOWN on FLOWDOWN.\n");
                goto fail_rb;
        }

        if (ssm_rbuff_read(rb) != -EFLOWDOWN) {
                printf("Expected -EFLOWDOWN on read with FLOWDOWN.\n");
                goto fail_rb;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_open_close(void)
{
        struct ssm_rbuff * rb1;
        struct ssm_rbuff * rb2;
        pid_t              pid;

        TEST_START();

        pid = getpid();

        rb1 = ssm_rbuff_create(pid, 6);
        if (rb1 == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        if (ssm_rbuff_write(rb1, 123) < 0) {
                printf("Failed to write value.\n");
                goto fail_rb1;
        }

        rb2 = ssm_rbuff_open(pid, 6);
        if (rb2 == NULL) {
                printf("Failed to open existing rbuff.\n");
                goto fail_rb1;
        }

        if (ssm_rbuff_queued(rb2) != 1) {
                printf("Expected 1 queued in opened rbuff, got %zu.\n",
                       ssm_rbuff_queued(rb2));
                goto fail_rb2;
        }

        if (ssm_rbuff_read(rb2) != 123) {
                printf("Failed to read from opened rbuff.\n");
                goto fail_rb2;
        }

        ssm_rbuff_close(rb2);
        ssm_rbuff_destroy(rb1);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb2:
        ssm_rbuff_close(rb2);
 fail_rb1:
        ssm_rbuff_destroy(rb1);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

struct thread_args {
        struct ssm_rbuff * rb;
        int                iterations;
        int                delay_us;
};

static void * writer_thread(void * arg)
{
        struct thread_args * args = (struct thread_args *) arg;
        struct timespec      delay = {0, 0};
        int                  i;

        delay.tv_nsec = args->delay_us * 1000L;

        for (i = 0; i < args->iterations; ++i) {
                while (ssm_rbuff_write(args->rb, i) < 0)
                        nanosleep(&delay, NULL);
        }

        return NULL;
}

static void * reader_thread(void * arg)
{
        struct thread_args * args = (struct thread_args *) arg;
        struct timespec      delay = {0, 0};
        int                  i;
        ssize_t              val;

        delay.tv_nsec = args->delay_us * 1000L;

        for (i = 0; i < args->iterations; ++i) {
                val = ssm_rbuff_read(args->rb);
                while (val < 0) {
                        nanosleep(&delay, NULL);

                        val = ssm_rbuff_read(args->rb);
                }

                if (val != i) {
                        printf("Expected %d, got %zd.\n", i, val);
                        return (void *) -1;
                }
        }

        return NULL;
}

static void * blocking_wr_thread(void * arg)
{
        struct thread_args * args = (struct thread_args *) arg;
        int                  i;

        for (i = 0; i < args->iterations; ++i) {
                if (ssm_rbuff_write_b(args->rb, i, NULL) < 0)
                        return (void *) -1;
        }

        return NULL;
}

static void * blocking_rd_thread(void * arg)
{
        struct thread_args * args = (struct thread_args *) arg;
        int                  i;
        ssize_t              val;

        for (i = 0; i < args->iterations; ++i) {
                val = ssm_rbuff_read_b(args->rb, NULL);
                if (val < 0 || val != i) {
                        printf("Expected %d, got %zd.\n", i, val);
                        return (void *) -1;
                }
        }

        return NULL;
}

static int test_ssm_rbuff_blocking(void)
{
        struct ssm_rbuff * rb;
        pthread_t          wthread;
        pthread_t          rthread;
        struct thread_args args;
        struct timespec    delay = {0, 10 * MILLION};
        void *             ret_w;
        void *             ret_r;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 8);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        args.rb = rb;
        args.iterations = 50;
        args.delay_us = 0;
        if (pthread_create(&rthread, NULL, blocking_rd_thread, &args) != 0) {
                printf("Failed to create reader thread.\n");
                goto fail_rthread;
        }

        nanosleep(&delay, NULL);

        if (pthread_create(&wthread, NULL, blocking_wr_thread, &args) != 0) {
                printf("Failed to create writer thread.\n");
                pthread_cancel(rthread);
                goto fail_wthread;
        }

        pthread_join(wthread, &ret_w);
        pthread_join(rthread, &ret_r);

        if (ret_w != NULL || ret_r != NULL) {
                printf("Thread returned error.\n");
                goto fail_ret;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_ret:
 fail_wthread:
        pthread_join(rthread, NULL);
 fail_rthread:
        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_blocking_timeout(void)
{
        struct ssm_rbuff * rb;
        struct timespec    abs_timeout;
        struct timespec    interval = {0, 100 * MILLION};
        struct timespec    start;
        struct timespec    end;
        ssize_t            ret;
        long               elapsed_ms;
        size_t             i;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 9);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &start);
        ts_add(&start, &interval, &abs_timeout);

        ret = ssm_rbuff_read_b(rb, &abs_timeout);

        clock_gettime(PTHREAD_COND_CLOCK, &end);

        if (ret != -ETIMEDOUT) {
                printf("Expected -ETIMEDOUT, got %zd.\n", ret);
                goto fail_rb;
        }

        elapsed_ms = (end.tv_sec - start.tv_sec) * 1000L +
                     (end.tv_nsec - start.tv_nsec) / 1000000L;

        if (elapsed_ms < 90 || elapsed_ms > 200) {
                printf("Timeout took %ld ms, expected ~100 ms.\n", elapsed_ms);
                goto fail_rb;
        }

        for (i = 0; i < SSM_RBUFF_SIZE - 1; ++i) {
                if (ssm_rbuff_write(rb, i) < 0) {
                        printf("Failed to fill buffer.\n");
                        goto fail_rb;
                }
        }

        clock_gettime(PTHREAD_COND_CLOCK, &start);
        ts_add(&start, &interval, &abs_timeout);

        ret = ssm_rbuff_write_b(rb, 999, &abs_timeout);

        clock_gettime(PTHREAD_COND_CLOCK, &end);

        if (ret != -ETIMEDOUT) {
                printf("Expected -ETIMEDOUT on full buffer, got %zd.\n", ret);
                goto fail_rb;
        }

        elapsed_ms = (end.tv_sec - start.tv_sec) * 1000L +
                     (end.tv_nsec - start.tv_nsec) / 1000000L;

        if (elapsed_ms < 90 || elapsed_ms > 200) {
                printf("Write timeout took %ld ms, expected ~100 ms.\n",
                       elapsed_ms);
                goto fail_rb;
        }

        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_blocking_flowdown(void)
{
        struct ssm_rbuff * rb;
        struct timespec    abs_timeout;
        struct timespec    now;
        struct timespec    interval = {5, 0};
        ssize_t            ret;
        size_t             i;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 10);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        ts_add(&now, &interval, &abs_timeout);

        ssm_rbuff_set_flags(rb, RB_FLOWDOWN);

        ret = ssm_rbuff_read_b(rb, &abs_timeout);
        if (ret != -EFLOWDOWN) {
                printf("Expected -EFLOWDOWN, got %zd.\n", ret);
                goto fail_rb;
        }

        ssm_rbuff_clr_flags(rb, RB_FLOWDOWN);

        for (i = 0; i < SSM_RBUFF_SIZE - 1; ++i) {
                if (ssm_rbuff_write(rb, i) < 0) {
                        printf("Failed to fill buffer.\n");
                        goto fail_rb;
                }
        }

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        ts_add(&now, &interval, &abs_timeout);

        ssm_rbuff_set_flags(rb, RB_FLOWDOWN);

        ret = ssm_rbuff_write_b(rb, 999, &abs_timeout);
        if (ret != -EFLOWDOWN) {
                printf("Expected -EFLOWDOWN on write, got %zd.\n", ret);
                goto fail_rb;
        }

        ssm_rbuff_clr_flags(rb, RB_FLOWDOWN);

        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_threaded(void)
{
        struct ssm_rbuff * rb;
        pthread_t          wthread;
        pthread_t          rthread;
        struct thread_args args;
        void *             ret_w;
        void *             ret_r;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 7);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        args.rb = rb;
        args.iterations = 100;
        args.delay_us = 100;
        if (pthread_create(&wthread, NULL, writer_thread, &args) != 0) {
                printf("Failed to create writer thread.\n");
                goto fail_rb;
        }

        if (pthread_create(&rthread, NULL, reader_thread, &args) != 0) {
                printf("Failed to create reader thread.\n");
                pthread_cancel(wthread);
                pthread_join(wthread, NULL);
                goto fail_rb;
        }

        pthread_join(wthread, &ret_w);
        pthread_join(rthread, &ret_r);

        if (ret_w != NULL || ret_r != NULL) {
                printf("Thread returned error.\n");
                goto fail_rb;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_limit_off(void)
{
        struct ssm_rbuff * rb;
        size_t             i;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 11);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        if (ssm_rbuff_get_limit(rb) != SSM_RBUFF_SIZE - 1) {
                printf("Expected default limit %d, got %zu.\n",
                       SSM_RBUFF_SIZE - 1, ssm_rbuff_get_limit(rb));
                goto fail_rb;
        }

        for (i = 0; i < SSM_RBUFF_SIZE - 1; ++i) {
                if (ssm_rbuff_write(rb, i) < 0) {
                        printf("Failed to write at index %zu.\n", i);
                        goto fail_rb;
                }
        }

        if (ssm_rbuff_write(rb, 999) != -EAGAIN) {
                printf("Expected -EAGAIN on physically full buffer.\n");
                goto fail_rb;
        }

        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_limit_slow(void)
{
        struct ssm_rbuff * rb;
        struct timespec    dfl = TIMESPEC_INIT_MS(SSM_RBUFF_TXQ_DELAY);
        struct timespec    delay = {0, 10 * MILLION};
        size_t             limit;
        size_t             i;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 12);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        ssm_rbuff_set_txq_target(rb, &dfl);

        for (i = 0; i < 32; ++i) {
                if (ssm_rbuff_write_b(rb, i, NULL) < 0) {
                        printf("Failed to write at index %zu.\n", i);
                        goto fail_rb;
                }
                nanosleep(&delay, NULL);

                if (ssm_rbuff_read(rb) < 0) {
                        printf("Failed to read at index %zu.\n", i);
                        goto fail_rb;
                }
        }

        limit = ssm_rbuff_get_limit(rb);
        if (limit > FLOOR_SLOTS) {
                printf("Expected limit near the floor, got %zu.\n", limit);
                goto fail_rb;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_limit_fast(void)
{
        struct ssm_rbuff * rb;
        struct timespec    dfl = TIMESPEC_INIT_MS(SSM_RBUFF_TXQ_DELAY);
        size_t             limit;
        size_t             i;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 13);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        ssm_rbuff_set_txq_target(rb, &dfl);

        for (i = 0; i < 200; ++i) {
                if (ssm_rbuff_write_b(rb, i, NULL) < 0) {
                        printf("Failed to write at index %zu.\n", i);
                        goto fail_rb;
                }

                if (ssm_rbuff_read(rb) < 0) {
                        printf("Failed to read at index %zu.\n", i);
                        goto fail_rb;
                }
        }

        limit = ssm_rbuff_get_limit(rb);
        if (limit != CEIL_SLOTS) {
                printf("Expected limit %d, got %zu.\n", CEIL_SLOTS, limit);
                goto fail_rb;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_rbuff_limit_floor(void)
{
        struct ssm_rbuff * rb;
        struct timespec    dfl = TIMESPEC_INIT_MS(SSM_RBUFF_TXQ_DELAY);
        struct timespec    interval = {0, 50 * MILLION};
        struct timespec    now;
        struct timespec    abs_timeout;
        size_t             limit;
        int                ret = 0;
        size_t             i;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 14);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        ssm_rbuff_set_txq_target(rb, &dfl);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        ts_add(&now, &interval, &abs_timeout);

        for (i = 0; i < SSM_RBUFF_SIZE; ++i) {
                ret = ssm_rbuff_write_b(rb, i, &abs_timeout);
                if (ret == -ETIMEDOUT)
                        break;

                if (ret < 0) {
                        printf("Write failed at index %zu: %d.\n", i, ret);
                        goto fail_rb;
                }
        }

        if (ret != -ETIMEDOUT) {
                printf("Expected the limiter to block the ring.\n");
                goto fail_rb;
        }

        limit = ssm_rbuff_get_limit(rb);
        if (limit > FLOOR_SLOTS) {
                printf("Expected floor limit, got %zu.\n", limit);
                goto fail_rb;
        }

        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* A fresh ring is unlimited; rx rings must not inherit a bound. */
static int test_ssm_rbuff_txq_target(void)
{
        struct ssm_rbuff * rb;
        struct timespec    dfl = TIMESPEC_INIT_MS(SSM_RBUFF_TXQ_DELAY);
        struct timespec    delay = {0, 5 * MILLION};
        struct timespec    small = {0, 2 * MILLION};
        struct timespec    big   = {0, 200 * MILLION};
        struct timespec    def;
        struct timespec    got;
        size_t             limit_small;
        size_t             limit_big;
        size_t             i;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 15);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        ssm_rbuff_get_txq_target(rb, &got);

        if (got.tv_sec != 0 || got.tv_nsec != 0) {
                printf("A new ring is not unlimited.\n");
                goto fail_rb;
        }

        ssm_rbuff_set_txq_target(rb, &dfl);
        ssm_rbuff_get_txq_target(rb, &def);

        ssm_rbuff_set_txq_target(rb, &small);

        for (i = 0; i < 64; ++i) {
                if (ssm_rbuff_write_b(rb, i, NULL) < 0) {
                        printf("Failed to write at index %zu.\n", i);
                        goto fail_rb;
                }
                nanosleep(&delay, NULL);

                if (ssm_rbuff_read(rb) < 0) {
                        printf("Failed to read at index %zu.\n", i);
                        goto fail_rb;
                }
        }

        limit_small = ssm_rbuff_get_limit(rb);

        ssm_rbuff_set_txq_target(rb, &big);

        for (i = 0; i < 64; ++i) {
                if (ssm_rbuff_write_b(rb, i, NULL) < 0) {
                        printf("Failed to write at index %zu.\n", i);
                        goto fail_rb;
                }
                nanosleep(&delay, NULL);

                if (ssm_rbuff_read(rb) < 0) {
                        printf("Failed to read at index %zu.\n", i);
                        goto fail_rb;
                }
        }

        limit_big = ssm_rbuff_get_limit(rb);
        if (limit_big <= limit_small) {
                printf("Expected a larger target to grow the limit: "
                       "%zu -> %zu.\n", limit_small, limit_big);
                goto fail_rb;
        }

        ssm_rbuff_set_txq_target(rb, &dfl);
        ssm_rbuff_get_txq_target(rb, &got);

        if (got.tv_sec != def.tv_sec || got.tv_nsec != def.tv_nsec) {
                printf("NULL did not restore the default target.\n");
                goto fail_rb;
        }

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Ages the seed sample past the estimator's dt floor at write 16. */
static int test_ssm_rbuff_write_over_limit(void)
{
        struct ssm_rbuff * rb;
        struct timespec    dfl = TIMESPEC_INIT_MS(SSM_RBUFF_TXQ_DELAY);
        struct timespec    age = {0, 20 * 1000};
        size_t             count;
        int                ret = 0;

        TEST_START();

        rb = ssm_rbuff_create(getpid(), 16);
        if (rb == NULL) {
                printf("Failed to create rbuff.\n");
                goto fail;
        }

        ssm_rbuff_set_txq_target(rb, &dfl);

        for (count = 0; count < SSM_RBUFF_SIZE; ++count) {
                ret = ssm_rbuff_write(rb, count);
                if (ret == -EAGAIN)
                        break;

                if (ret < 0) {
                        printf("Write failed at index %zu: %d.\n", count, ret);
                        goto fail_rb;
                }

                if (count == 16)
                        nanosleep(&age, NULL);
        }

        if (ret != -EAGAIN) {
                printf("Expected the limiter to reject a write.\n");
                goto fail_rb;
        }

        if (count >= SSM_RBUFF_SIZE / 2) {
                printf("Expected -EAGAIN well before a full ring, "
                       "got %zu writes.\n", count);
                goto fail_rb;
        }

        if (ssm_rbuff_queued(rb) != count) {
                printf("Queued %zu does not match write count %zu.\n",
                       ssm_rbuff_queued(rb), count);
                goto fail_rb;
        }

        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_rb:
        while (ssm_rbuff_read(rb) >= 0)
                ;

        ssm_rbuff_destroy(rb);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int rbuff_test(int     argc,
               char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_ssm_rbuff_create_destroy();
        ret |= test_ssm_rbuff_write_read();
        ret |= test_ssm_rbuff_read_empty();
        ret |= test_ssm_rbuff_fill_drain();
        ret |= test_ssm_rbuff_flags();
        ret |= test_ssm_rbuff_open_close();
        ret |= test_ssm_rbuff_threaded();
        ret |= test_ssm_rbuff_blocking();
        ret |= test_ssm_rbuff_blocking_timeout();
        ret |= test_ssm_rbuff_blocking_flowdown();
        ret |= test_ssm_rbuff_limit_off();
        ret |= test_ssm_rbuff_limit_slow();
        ret |= test_ssm_rbuff_limit_fast();
        ret |= test_ssm_rbuff_limit_floor();
        ret |= test_ssm_rbuff_txq_target();
        ret |= test_ssm_rbuff_write_over_limit();

        return ret;
}
