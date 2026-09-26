/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Tests for the threadpool manager
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


#include <ouroboros/pthread.h>
#include <ouroboros/tpm.h>

#include <test/test.h>

#define TEST_MAX_THR 5
#define TEST_WAIT_S  5

struct test_ctx {
        pthread_mutex_t mtx;
        size_t          n;
        struct tpm *    tpm;
};

static void * test_func(void * o)
{
        (void) o;

        while(1)
                sleep(1);

        return NULL;
}

static int test_tpm_create_destroy(void)
{
        struct tpm *tpm;

        TEST_START();

        tpm = tpm_create(2, 2, 4, &test_func, NULL);
        if (tpm == NULL) {
                printf("Failed to initialize TPM.\n");
                goto fail;
        }

        tpm_destroy(tpm);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tpm_start_stop(void * (* fn)(void *),
                               void * o)
{
        struct tpm *tpm;

        TEST_START();

        tpm = tpm_create(2, 2, 4, fn, o);
        if (tpm == NULL) {
                printf("Failed to initialize TPM.\n");
                goto fail_create;
        }

        if (tpm_start(tpm) < 0) {
                printf("Failed to start TPM.\n");
                goto fail_start;
        }

        tpm_stop(tpm);

        tpm_destroy(tpm);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_start:
        tpm_destroy(tpm);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Each thread stays busy forever, so the manager spawns up to max. */
static void * busy_func(void * o)
{
        struct test_ctx * ctx = (struct test_ctx *) o;

        pthread_mutex_lock(&ctx->mtx);
        ++ctx->n;
        pthread_mutex_unlock(&ctx->mtx);

        tpm_begin_work(ctx->tpm);

        while (1)
                sleep(1);

        return NULL;
}

static size_t ctx_count(struct test_ctx * ctx)
{
        size_t n;

        pthread_mutex_lock(&ctx->mtx);

        n = ctx->n;

        pthread_mutex_unlock(&ctx->mtx);

        return n;
}

static int test_tpm_max(void)
{
        struct tpm *   tpm;
        struct test_ctx ctx;
        int            i;

        TEST_START();

        ctx.n = 0;
        if (pthread_mutex_init(&ctx.mtx, NULL) != 0) {
                printf("Failed to init mutex.\n");
                goto fail;
        }

        tpm = tpm_create(2, 2, TEST_MAX_THR, &busy_func, &ctx);
        if (tpm == NULL) {
                printf("Failed to initialize TPM.\n");
                goto fail_create;
        }

        ctx.tpm = tpm;
        if (tpm_start(tpm) < 0) {
                printf("Failed to start TPM.\n");
                goto fail_start;
        }

        for (i = 0; i < TEST_WAIT_S && ctx_count(&ctx) < TEST_MAX_THR; ++i)
                sleep(1);

        sleep(2); /* give the manager time to overshoot */

        if (ctx_count(&ctx) != TEST_MAX_THR) {
                printf("Expected %d threads, got %zu.\n",
                       TEST_MAX_THR, ctx_count(&ctx));
                goto fail_max;
        }

        tpm_stop(tpm);

        tpm_destroy(tpm);

        pthread_mutex_destroy(&ctx.mtx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_max:
        tpm_stop(tpm);
 fail_start:
        tpm_destroy(tpm);
 fail_create:
        pthread_mutex_destroy(&ctx.mtx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int tpm_test(int     argc,
             char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_tpm_create_destroy();
        ret |= test_tpm_start_stop(&test_func, NULL);
        ret |= test_tpm_max();

        return ret;
}
