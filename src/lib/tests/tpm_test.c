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


#include "tpm.c"

#include <test/test.h>

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

        tpm = tpm_create(2, 2, &test_func, NULL);
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

        tpm = tpm_create(2, 2, fn, o);
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

int tpm_test(int     argc,
             char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_tpm_create_destroy();
        ret |= test_tpm_start_stop(&test_func, NULL);

        return ret;
}
