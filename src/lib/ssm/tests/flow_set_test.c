/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the SSM flow set
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
#include <ouroboros/ssm_flow_set.h>
#include <ouroboros/errno.h>
#include <ouroboros/time.h>

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

static int test_ssm_flow_set_create_destroy(void)
{
        struct ssm_flow_set * set;
        pid_t                 pid;

        TEST_START();

        pid = getpid();

        set = ssm_flow_set_create(pid);
        if (set == NULL) {
                printf("Failed to create flow set.\n");
                goto fail;
        }

        ssm_flow_set_destroy(set);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_flow_set_add_del_has(void)
{
        struct ssm_flow_set * set;
        pid_t                 pid;
        size_t                idx = 0;
        int                   flow_id = 42;

        TEST_START();

        pid = getpid();

        set = ssm_flow_set_create(pid);
        if (set == NULL) {
                printf("Failed to create flow set.\n");
                goto fail;
        }

        if (ssm_flow_set_has(set, idx, flow_id)) {
                printf("Flow should not be in set initially.\n");
                goto fail_destroy;
        }

        if (ssm_flow_set_add(set, idx, flow_id) < 0) {
                printf("Failed to add flow to set.\n");
                goto fail_destroy;
        }

        if (!ssm_flow_set_has(set, idx, flow_id)) {
                printf("Flow should be in set after add.\n");
                goto fail_destroy;
        }

        /* Adding same flow again should fail */
        if (ssm_flow_set_add(set, idx, flow_id) != -EPERM) {
                printf("Should not be able to add flow twice.\n");
                goto fail_destroy;
        }

        ssm_flow_set_del(set, idx, flow_id);

        if (ssm_flow_set_has(set, idx, flow_id)) {
                printf("Flow should not be in set after delete.\n");
                goto fail_destroy;
        }

        ssm_flow_set_destroy(set);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
fail_destroy:
        ssm_flow_set_destroy(set);
fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_flow_set_zero(void)
{
        struct ssm_flow_set * set;
        pid_t                 pid;
        size_t                idx = 0;
        int                   flow_id1 = 10;
        int                   flow_id2 = 20;

        TEST_START();

        pid = getpid();

        set = ssm_flow_set_create(pid);
        if (set == NULL) {
                printf("Failed to create flow set.\n");
                goto fail;
        }

        if (ssm_flow_set_add(set, idx, flow_id1) < 0) {
                printf("Failed to add flow1 to set.\n");
                goto fail_destroy;
        }

        if (ssm_flow_set_add(set, idx, flow_id2) < 0) {
                printf("Failed to add flow2 to set.\n");
                goto fail_destroy;
        }

        ssm_flow_set_zero(set, idx);

        if (ssm_flow_set_has(set, idx, flow_id1)) {
                printf("Flow1 should not be in set after zero.\n");
                goto fail_destroy;
        }

        if (ssm_flow_set_has(set, idx, flow_id2)) {
                printf("Flow2 should not be in set after zero.\n");
                goto fail_destroy;
        }

        ssm_flow_set_destroy(set);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
fail_destroy:
        ssm_flow_set_destroy(set);
fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_flow_set_notify_wait(void)
{
        struct ssm_flow_set * set;
        pid_t                 pid;
        size_t                idx = 0;
        int                   flow_id = 100;
        struct flowevent      events[SSM_RBUFF_SIZE];
        struct timespec       timeout;
        ssize_t               ret;

        TEST_START();

        pid = getpid();

        set = ssm_flow_set_create(pid);
        if (set == NULL) {
                printf("Failed to create flow set.\n");
                goto fail;
        }

        if (ssm_flow_set_add(set, idx, flow_id) < 0) {
                printf("Failed to add flow to set.\n");
                goto fail_destroy;
        }

        /* Test immediate timeout when no events */
        clock_gettime(PTHREAD_COND_CLOCK, &timeout);
        ret = ssm_flow_set_wait(set, idx, events, &timeout);
        if (ret != -ETIMEDOUT) {
                printf("Wait should timeout immediately when no events.\n");
                goto fail_destroy;
        }

        /* Notify an event */
        ssm_flow_set_notify(set, flow_id, FLOW_PKT);

        /* Should be able to read the event immediately */
        clock_gettime(PTHREAD_COND_CLOCK, &timeout);
        ts_add(&timeout, &timeout, &((struct timespec) {1, 0}));

        ret = ssm_flow_set_wait(set, idx, events, &timeout);
        if (ret != 1) {
                printf("Wait should return 1 event, got %zd.\n", ret);
                goto fail_destroy;
        }

        if (events[0].flow_id != flow_id) {
                printf("Event flow_id mismatch: expected %d, got %d.\n",
                       flow_id, events[0].flow_id);
                goto fail_destroy;
        }

        if (events[0].event != FLOW_PKT) {
                printf("Event type mismatch: expected %d, got %d.\n",
                       FLOW_PKT, events[0].event);
                goto fail_destroy;
        }

        ssm_flow_set_destroy(set);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
fail_destroy:
        ssm_flow_set_destroy(set);
fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int flow_set_test(int     argc,
                  char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_ssm_flow_set_create_destroy();
        ret |= test_ssm_flow_set_add_del_has();
        ret |= test_ssm_flow_set_zero();
        ret |= test_ssm_flow_set_notify_wait();

        return ret;
}
