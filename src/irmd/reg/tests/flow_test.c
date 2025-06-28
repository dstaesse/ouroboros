/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Flows - Unit Tests
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

#include "../flow.c"

#include <ouroboros/test.h>

#include <string.h>

#define TEST_DATA "testpiggybackdata"

static int test_reg_flow_create_destroy(void)
{
        struct reg_flow * f;

        struct flow_info info = {
                .id    = 1,
                .n_pid = 1,
                .qs    = qos_raw,
                .state = FLOW_INIT
        };

        TEST_START();

        f = reg_flow_create(&info);
        if (f == NULL) {
                printf("Failed to create flow.\n");
                goto fail;
        }

        reg_flow_destroy(f);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_flow_create_no_id(void) {
        struct flow_info info = {
                .id    = 0,
                .n_pid = 1,
                .qs    = qos_raw,
                .state = FLOW_INIT
        };

        reg_flow_create(&info); /* assert fail */

        return TEST_RC_SUCCESS;
}

static int test_reg_flow_create_no_pid(void) {
        struct flow_info info = {
                .id    = 1,
                .n_pid = 0,
                .qs    = qos_raw,
                .state = FLOW_INIT
        };

        reg_flow_create(&info); /* assert fail */

        return TEST_RC_SUCCESS;
}

static int test_reg_flow_create_has_n_1_pid(void) {
        struct flow_info info = {
                .id      = 1,
                .n_pid   = 0,
                .n_1_pid = 1,
                .qs      = qos_raw,
                .state   = FLOW_INIT
        };

        reg_flow_create(&info); /* assert fail */

        return TEST_RC_SUCCESS;
}

static int test_reg_flow_create_wrong_state(void) {
        struct flow_info info = {
                .id      = 1,
                .n_pid   = 0,
                .n_1_pid = 1,
                .qs      = qos_raw,
                .state   = FLOW_ALLOC_PENDING
        };

        reg_flow_create(&info); /* assert fail */

        return TEST_RC_SUCCESS;
}

static int test_reg_flow_create_has_mpl(void) {
        struct flow_info info = {
                .id      = 1,
                .n_pid   = 1,
                .n_1_pid = 0,
                .mpl     = 10,
                .qs      = qos_raw,
                .state   = FLOW_ALLOC_PENDING
        };

        reg_flow_create(&info); /* assert fail */

        return TEST_RC_SUCCESS;
}

static int test_reg_flow_update(void)
{
        struct reg_flow * f;

        struct flow_info info = {
                .id    = 1,
                .n_pid = 1,
                .qs    = qos_raw,
                .state = FLOW_INIT
        };

        struct flow_info upd = {
                .id    = 1,
                .n_pid = 1,
                .qs    = qos_data,
                .state = FLOW_DEALLOCATED
        };

        TEST_START();

        f = reg_flow_create(&info);
        if (f == NULL) {
                printf("Failed to create flow.\n");
                goto fail;
        }

        reg_flow_update(f, &upd);

        if (memcmp(&f->info, &upd, sizeof(upd)) != 0) {
                printf("Flow info not updated.\n");
                goto fail;
        }

        reg_flow_destroy(f);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_flow_update_wrong_id(void)
{
        struct reg_flow * f;

        struct flow_info info = {
                .id    = 1,
                .n_pid = 1,
                .qs    = qos_raw,
                .state = FLOW_INIT
        };

        struct flow_info upd = {
                .id    = 2,
                .n_pid = 1,
                .qs    = qos_data,
                .state = FLOW_DEALLOCATED
        };

        TEST_START();

        f = reg_flow_create(&info);
        if (f == NULL) {
                printf("Failed to create flow.\n");
                goto fail;
        }

        reg_flow_update(f, &upd); /* assert fail */

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_flow_assert_fails(void)
{
        int ret = 0;

        ret |= test_assert_fail(test_reg_flow_create_no_id);
        ret |= test_assert_fail(test_reg_flow_create_no_pid);
        ret |= test_assert_fail(test_reg_flow_create_has_n_1_pid);
        ret |= test_assert_fail(test_reg_flow_create_wrong_state);
        ret |= test_assert_fail(test_reg_flow_create_has_mpl);
        ret |= test_assert_fail(test_reg_flow_update_wrong_id);

        return ret;
}

static int test_flow_data(void)
{
        struct reg_flow * f;

        struct flow_info info = {
                .id    = 1,
                .n_pid = 1,
                .qs    = qos_raw,
                .state = FLOW_INIT
        };

        char * data;
        buffer_t buf;
        buffer_t rcv = {NULL, 0};

        TEST_START();

        data = strdup(TEST_DATA);
        if (data == NULL) {
                printf("Failed to strdup data.\n");
                goto fail;
        }

        buf.data = (uint8_t *) data;
        buf.len  = strlen(data);

        f = reg_flow_create(&info);
        if (f == NULL) {
                printf("Failed to create flow.\n");
                goto fail;
        }

        reg_flow_set_data(f, &buf);

        reg_flow_get_data(f, &rcv);

        freebuf(buf);
        clrbuf(rcv);

        reg_flow_destroy(f);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        free(data);
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int flow_test(int     argc,
              char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_reg_flow_create_destroy();
        ret |= test_reg_flow_update();
        ret |= test_reg_flow_assert_fails();
        ret |= test_flow_data();

        return ret;
}
