/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * The IPC Resource Manager - Registry - Names - Unit Tests
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


#include "../name.c"

#include <test/test.h>

#define TEST_PID  65534
#define TEST_PROG "/usr/bin/testprog"
#define TEST_NAME "testservicename"

static int test_reg_name_create(void)
{
        struct reg_name * n;
        struct name_info  info = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR,
        };

        TEST_START();

        n = reg_name_create(&info);
        if (n == NULL) {
                printf("Failed to create name %s.\n", info.name);
                goto fail;
        }

        reg_name_destroy(n);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_name_add_proc(void)
{
        struct reg_name * n;
        struct name_info  info = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR,
        };

        TEST_START();

        n = reg_name_create(&info);
        if (n == NULL) {
                printf("Failed to create name %s.\n", info.name);
                goto fail;
        }

        if (reg_name_add_proc(n, TEST_PID) < 0) {
                printf("Failed to add proc.\n");
                goto fail;
        }

        if (n->procs.len != 1) {
                printf("Proc not added to list.\n");
                goto fail;
        }

        if (!reg_name_has_proc(n, TEST_PID)) {
                printf("Proc not found.\n");
                goto fail;
        }

        reg_name_del_proc(n, TEST_PID);

        if (n->procs.len != 0) {
                printf("Proc not removed from list.\n");
                goto fail;
        }

        reg_name_destroy(n);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_name_add_prog(void)
{
        struct reg_name * n;
        struct name_info  info = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR,
        };

        char * exec[] = { TEST_PROG, "--argswitch", "argvalue", NULL};

        TEST_START();

        n = reg_name_create(&info);
        if (n == NULL) {
                printf("Failed to create name %s.\n", info.name);
                goto fail;
        }

        if (reg_name_add_prog(n, exec) < 0) {
                printf("Failed to add prog.\n");
                goto fail;
        }

        if (n->progs.len != 1) {
                printf("Prog not added to list.\n");
                goto fail;
        }

        if (!reg_name_has_prog(n, TEST_PROG)) {
                printf("Prog not found.\n");
                goto fail;
        }

        reg_name_del_prog(n, TEST_PROG);

        if (n->progs.len != 0) {
                printf("Prog not removed from list.\n");
                goto fail;
        }

        reg_name_destroy(n);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_name_add_active(enum pol_balance lb)
{
        struct reg_name * n;
        pid_t             pid;
        struct name_info  info = {
                .name   = TEST_NAME,
                .pol_lb = lb,
        };

        TEST_START();

        n = reg_name_create(&info);
        if (n == NULL) {
                printf("Failed to create name %s.\n", info.name);
                goto fail;
        }

        if (reg_name_get_active(n) != -1) {
                printf("Got active from empty actives.\n");
                goto fail;
        }

        if (reg_name_add_proc(n, TEST_PID) < 0) {
                printf("Failed to add proc 0.\n");
                goto fail;
        }

        if (reg_name_add_proc(n, TEST_PID + 1) < 0) {
                printf("Failed to add proc 1.\n");
                goto fail;
        }

        if (reg_name_add_proc(n, TEST_PID + 2) < 0) {
                printf("Failed to add proc 2.\n");
                goto fail;
        }

        if (reg_name_add_active(n, TEST_PID) < 0) {
                printf("Failed to add active.\n");
                goto fail;
        }

        if (n->active.len != 1) {
                printf("Active list not updated.\n");
                goto fail;
        }

        if (reg_name_get_active(n) != TEST_PID) {
                printf("Failed to get active.\n");
                goto fail;
        }

        if (reg_name_get_active(n) != TEST_PID) {
                printf("Failed to get active.\n");
                goto fail;
        }

        if (reg_name_add_active(n, TEST_PID + 1) < 0) {
                printf("Failed to add active 3.\n");
                goto fail;
        }

        if (reg_name_add_active(n, TEST_PID + 1) < 0) {
                printf("Failed to add active 3.\n");
                goto fail;
        }


        if (reg_name_add_active(n, TEST_PID + 2) < 0) {
                printf("Failed to add active 4.\n");
                goto fail;
        }

        if (n->procs.len != 3) {
                printf("Procs list not updated.\n");
                goto fail;
        }

        if (n->active.len != 4) {
                printf("Active list not updated.\n");
                goto fail;
        }

        pid = info.pol_lb == LB_RR ? TEST_PID : TEST_PID + 2;

        if (reg_name_get_active(n) != pid) {
                printf("Got wrong active pid 1.\n");
                goto fail;
        }

        reg_name_del_active(n, pid);

        if (reg_name_add_active(n, pid) < 0) {
                printf("Failed to add active 4.\n");
                goto fail;
        }

        pid = info.pol_lb == LB_RR ? TEST_PID + 1 : TEST_PID + 2;

        if (reg_name_get_active(n) != pid) {
                printf("Got wrong active pid 2 %d.\n", pid);
                goto fail;
        }

        reg_name_del_proc(n, TEST_PID + 2);

        reg_name_del_proc(n, TEST_PID + 1);

        reg_name_del_proc(n, TEST_PID);

        if (n->procs.len != 0) {
                printf("Procs list not cleared.\n");
                goto fail;
        }

        if (n->active.len != 0) {
                printf("Active list not cleared.\n");
                goto fail;
        }

        reg_name_destroy(n);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int name_test(int     argc,
              char ** argv)
{
        int rc = 0;

        (void) argc;
        (void) argv;

        rc |= test_reg_name_create();
        rc |= test_reg_name_add_proc();
        rc |= test_reg_name_add_prog();
        rc |= test_reg_name_add_active(LB_RR);
        rc |= test_reg_name_add_active(LB_SPILL);

        return rc;
}
