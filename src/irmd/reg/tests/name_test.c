/*
 * Ouroboros - Copyright (C) 2016 - 2024
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

        n = reg_name_create(&info);
        if (n == NULL) {
                printf("Failed to create name %s.\n", info.name);
                goto fail;
        }

        reg_name_destroy(n);

        return 0;
 fail:
        return -1;
}

static int test_reg_name_add_proc(void)
{
        struct reg_name * n;
        struct name_info  info = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR,
        };

        n = reg_name_create(&info);
        if (n == NULL) {
                printf("Failed to create name %s.\n", info.name);
                goto fail;
        }

        if (reg_name_add_proc(n, TEST_PID) < 0) {
                printf("Failed to add proc.\n");
                goto fail;
        }

        if (n->n_procs != 1) {
                printf("n_procs not updated.\n");
                goto fail;
        }

        if (!reg_name_has_proc(n, TEST_PID)) {
                printf("Proc not found.\n");
                goto fail;
        }

        reg_name_del_proc(n, TEST_PID);

        if (n->n_procs != 0) {
                printf("n_procs not updated.\n");
                goto fail;
        }

        reg_name_destroy(n);

        return 0;
 fail:
        return -1;
}

static int test_reg_name_add_prog(void)
{
        struct reg_name * n;
        struct name_info  info = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR,
        };

        char * exec[] = { TEST_PROG, "--argswitch", "argvalue", NULL};

        n = reg_name_create(&info);
        if (n == NULL) {
                printf("Failed to create name %s.\n", info.name);
                goto fail;
        }

        if (reg_name_add_prog(n, exec) < 0) {
                printf("Failed to add prog.\n");
                goto fail;
        }

        if (n->n_progs != 1) {
                printf("n_progs not updated.\n");
                goto fail;
        }

        if (!reg_name_has_prog(n, TEST_PROG)) {
                printf("Prog not found.\n");
                goto fail;
        }

        reg_name_del_prog(n, TEST_PROG);

        if (n->n_progs != 0) {
                printf("n_progs not updated.\n");
                goto fail;
        }

        reg_name_destroy(n);

        return 0;
 fail:
        return -1;
}

static int test_reg_name_add_active(enum pol_balance lb)
{
        struct reg_name * n;
        pid_t             pid;
        struct name_info  info = {
                .name   = TEST_NAME,
                .pol_lb = lb,
        };

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

        if (n->n_active != 1) {
                printf("n_active not updated.\n");
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

        if (n->n_procs != 3) {
                printf("n_procs not updated.\n");
                goto fail;
        }

        if (n->n_active != 4) {
                printf("n_active not updated.\n");
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

        if (n->n_procs != 0) {
                printf("n_procs not updated.\n");
                goto fail;
        }

        if (n->n_active != 0) {
                printf("n_active not updated.\n");
                goto fail;
        }

        reg_name_destroy(n);

        return 0;
 fail:
        return -1;
}


int name_test(int     argc,
              char ** argv)
{
        int res = 0;

        (void) argc;
        (void) argv;

        res |= test_reg_name_create();

        res |= test_reg_name_add_proc();

        res |= test_reg_name_add_prog();

        res |= test_reg_name_add_active(LB_RR);

        res |= test_reg_name_add_active(LB_SPILL);

        return res;
}