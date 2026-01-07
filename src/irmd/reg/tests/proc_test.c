/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Processes - Unit Tests
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

#include "../proc.c"

#include <test/test.h>

#define TEST_PID  65534
#define TEST_PROG "usr/bin/testprog"

static int test_reg_proc_create_destroy(void)
{
        struct reg_proc * proc;
        struct proc_info  info = {
                .pid =  TEST_PID,
                .prog = TEST_PROG
        };

        TEST_START();

        proc = reg_proc_create(&info);
        if (proc == NULL) {
                printf("Failed to create proc.\n");
                goto fail;
        }

        reg_proc_destroy(proc);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_proc_add_name(void)
{
        struct reg_proc * proc;
        struct proc_info  info = {
                .pid  = TEST_PID,
                .prog = TEST_PROG
        };

        char * name = "testname";

        TEST_START();

        proc = reg_proc_create(&info);
        if (proc == NULL) {
                printf("Failed to create proc.\n");
                goto fail;
        }

        if (reg_proc_add_name(proc, name) < 0) {
                printf("Failed to add name.");
                goto fail;
        }

        if (proc->n_names != 1) {
                printf("n_names not updated.\n");
                goto fail;
        }

        if (!reg_proc_has_name(proc, name)) {
                printf("Name not found.\n");
                goto fail;
        }

        reg_proc_del_name(proc, name);

        if (proc->n_names != 0) {
                printf("n_names not updated.\n");
                goto fail;
        }

        reg_proc_destroy(proc);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int proc_test(int     argc,
              char ** argv)
{
        int res = 0;

        (void) argc;
        (void) argv;

        res |= test_reg_proc_create_destroy();
        res |= test_reg_proc_add_name();

        return res;
}
