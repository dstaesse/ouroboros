/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Programs - Unit Tests
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

#include "../prog.c"

#define TEST_PROG "usr/bin/testprog"


static int test_reg_prog_create(void)
{
        struct reg_prog * prog;
        struct prog_info  info = {
                .name = TEST_PROG
        };

        prog = reg_prog_create(&info);
        if (prog == NULL) {
                printf("Failed to create prog.\n");
                goto fail;
        }

        reg_prog_destroy(prog);

        return 0;
 fail:
        return -1;
}

static int test_reg_prog_add_name(void)
{
        struct reg_prog * prog;
        struct prog_info  info = {
                .name = TEST_PROG
        };

        char * name = "testname";

        prog = reg_prog_create(&info);
        if (prog == NULL) {
                printf("Failed to create prog.\n");
                goto fail;
        }

        if (reg_prog_add_name(prog, name) < 0) {
                printf("Failed to add name.");
                goto fail;
        }

        if (prog->n_names != 1) {
                printf("n_names not updated.\n");
                goto fail;
        }

        if (!reg_prog_has_name(prog, name)) {
                printf("Name not found.\n");
                goto fail;
        }

        reg_prog_del_name(prog, name);

        if (prog->n_names != 0) {
                printf("n_names not updated.\n");
                goto fail;
        }

        reg_prog_destroy(prog);

        return 0;
 fail:
        return -1;
}

int prog_test(int     argc,
              char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_reg_prog_create();

        ret |= test_reg_prog_add_name();

        return ret;
}