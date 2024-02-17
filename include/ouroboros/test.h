/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Test macros
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_TEST_H
#define OUROBOROS_LIB_TEST_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST_START()                                           \
        do {                                                   \
                printf("%s started.\n", __func__);             \
                fflush(stdout);                                \
        } while(0)
#define TEST_SUCCESS()                                         \
        do {                                                   \
                printf("%s succeeded.\n", __func__);           \
                fflush(stdout);                                \
        } while(0)

#define TEST_FAIL()                                            \
        do {                                                   \
                printf("%s failed.\n", __func__);              \
                fflush(stdout);                                \
        } while(0)

static int __attribute__((unused)) test_assert_fail(int(* testfunc)(void))
{
        pid_t pid;
        int   wstatus;

        pid = fork();
        if (pid == -1) {
                printf("Failed to fork: %s.\n", strerror(errno));
                return -1;
        }

        if (pid == 0)
                return testfunc(); /* should abort */

        waitpid(pid, &wstatus, 0);
#ifdef CONFIG_OUROBOROS_DEBUG
        if (WIFSIGNALED(wstatus) && wstatus == 134)
                return 0;

        printf("Process did not abort, status: %d.\n", wstatus);
#else
        if (WIFEXITED(wstatus) && wstatus == 0)
                return 0;

        printf("Process did not exit, status: %d.\n", wstatus);
#endif

        return -1;
}

#endif /* OUROBOROS_LIB_TEST_H */