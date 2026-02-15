/*
 * Ouroboros - Copyright (C) 2016 - 2026
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
#include <sys/types.h>
#include <sys/resource.h>

#define TEST_RC_SUCCESS  0
#define TEST_RC_SKIP     1
#define TEST_RC_FAIL    -1

#define TEST_START(...)                                                       \
        do {                                                                  \
                printf("%s", __func__);                                       \
                if (sizeof(#__VA_ARGS__) > 1)                                 \
                        printf(" " __VA_ARGS__);                              \
                printf(" started.\n");                                        \
                fflush(stdout);                                               \
        } while (0)

#define TEST_SUCCESS(...)                                                     \
        do {                                                                  \
                printf("\x1b[32m%s", __func__);                               \
                if (sizeof(#__VA_ARGS__) > 1)                                 \
                        printf(" " __VA_ARGS__);                              \
                printf(" succeeded.\x1b[0m\n");                               \
                fflush(stdout);                                               \
        } while (0)

#define TEST_SKIPPED()                                                        \
        do {                                                                  \
                printf("\x1b[33m%s skipped.\x1b[0m\n", __func__);             \
                fflush(stdout);                                               \
        } while (0)

#define TEST_FAIL(...)                                                        \
        do {                                                                  \
                printf("\x1b[31m%s", __func__);                               \
                if (sizeof(#__VA_ARGS__) > 1)                                 \
                        printf(" " __VA_ARGS__);                              \
                printf(" failed.\x1b[0m\n");                                  \
                fflush(stdout);                                               \
        } while (0)

#define TEST_END(result)                                                      \
        do { if (result == 0) TEST_SUCCESS(); else TEST_FAIL(); } while (0)

static int __attribute__((unused)) test_assert_fail(int(* testfunc)(void))
{
        pid_t pid;
        int   wstatus;

        pid = fork();
        if (pid == -1) {
                printf("Failed to fork: %s.\n", strerror(errno));
                return TEST_RC_FAIL;
        }

        if (pid == 0) {
#ifdef DISABLE_TESTS_CORE_DUMPS
                struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
                setrlimit(RLIMIT_CORE, &rl);
#endif
                return testfunc(); /* should abort */
        }

        waitpid(pid, &wstatus, 0);
#ifdef CONFIG_OUROBOROS_DEBUG
        if (WIFSIGNALED(wstatus) && (wstatus == 134 || wstatus == 6))
                return TEST_RC_SUCCESS;

        printf("Process did not abort, status: %d.\n", wstatus);
#else
        if (WIFEXITED(wstatus) && wstatus == 0)
                return TEST_RC_SUCCESS;

        printf("Process did not exit, status: %d.\n", wstatus);
#endif

        return TEST_RC_FAIL;
}

#endif /* OUROBOROS_LIB_TEST_H */
