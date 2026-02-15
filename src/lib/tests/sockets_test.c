/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Tests for socket.c
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

#include <ouroboros/sockets.h>
#include <test/test.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define TEST_PID              1234
#define TEST_PID_STR          "1234"
#define TEST_SERVER_PATH      "/tmp/test.sock"
#define TEST_SERVER_PREFIX    "/tmp/ouroboros/test."
#define TEST_SOCK_PATH_PREFIX "var/run/ouroboros/test."

static int test_sock_path(void)
{
        char * path;
        char * exp = TEST_SOCK_PATH_PREFIX TEST_PID_STR SOCK_PATH_SUFFIX;

        TEST_START();

        path = sock_path(TEST_PID, TEST_SOCK_PATH_PREFIX);
        if (path == NULL) {
                printf("Path is NULL.\n");
                goto fail_path;
        }

        if (strcmp(path, exp) != 0) {
                printf("Expected path '%s', got '%s'.\n", exp, path);
                goto fail_cmp;
        }

        free(path);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
 fail_cmp:
        free(path);
 fail_path:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_server_socket_open(void)
{
        int sockfd;

        TEST_START();

        sockfd = server_socket_open(TEST_SERVER_PATH);
        if (sockfd < 0) {
                printf("Failed to open server socket.\n");
                goto fail_sock;
        }

        close(sockfd);

        unlink(TEST_SERVER_PATH);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
 fail_sock:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int sockets_test(void)
{
        int ret = 0;

        ret |= test_sock_path();
        ret |= test_server_socket_open();

        return ret;
}
