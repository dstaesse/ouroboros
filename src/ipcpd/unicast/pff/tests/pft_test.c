/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the hash table
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

#include "pft.c"

#include <test/test.h>

#include <stdio.h>

#define TBL_SIZE 256
#define INT_TEST 4

/* Next hops used by the del_fd tests. */
#define FD_GONE  7
#define FD_KEEP  8
#define FD_OTHER 9

static int pft_add(struct pft * pft,
                   uint64_t     dst,
                   const int *  fds,
                   size_t       len)
{
        int *  blk;
        size_t i;

        blk = malloc(sizeof(*blk) * len);
        if (blk == NULL)
                return -1;

        for (i = 0; i < len; i++)
                blk[i] = fds[i];

        if (pft_insert(pft, dst, blk, len)) {
                free(blk);
                return -1;
        }

        return 0;
}

static int test_pft_create_destroy(void)
{
        struct pft * pft;

        TEST_START();

        pft = pft_create(TBL_SIZE);
        if (pft == NULL) {
                printf("Failed to create.\n");
                goto fail;
        }

        pft_destroy(pft);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_pft_insert_lookup(void)
{
        struct pft * pft;
        int *        j;
        size_t       len;
        int          i;

        TEST_START();

        pft = pft_create(TBL_SIZE);
        if (pft == NULL) {
                printf("Failed to create.\n");
                goto fail;
        }

        for (i = 0; i < TBL_SIZE + INT_TEST + 2; i++) {
                if (pft_add(pft, i, &i, 1)) {
                        printf("Failed to insert.\n");
                        goto fail_pft;
                }
        }

        if (pft_lookup(pft, INT_TEST, &j, &len)) {
                printf("Failed to lookup.\n");
                goto fail_pft;
        }

        if (*j != INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       INT_TEST, *j);
                goto fail_pft;
        }

        if (pft_lookup(pft, TBL_SIZE + INT_TEST, &j, &len)) {
                printf("Failed to lookup on a shared bucket.\n");
                goto fail_pft;
        }

        if (*j != TBL_SIZE + INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       TBL_SIZE + INT_TEST, *j);
                goto fail_pft;
        }

        pft_destroy(pft);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_pft:
        pft_destroy(pft);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_pft_delete(void)
{
        struct pft * pft;
        int *        j;
        size_t       len;
        int          i;

        TEST_START();

        pft = pft_create(TBL_SIZE);
        if (pft == NULL) {
                printf("Failed to create.\n");
                goto fail;
        }

        for (i = 0; i < TBL_SIZE + INT_TEST + 2; i++) {
                if (pft_add(pft, i, &i, 1)) {
                        printf("Failed to insert.\n");
                        goto fail_pft;
                }
        }

        if (pft_delete(pft, INT_TEST)) {
                printf("Failed to delete.\n");
                goto fail_pft;
        }

        if (pft_lookup(pft, INT_TEST, &j, &len) == 0) {
                printf("Failed to delete properly.\n");
                goto fail_pft;
        }

        if (pft_lookup(pft, TBL_SIZE + INT_TEST, &j, &len)) {
                printf("Failed to lookup after deletion.\n");
                goto fail_pft;
        }

        if (*j != TBL_SIZE + INT_TEST) {
                printf("Lookup returned wrong value (%d != %d).\n",
                       TBL_SIZE + INT_TEST, *j);
                goto fail_pft;
        }

        pft_destroy(pft);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_pft:
        pft_destroy(pft);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_pft_del_fd_sole(void)
{
        struct pft * pft;
        int *        j;
        size_t       len;
        int          fds[] = {FD_GONE};

        TEST_START();

        pft = pft_create(TBL_SIZE);
        if (pft == NULL) {
                printf("Failed to create.\n");
                goto fail;
        }

        if (pft_add(pft, INT_TEST, fds, 1)) {
                printf("Failed to insert.\n");
                goto fail_pft;
        }

        pft_del_fd(pft, FD_GONE);

        if (pft_lookup(pft, INT_TEST, &j, &len) == 0) {
                printf("Route without a next hop survived.\n");
                goto fail_pft;
        }

        pft_destroy(pft);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_pft:
        pft_destroy(pft);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_pft_del_fd_shared(void)
{
        struct pft * pft;
        int *        j;
        size_t       len;
        int          fds[] = {FD_KEEP, FD_GONE, FD_OTHER};

        TEST_START();

        pft = pft_create(TBL_SIZE);
        if (pft == NULL) {
                printf("Failed to create.\n");
                goto fail;
        }

        if (pft_add(pft, INT_TEST, fds, 3)) {
                printf("Failed to insert.\n");
                goto fail_pft;
        }

        pft_del_fd(pft, FD_GONE);

        if (pft_lookup(pft, INT_TEST, &j, &len)) {
                printf("Route with next hops left was dropped.\n");
                goto fail_pft;
        }

        if (len != 2) {
                printf("Expected 2 next hops, got %zu.\n", len);
                goto fail_pft;
        }

        if (j[0] != FD_KEEP || j[1] != FD_OTHER) {
                printf("Next hops not preserved in order (%d, %d).\n",
                       j[0], j[1]);
                goto fail_pft;
        }

        pft_destroy(pft);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_pft:
        pft_destroy(pft);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_pft_del_fd_untouched(void)
{
        struct pft * pft;
        int *        j;
        size_t       len;
        int          fds[] = {FD_KEEP};

        TEST_START();

        pft = pft_create(TBL_SIZE);
        if (pft == NULL) {
                printf("Failed to create.\n");
                goto fail;
        }

        if (pft_add(pft, INT_TEST, fds, 1)) {
                printf("Failed to insert.\n");
                goto fail_pft;
        }

        pft_del_fd(pft, FD_GONE);

        if (pft_lookup(pft, INT_TEST, &j, &len)) {
                printf("Unrelated route was dropped.\n");
                goto fail_pft;
        }

        if (len != 1 || *j != FD_KEEP) {
                printf("Unrelated route was modified.\n");
                goto fail_pft;
        }

        pft_destroy(pft);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_pft:
        pft_destroy(pft);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int pft_test(int     argc,
             char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_pft_create_destroy();
        ret |= test_pft_insert_lookup();
        ret |= test_pft_delete();
        ret |= test_pft_del_fd_sole();
        ret |= test_pft_del_fd_shared();
        ret |= test_pft_del_fd_untouched();

        return ret;
}
