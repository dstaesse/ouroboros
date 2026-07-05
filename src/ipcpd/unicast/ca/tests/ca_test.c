/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Unit tests for the congestion-avoidance interface
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

#include "config.h"

#include "ca.h"

#include <test/test.h>

#define ADDR_A 0x1111ULL
#define ADDR_B 0x2222ULL

static const struct {
        enum pol_cong_avoid pol;
        const char *        name;
} ca_pols[] = {
        { CA_NONE,   "none"   },
        { CA_MB_ECN, "mb-ecn" }
};

#define CA_POLS (sizeof(ca_pols) / sizeof(ca_pols[0]))

static int test_ca_init_fini(enum pol_cong_avoid pol,
                             const char *        name)
{
        TEST_START("(%s)", name);

        if (ca_init(pol) < 0) {
                printf("Failed to init ca for %s.\n", name);
                goto fail;
        }

        ca_fini();

        TEST_SUCCESS("(%s)", name);

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL("(%s)", name);
        return TEST_RC_FAIL;
}

static int test_ca_init_fini_all(void)
{
        int    ret = 0;
        size_t i;

        for (i = 0; i < CA_POLS; i++)
                ret |= test_ca_init_fini(ca_pols[i].pol, ca_pols[i].name);

        return ret;
}

static int test_ca_init_invalid(void)
{
        TEST_START();

        if (ca_init(CA_INVALID) == 0) {
                printf("Init accepted an invalid policy.\n");
                ca_fini();
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ca_ctx_share(enum pol_cong_avoid pol,
                             const char *        name)
{
        void * c1;
        void * c2;

        TEST_START("(%s)", name);

        if (ca_init(pol) < 0) {
                printf("Failed to init ca for %s.\n", name);
                goto fail;
        }

        c1 = ca_ctx_get(ADDR_A, QOS_CUBE_BE);
        if (c1 == NULL) {
                printf("Failed to get ctx.\n");
                goto fail_init;
        }

        c2 = ca_ctx_get(ADDR_A, QOS_CUBE_BE);
        if (c2 == NULL) {
                printf("Failed to get second ctx.\n");
                goto fail_c1;
        }

#ifdef IPCP_CA_PER_FLOW
        if (c1 == c2) {
                printf("Per-flow build shared a ctx across flows.\n");
                goto fail_c2;
        }
#else
        if (c1 != c2) {
                printf("Aggregate build did not share ctx per (addr, qc).\n");
                goto fail_c2;
        }
#endif
        ca_ctx_put(c2);
        ca_ctx_put(c1);

        ca_fini();

        TEST_SUCCESS("(%s)", name);

        return TEST_RC_SUCCESS;
 fail_c2:
        ca_ctx_put(c2);
 fail_c1:
        ca_ctx_put(c1);
 fail_init:
        ca_fini();
 fail:
        TEST_FAIL("(%s)", name);
        return TEST_RC_FAIL;
}

static int test_ca_ctx_share_all(void)
{
        int    ret = 0;
        size_t i;

        for (i = 0; i < CA_POLS; i++)
                ret |= test_ca_ctx_share(ca_pols[i].pol, ca_pols[i].name);

        return ret;
}

static int test_ca_ctx_distinct(void)
{
        void * a_be;
        void * b_be;
        void * a_video;

        TEST_START();

        if (ca_init(CA_NONE) < 0) {
                printf("Failed to init ca.\n");
                goto fail;
        }

        a_be = ca_ctx_get(ADDR_A, QOS_CUBE_BE);
        if (a_be == NULL) {
                printf("Failed to get ctx.\n");
                goto fail_init;
        }

        b_be = ca_ctx_get(ADDR_B, QOS_CUBE_BE);
        if (b_be == NULL) {
                printf("Failed to get ctx.\n");
                goto fail_a_be;
        }

        a_video = ca_ctx_get(ADDR_A, QOS_CUBE_VIDEO);
        if (a_video == NULL) {
                printf("Failed to get ctx.\n");
                goto fail_b_be;
        }

        if (a_be == b_be) {
                printf("Distinct addresses shared a ctx.\n");
                goto fail_a_video;
        }

        if (a_be == a_video) {
                printf("Distinct qos cubes shared a ctx.\n");
                goto fail_a_video;
        }

        ca_ctx_put(a_video);
        ca_ctx_put(b_be);
        ca_ctx_put(a_be);

        ca_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_a_video:
        ca_ctx_put(a_video);
 fail_b_be:
        ca_ctx_put(b_be);
 fail_a_be:
        ca_ctx_put(a_be);
 fail_init:
        ca_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Refcount survival is an aggregate-only property. */
#ifndef IPCP_CA_PER_FLOW
static int test_ca_ctx_refcount(void)
{
        void * c1;
        void * c3;

        TEST_START();

        if (ca_init(CA_NONE) < 0) {
                printf("Failed to init ca.\n");
                goto fail;
        }

        c1 = ca_ctx_get(ADDR_A, QOS_CUBE_BE); /* refs = 1 */
        if (c1 == NULL) {
                printf("Failed to get ctx.\n");
                goto fail_init;
        }

        if (ca_ctx_get(ADDR_A, QOS_CUBE_BE) == NULL) { /* refs = 2 */
                printf("Failed to get second ref.\n");
                goto fail_c1;
        }

        ca_ctx_put(c1); /* refs = 1 */

        c3 = ca_ctx_get(ADDR_A, QOS_CUBE_BE);  /* refs = 2 */
        if (c3 == NULL) {
                printf("Failed to get third ref.\n");
                goto fail_c1;
        }

        if (c3 != c1) {
                printf("Refcounted ctx freed while still referenced.\n");
                goto fail_c3;
        }

        ca_ctx_put(c3);
        ca_ctx_put(c1);

        ca_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_c3:
        ca_ctx_put(c3);
 fail_c1:
        ca_ctx_put(c1);
 fail_init:
        ca_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* The last put frees the interned ctx; a fresh get recreates it. */
static int test_ca_ctx_recreate(void)
{
        void * c1;
        void * c2;
        void * c3;

        TEST_START();

        if (ca_init(CA_NONE) < 0) {
                printf("Failed to init ca.\n");
                goto fail;
        }

        c1 = ca_ctx_get(ADDR_A, QOS_CUBE_BE);  /* refs = 1 */
        if (c1 == NULL) {
                printf("Failed to get ctx.\n");
                goto fail_init;
        }

        ca_ctx_put(c1);  /* refs = 0: freed and de-interned */

        c2 = ca_ctx_get(ADDR_A, QOS_CUBE_BE);  /* fresh entry */
        if (c2 == NULL) {
                printf("Get after release did not recreate.\n");
                goto fail_init;
        }

        c3 = ca_ctx_get(ADDR_A, QOS_CUBE_BE);  /* refs = 2: shares */
        if (c3 == NULL) {
                printf("Failed to share recreated ctx.\n");
                goto fail_c2;
        }

        if (c3 != c2) {
                printf("Recreated ctx did not intern.\n");
                goto fail_c3;
        }

        ca_ctx_put(c3);
        ca_ctx_put(c2);

        ca_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_c3:
        ca_ctx_put(c3);
 fail_c2:
        ca_ctx_put(c2);
 fail_init:
        ca_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* ca_fini drains a ctx a flow left interned, with no leak. */
static int test_ca_fini_drains(void)
{
        void * c1;
        void * c2;

        TEST_START();

        if (ca_init(CA_NONE) < 0) {
                printf("Failed to init ca.\n");
                goto fail;
        }

        c1 = ca_ctx_get(ADDR_A, QOS_CUBE_BE);  /* refs = 1 */
        if (c1 == NULL) {
                printf("Failed to get ctx.\n");
                goto fail_init;
        }

        c2 = ca_ctx_get(ADDR_A, QOS_CUBE_BE);  /* refs = 2 */
        if (c2 == NULL) {
                printf("Failed to get second ref.\n");
                goto fail_init;
        }

        /* Leave both refs live: ca_fini must drain and free the ctx. */
        ca_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        ca_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}
#endif /* !IPCP_CA_PER_FLOW */

int ca_test(int     argc,
            char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_ca_init_fini_all();
        ret |= test_ca_init_invalid();
        ret |= test_ca_ctx_share_all();
        ret |= test_ca_ctx_distinct();
#ifndef IPCP_CA_PER_FLOW
        ret |= test_ca_ctx_refcount();
        ret |= test_ca_ctx_recreate();
        ret |= test_ca_fini_drains();
#endif
        return ret;
}
