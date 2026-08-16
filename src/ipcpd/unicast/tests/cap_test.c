/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Unit tests for link capacity codes
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

#include "cap.c"

#include <test/test.h>

/* Exact roundtrip holds for codes >= 32 (rates >= 256 B/s). */
static int test_cap_codec_roundtrip(void)
{
        unsigned c;

        TEST_START();

        for (c = 32; c <= 255; c++) {
                if (cap_enc(cap_dec((uint8_t) c)) != c) {
                        printf("Code %u does not roundtrip.\n", c);
                        goto fail;
                }

                if (cap_dec((uint8_t) c) <= cap_dec((uint8_t) (c - 1))) {
                        printf("Decode not monotone at %u.\n", c);
                        goto fail;
                }
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_codec_bounds(void)
{
        TEST_START();

        if (cap_enc(0) != 0 || cap_dec(0) != 0) {
                printf("Zero is not unknown.\n");
                goto fail;
        }

        if (cap_enc(1) != 1) {
                printf("Rate 1 encoded as %u.\n", cap_enc(1));
                goto fail;
        }

        if (cap_enc(UINT64_MAX) != 255) {
                printf("Max rate encoded as %u.\n", cap_enc(UINT64_MAX));
                goto fail;
        }

        if (cap_dec(255) <= cap_dec(254)) {
                printf("Top code does not decode.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_min(void)
{
        TEST_START();

        if (cap_min(0, 42) != 42 || cap_min(42, 0) != 42) {
                printf("Unknown not skipped in min.\n");
                goto fail;
        }

        if (cap_min(0, 0) != 0) {
                printf("Two unknowns not unknown.\n");
                goto fail;
        }

        if (cap_min(97, 42) != 42 || cap_min(42, 97) != 42) {
                printf("Min not taken.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_cap_stamp(void)
{
        uint8_t pci;

        TEST_START();

        pci = 42;

        cap_stamp(&pci, 0);

        if (pci != 42) {
                printf("Unknown own code overwrote the byte.\n");
                goto fail;
        }

        pci = 0;

        cap_stamp(&pci, 97);

        if (pci != 97) {
                printf("Own code not written into unknown.\n");
                goto fail;
        }

        pci = 97;

        cap_stamp(&pci, 42);

        if (pci != 42) {
                printf("Lower own code did not lower the byte.\n");
                goto fail;
        }

        pci = 42;

        cap_stamp(&pci, 97);

        if (pci != 42) {
                printf("Higher own code raised the byte.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int cap_test(int     argc,
             char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_cap_codec_roundtrip();
        ret |= test_cap_codec_bounds();
        ret |= test_cap_min();
        ret |= test_cap_stamp();

        return ret;
}
