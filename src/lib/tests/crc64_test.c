/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the CRC-64/NVMe function
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

#include <ouroboros/crc64.h>
#include <ouroboros/random.h>

#include <test/test.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Reference impl, internal to libouroboros-common. */
extern void crc64_nvme_table(uint64_t *   crc,
                             const void * buf,
                             size_t       len);

/* reveng-catalog smoke vectors plus a 16-byte fold-boundary check. */
static int test_crc64_nvme_basic(void)
{
        uint64_t crc;

        TEST_START();

        crc = 0;
        crc64_nvme(&crc, "", 0);
        if (crc != 0x0000000000000000ULL)
                goto fail;

        crc = 0;
        crc64_nvme(&crc, "123456789", 9);
        if (crc != 0xae8b14860a799888ULL)
                goto fail;

        crc = 0;
        crc64_nvme(&crc, "0123456789abcdef", 16);
        if (crc != 0x091485ca7018730eULL)
                goto fail;

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

#if defined(HAVE_PCLMUL) || defined(HAVE_PMULL)
/* Cross-check the accelerated dispatcher path against the byte-table. */
static int test_crc64_nvme_random(void)
{
        static const size_t lens[] = {
                0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128,
                129, 255, 256, 257, 1023, 1024, 1025, 4096
        };
        uint8_t  buf[4096];
        size_t   i;
        uint64_t ref;
        uint64_t got;

        TEST_START();

        if (random_buffer(buf, sizeof(buf)) < 0) {
                printf("Failed to generate random data.\n");
                goto fail;
        }

        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
                ref = 0;
                crc64_nvme_table(&ref, buf, lens[i]);

                got = 0;
                crc64_nvme(&got, buf, lens[i]);

                if (ref == got)
                        continue;

                printf("Mismatch at len=%zu: table=0x%016lx disp=0x%016lx\n",
                        lens[i],
                        (unsigned long) ref,
                        (unsigned long) got);
                goto fail;
        }

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
#endif
}

int crc64_test(int     argc,
               char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_crc64_nvme_basic();
#if defined(HAVE_PCLMUL) || defined(HAVE_PMULL)
        ret |= test_crc64_nvme_random();
#endif
        return ret;
}
