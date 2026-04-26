/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the CRC-8/AUTOSAR function
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

#include <ouroboros/crc8.h>

#include <test/test.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* reveng-catalog smoke vectors. */
static int test_crc8_autosar_basic(void)
{
        uint8_t crc;

        TEST_START();

        crc = 0;
        crc8_autosar(&crc, "", 0);
        if (crc != 0x00)
                goto fail;

        crc = 0;
        crc8_autosar(&crc, "123456789", 9);
        if (crc != 0xdf)
                goto fail;

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int crc8_test(int     argc,
              char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_crc8_autosar_basic();
        return ret;
}
