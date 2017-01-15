/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Test of the CRC32 function
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/crc32.h>

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

/*
 * Test vectors calculated at
 * https://www.lammertbies.nl/comm/info/crc-calculation.html
 */

int crc32_test(int     argc,
               char ** argv)
{
        uint32_t crc = 0;
        int i = 0;

        (void) argc;
        (void) argv;

        crc32(&crc, "0", 1);
        if (crc != 0xF4DBDF21)
                return -1;

        crc = 0;

        crc32(&crc, "123456789", 9);
        if (crc != 0xCBF43926)
                return -1;

        crc = 0;

        crc32(&crc, "987654321", 9);
        if (crc != 0x015F0201)
                return -1;

        crc32(&crc, "123456789", 9);
        if (crc != 0x806B60E3)
                return -1;

        crc = 0;

        crc32(&crc, &i , 1);
        if (crc != 0xD202EF8D)
                return -1;

        return 0;
}
