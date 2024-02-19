/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Test of the hashing functions
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

#include <ouroboros/hash.h>
#include <ouroboros/test.h>

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

/*
 * Test vectors calculated at
 * https://www.lammertbies.nl/comm/info/crc-calculation.html
 */

struct vec_entry {
        char * in;
        char * out;
};

static int test_crc32(void)
{
        int ret = 0;

        struct vec_entry vec [] = {
                { "0",         "f4dbdf21" },
                { "123456789", "cbf43926" },
                { "987654321", "015f0201" },
                { NULL,        NULL       }
        };

        struct vec_entry * cur = vec;

        TEST_START();

        while (cur->in != NULL) {
                uint8_t crc[4];
                char    res[9];

                str_hash(HASH_CRC32, crc, cur->in);

                sprintf(res, HASH_FMT32, HASH_VAL32(crc));
                if (strcmp(res, cur->out) != 0) {
                        printf("Hash failed %s != %s.\n", res, cur->out);
                        ret |= -1;
                }

                ++cur;
        }

        TEST_END(ret);

        return ret;
}

static int test_md5(void)
{
        int ret = 0;

        struct vec_entry vec [] = {{
                "abc",
                "900150983cd24fb0d6963f7d28e17f72"
        }, {
                "The quick brown fox jumps over the lazy dog",
                "9e107d9d372bb6826bd81d3542a419d6"
        }, {
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "8215ef0796a20bcaaae116d3876c664a"
        }, {
                NULL,
                NULL
        }};

        struct vec_entry * cur = vec;

        TEST_START();


        while (cur->in != NULL) {
                uint8_t md5[16];
                char    res[33];

                str_hash(HASH_MD5, md5, cur->in);

                sprintf(res, HASH_FMT128, HASH_VAL128(md5));
                if (strcmp(res, cur->out) != 0) {
                        printf("Hash failed %s != %s.\n", res, cur->out);
                        ret |= -1;
                }

                ++cur;
        }

        TEST_END(ret);

        return ret;
}

static int test_sha3(void)
{
        int ret = 0;

        uint8_t sha3[64];
        char    res[129];

        char * in = "abc";

        char * out =
                "e642824c3f8cf24ad09234ee7d3c766f"
                "c9a3a5168d0c94ad73b46fdf";

        TEST_START();

        str_hash(HASH_SHA3_224, sha3, in);

        sprintf(res, HASH_FMT224, HASH_VAL224(sha3));
        if (strcmp(res, out) != 0) {
                printf("SHA3-224 failed %s != %s", res, out);
                ret |= -1;
        }

        out =
                "3a985da74fe225b2045c172d6bd390bd"
                "855f086e3e9d525b46bfe24511431532";

        str_hash(HASH_SHA3_256, sha3, in);

        sprintf(res, HASH_FMT256, HASH_VAL256(sha3));
        if (strcmp(res, out) != 0) {
                printf("SHA3-256 failed %s != %s.\n", res, out);
                ret |= -1;
        }

        out =
                "ec01498288516fc926459f58e2c6ad8d"
                "f9b473cb0fc08c2596da7cf0e49be4b2"
                "98d88cea927ac7f539f1edf228376d25";

        str_hash(HASH_SHA3_384, sha3, in);

        sprintf(res, HASH_FMT384, HASH_VAL384(sha3));
        if (strcmp(res, out) != 0) {
                printf("SHA3-384failed %s != %s.'n", res, out);
                ret |= -1;
        }

        out =
                "b751850b1a57168a5693cd924b6b096e"
                "08f621827444f70d884f5d0240d2712e"
                "10e116e9192af3c91a7ec57647e39340"
                "57340b4cf408d5a56592f8274eec53f0";

        str_hash(HASH_SHA3_512, sha3, in);

        sprintf(res, HASH_FMT512, HASH_VAL512(sha3));
        if (strcmp(res, out) != 0) {
                printf("SHA3-512 failed %s != %s.\n", res, out);
                ret |= -1;
        }

        TEST_END(ret);

        return ret;
}

int hash_test(int     argc,
              char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_crc32();

        ret |= test_md5();

        ret |= test_sha3();

        return ret;
}
