/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Test of the MD5 function
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

#include <ouroboros/md5.h>

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

static char * hash_to_str(uint8_t * hash,
                          size_t    len)
{
        size_t i;

        char * HEX = "0123456789abcdef";
        char * str;

        str = malloc(len * 2 + 1);
        if (str == NULL)
                return NULL;

        for (i = 0; i < len; ++i) {
                str[i * 2]     = HEX[(hash[i] & 0xF0) >> 4];
                str[i * 2 + 1] = HEX[hash[i] & 0x0F];
        }

        str[2 * i] = '\0';

        return str;
}

static int check_hash(char *    check,
                      uint8_t * hash,
                      size_t    len)
{
        char * res;
        int ret;

        assert(hash);
        assert(check);
        assert(strlen(check));

        res = hash_to_str(hash, len);
        if (res == NULL) {
                printf("Out of memory.\n");
                return -1;
        }

        ret = strcmp(res, check);

        printf("hash  : %s\n", res);
        printf("check : %s\n\n", check);

        free(res);

        return ret;

}

int md5_test(int     argc,
             char ** argv)
{
        struct md5_ctx ctx;

        /* Storage for result. */
        uint8_t res[MD5_HASH_LEN];

        /* SHA3 test vectors */
        char * str1_inp = "abc";

        char * str1_md5 = "900150983cd24fb0d6963f7d28e17f72";

        char * str2_inp = "The quick brown fox jumps over the lazy dog";

        char * str2_md5 = "9e107d9d372bb6826bd81d3542a419d6";

        char * str3_inp =
                "abcdbcdecdefdefgefghfghighijhijk"
                "ijkljklmklmnlmnomnopnopq";

        char * str3_inp2 =
                " abcdbcdecdefdefgefghfghighijhijk"
                "ijkljklmklmnlmnomnopnopq";

        char * str3_md5 = "8215ef0796a20bcaaae116d3876c664a";

        (void) argc;
        (void) argv;

        /* 1st input string. */
        printf("test: %s.\n\n", str1_inp);

        rhash_md5_init(&ctx);
        rhash_md5_update(&ctx, str1_inp, strlen(str1_inp));
        rhash_md5_final(&ctx, res);

        if (check_hash(str1_md5, res, MD5_HASH_LEN))
                return -1;

        /* 2nd input string. */
        printf("test: <empty string>.\n\n");

        rhash_md5_init(&ctx);
        rhash_md5_update(&ctx, str2_inp, strlen(str2_inp));
        rhash_md5_final(&ctx, res);

        if (check_hash(str2_md5, res, MD5_HASH_LEN))
                return -1;

        /* 3rd input string */
        printf("test: %s.\n\n", str3_inp);

        rhash_md5_init(&ctx);
        rhash_md5_update(&ctx, str3_inp, strlen(str3_inp));
        rhash_md5_final(&ctx, res);

        if (check_hash(str3_md5, res, MD5_HASH_LEN))
                return -1;

        /* unaligned 3rd input string. */
        printf("test: %s.\n\n", str3_inp2 + 1);

        rhash_md5_init(&ctx);
        rhash_md5_update(&ctx, str3_inp2 + 1, strlen(str3_inp2 + 1));
        rhash_md5_final(&ctx, res);

        if (check_hash(str3_md5, res, MD5_HASH_LEN))
                return -1;

        return 0;
}
