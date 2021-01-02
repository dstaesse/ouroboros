/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Test of the SHA3 function
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

#include <ouroboros/sha3.h>

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

int sha3_test(int     argc,
              char ** argv)
{
        struct sha3_ctx ctx;

        /* Storage for result. */
        uint8_t res[SHA3_512_HASH_LEN];

        /* SHA3 test vectors */
        char * str1_inp = "abc";

        char * str1_224 =
                "e642824c3f8cf24ad09234ee7d3c766f"
                "c9a3a5168d0c94ad73b46fdf";
        char * str1_256 =
                "3a985da74fe225b2045c172d6bd390bd"
                "855f086e3e9d525b46bfe24511431532";
        char * str1_384 =
                "ec01498288516fc926459f58e2c6ad8d"
                "f9b473cb0fc08c2596da7cf0e49be4b2"
                "98d88cea927ac7f539f1edf228376d25";
        char * str1_512 =
                "b751850b1a57168a5693cd924b6b096e"
                "08f621827444f70d884f5d0240d2712e"
                "10e116e9192af3c91a7ec57647e39340"
                "57340b4cf408d5a56592f8274eec53f0";

        char * str2_inp = "";

        char * str2_224 =
                "6b4e03423667dbb73b6e15454f0eb1ab"
                "d4597f9a1b078e3f5b5a6bc7";
        char * str2_256 =
                "a7ffc6f8bf1ed76651c14756a061d662"
                "f580ff4de43b49fa82d80a4b80f8434a";
        char * str2_384 =
                "0c63a75b845e4f7d01107d852e4c2485"
                "c51a50aaaa94fc61995e71bbee983a2a"
                "c3713831264adb47fb6bd1e058d5f004";
        char * str2_512 =
                "a69f73cca23a9ac5c8b567dc185a756e"
                "97c982164fe25859e0d1dcc1475c80a6"
                "15b2123af1f5f94c11e3e9402c3ac558"
                "f500199d95b6d3e301758586281dcd26";

        char * str3_inp =
                "abcdbcdecdefdefgefghfghighijhijk"
                "ijkljklmklmnlmnomnopnopq";

        char * str3_224 =
                "8a24108b154ada21c9fd5574494479ba"
                "5c7e7ab76ef264ead0fcce33";
        char * str3_256 =
                "41c0dba2a9d6240849100376a8235e2c"
                "82e1b9998a999e21db32dd97496d3376";
        char * str3_384 =
                "991c665755eb3a4b6bbdfb75c78a492e"
                "8c56a22c5c4d7e429bfdbc32b9d4ad5a"
                "a04a1f076e62fea19eef51acd0657c22";
        char * str3_512 =
                "04a371e84ecfb5b8b77cb48610fca818"
                "2dd457ce6f326a0fd3d7ec2f1e91636d"
                "ee691fbe0c985302ba1b0d8dc78c0863"
                "46b533b49c030d99a27daf1139d6e75e";

        char * str4_inp =
                "abcdefghbcdefghicdefghijdefghijk"
                "efghijklfghijklmghijklmnhijklmno"
                "ijklmnopjklmnopqklmnopqrlmnopqrs"
                "mnopqrstnopqrstu";

        char * str4_inp2 =
                " abcdefghbcdefghicdefghijdefghijk"
                "efghijklfghijklmghijklmnhijklmno"
                "ijklmnopjklmnopqklmnopqrlmnopqrs"
                "mnopqrstnopqrstu";

        char * str4_224 =
                "543e6868e1666c1a643630df77367ae5"
                "a62a85070a51c14cbf665cbc";
        char * str4_256 =
                "916f6061fe879741ca6469b43971dfdb"
                "28b1a32dc36cb3254e812be27aad1d18";
        char * str4_384 =
                "79407d3b5916b59c3e30b09822974791"
                "c313fb9ecc849e406f23592d04f625dc"
                "8c709b98b43b3852b337216179aa7fc7";
        char * str4_512 =
                "afebb2ef542e6579c50cad06d2e578f9"
                "f8dd6881d7dc824d26360feebf18a4fa"
                "73e3261122948efcfd492e74e82e2189"
                "ed0fb440d187f382270cb455f21dd185";

        (void) argc;
        (void) argv;

        /* 1st input string. */
        printf("test: %s.\n\n", str1_inp);

        rhash_sha3_224_init(&ctx);
        rhash_sha3_update(&ctx, str1_inp, strlen(str1_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str1_224, res, SHA3_224_HASH_LEN))
                return -1;

        rhash_sha3_256_init(&ctx);
        rhash_sha3_update(&ctx, str1_inp, strlen(str1_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str1_256, res, SHA3_256_HASH_LEN))
                return -1;

        rhash_sha3_384_init(&ctx);
        rhash_sha3_update(&ctx, str1_inp, strlen(str1_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str1_384, res, SHA3_384_HASH_LEN))
                return -1;

        rhash_sha3_512_init(&ctx);
        rhash_sha3_update(&ctx, str1_inp, strlen(str1_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str1_512, res, SHA3_512_HASH_LEN))
                return -1;

        /* 2nd input string. */
        printf("test: <empty string>.\n\n");

        rhash_sha3_224_init(&ctx);
        rhash_sha3_update(&ctx, str2_inp, strlen(str2_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str2_224, res, SHA3_224_HASH_LEN))
                return -1;

        rhash_sha3_256_init(&ctx);
        rhash_sha3_update(&ctx, str2_inp, strlen(str2_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str2_256, res, SHA3_256_HASH_LEN))
                return -1;

        rhash_sha3_384_init(&ctx);
        rhash_sha3_update(&ctx, str2_inp, strlen(str2_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str2_384, res, SHA3_384_HASH_LEN))
                return -1;

        rhash_sha3_512_init(&ctx);
        rhash_sha3_update(&ctx, str2_inp, strlen(str2_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str2_512, res, SHA3_512_HASH_LEN))
                return -1;

        /* 3rd input string */
        printf("test: %s.\n\n", str3_inp);

        rhash_sha3_224_init(&ctx);
        rhash_sha3_update(&ctx, str3_inp, strlen(str3_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str3_224, res, SHA3_224_HASH_LEN))
                return -1;

        rhash_sha3_256_init(&ctx);
        rhash_sha3_update(&ctx, str3_inp, strlen(str3_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str3_256, res, SHA3_256_HASH_LEN))
                return -1;

        rhash_sha3_384_init(&ctx);
        rhash_sha3_update(&ctx, str3_inp, strlen(str3_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str3_384, res, SHA3_384_HASH_LEN))
                return -1;

        rhash_sha3_512_init(&ctx);
        rhash_sha3_update(&ctx, str3_inp, strlen(str3_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str3_512, res, SHA3_512_HASH_LEN))
                return -1;

        /* 4th input string. */
        printf("test: %s.\n\n", str4_inp);

        rhash_sha3_224_init(&ctx);
        rhash_sha3_update(&ctx, str4_inp, strlen(str4_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str4_224, res, SHA3_224_HASH_LEN))
                return -1;

        rhash_sha3_256_init(&ctx);
        rhash_sha3_update(&ctx, str4_inp, strlen(str4_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str4_256, res, SHA3_256_HASH_LEN))
                return -1;

        rhash_sha3_384_init(&ctx);
        rhash_sha3_update(&ctx, str4_inp, strlen(str4_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str4_384, res, SHA3_384_HASH_LEN))
                return -1;

        rhash_sha3_512_init(&ctx);
        rhash_sha3_update(&ctx, str4_inp, strlen(str4_inp));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str4_512, res, SHA3_512_HASH_LEN))
                return -1;

        /* unaligned 4th input string. */
        printf("test: %s.\n\n", str4_inp2 + 1);

        rhash_sha3_224_init(&ctx);
        rhash_sha3_update(&ctx, str4_inp2 + 1, strlen(str4_inp2 + 1));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str4_224, res, SHA3_224_HASH_LEN))
                return -1;

        rhash_sha3_256_init(&ctx);
        rhash_sha3_update(&ctx, str4_inp2 + 1, strlen(str4_inp2 + 1));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str4_256, res, SHA3_256_HASH_LEN))
                return -1;

        rhash_sha3_384_init(&ctx);
        rhash_sha3_update(&ctx, str4_inp2 + 1, strlen(str4_inp2 + 1));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str4_384, res, SHA3_384_HASH_LEN))
                return -1;

        rhash_sha3_512_init(&ctx);
        rhash_sha3_update(&ctx, str4_inp2 + 1, strlen(str4_inp2 + 1));
        rhash_sha3_final(&ctx, res);

        if (check_hash(str4_512, res, SHA3_512_HASH_LEN))
                return -1;

        return 0;
}
