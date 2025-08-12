/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Test of the cryptography functions
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

#include <ouroboros/test.h>
#include <ouroboros/crypt.h>
#include <ouroboros/random.h>
#include <ouroboros/utils.h>

#define TEST_PACKET_SIZE 1500

static int test_crypt_create_destroy(void)
{
        struct crypt_ctx * ctx;

        TEST_START();

        ctx = crypt_create_ctx(0, NULL);
        if (ctx == NULL) {
                printf("Failed to initialize cryptography.\n");
                goto fail;
        }

        crypt_destroy_ctx(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_crypt_create_destroy_with_key(void)
{
        struct crypt_ctx * ctx;
        uint8_t            key[SYMMKEYSZ];

        TEST_START();

        memset(key, 0, sizeof(key));

        ctx = crypt_create_ctx(1, key);
        if (ctx == NULL) {
                printf("Failed to initialize cryptography.\n");
                goto fail;
        }

        crypt_destroy_ctx(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_crypt_dh_pkp_create_destroy(void)
{
        void *  pkp;
        uint8_t buf[MSGBUFSZ];

        TEST_START();

        if (crypt_dh_pkp_create(&pkp, buf) < 0) {
                printf("Failed to create DH PKP.");
                goto fail;
        }

        crypt_dh_pkp_destroy(pkp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_crypt_dh_derive(void)
{
        void *   pkp1;
        void *   pkp2;
        buffer_t pk1;
        buffer_t pk2;
        ssize_t  len;
        uint8_t  buf1[MSGBUFSZ];
        uint8_t  buf2[MSGBUFSZ];
        uint8_t  s1[SYMMKEYSZ];
        uint8_t  s2[SYMMKEYSZ];

        TEST_START();

        len = crypt_dh_pkp_create(&pkp1, buf1);
        if (len < 0) {
                printf("Failed to create first key pair.");
                goto fail_pkp1;
        }

        pk1.len  = (size_t) len;
        pk1.data = buf1;

        len = crypt_dh_pkp_create(&pkp2, buf2);
        if (len < 0) {
                printf("Failed to create second key pair.");
                goto fail_pkp2;
        }

        pk2.len  = (size_t) len;
        pk2.data = buf2;

        if (crypt_dh_derive(pkp1, pk2, s1) < 0) {
                printf("Failed to derive first key.");
                goto fail;
        }

        if (crypt_dh_derive(pkp2, pk1, s2) < 0) {
                printf("Failed to derive second key.");
                goto fail;
        }

        if (memcmp(s1, s2, SYMMKEYSZ) != 0) {
                printf("Derived keys do not match.");
                goto fail;
        }

        crypt_dh_pkp_destroy(pkp2);
        crypt_dh_pkp_destroy(pkp1);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        crypt_dh_pkp_destroy(pkp2);
 fail_pkp2:
        crypt_dh_pkp_destroy(pkp1);
 fail_pkp1:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int test_crypt_encrypt_decrypt(void)
{
        uint8_t            pkt[TEST_PACKET_SIZE];
        uint8_t            key[SYMMKEYSZ];
        struct crypt_ctx * ctx;
        buffer_t           in;
        buffer_t           out;
        buffer_t           out2;

        TEST_START();

        if (random_buffer(key, sizeof(key)) < 0) {
                printf("Failed to generate random key.\n");
                goto fail_init;
        }

        if (random_buffer(pkt, sizeof(pkt)) < 0) {
                printf("Failed to generate random data.\n");
                goto fail_init;
        }

        ctx = crypt_create_ctx(1, key);
        if (ctx == NULL) {
                printf("Failed to initialize cryptography.\n");
                goto fail_init;
        }

        in.len  = sizeof(pkt);
        in.data = pkt;

        if (crypt_encrypt(ctx, in, &out) < 0) {
                printf("Encryption failed.\n");
                goto fail_encrypt;
        }

        if (out.len < in.len) {
                printf("Encryption returned too little data.\n");
                goto fail_encrypt;
        }

        if (crypt_decrypt(ctx, out, &out2) < 0) {
                printf("Decryption failed.\n");
                goto fail_decrypt;
        }

        if (out2.len != in.len) {
                printf("Decrypted data length does not match original.\n");
                goto fail_chk;
        }

        if (memcmp(in.data, out2.data, in.len) != 0) {
                printf("Decrypted data does not match original.\n");
                goto fail_chk;
        }

        crypt_destroy_ctx(ctx);
        freebuf(out2);
        freebuf(out);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_chk:
        freebuf(out2);
 fail_decrypt:
        freebuf(out);
 fail_encrypt:
        crypt_destroy_ctx(ctx);
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int crypt_test(int     argc,
               char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_crypt_create_destroy();
        ret |= test_crypt_create_destroy_with_key();
#ifdef HAVE_OPENSSL
        ret |= test_crypt_dh_pkp_create_destroy();
        ret |= test_crypt_dh_derive();
        ret |= test_crypt_encrypt_decrypt();
#else
        (void) test_crypt_dh_pkp_create_destroy;
        (void) test_crypt_dh_derive;
        (void) test_crypt_encrypt_decrypt;

        ret = TEST_RC_SKIP;
#endif
        return ret;
}
