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

#include <test/test.h>
#include <ouroboros/random.h>
#include <ouroboros/crypt.h>
#include <ouroboros/utils.h>

#include <stdio.h>

#define TEST_PACKET_SIZE 1500

extern const uint16_t crypt_supported_nids[];
extern const uint16_t md_supported_nids[];

static int test_crypt_create_destroy(void)
{
        struct crypt_ctx * ctx;
        uint8_t            key[SYMMKEYSZ];
        struct crypt_sk    sk = {
                .nid = NID_aes_256_gcm,
                .key = key
        };

        TEST_START();

        memset(key, 0, sizeof(key));

        ctx = crypt_create_ctx(&sk);
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

static int test_crypt_encrypt_decrypt(int nid)
{
        uint8_t            pkt[TEST_PACKET_SIZE];
        struct crypt_ctx * ctx;
        uint8_t            key[SYMMKEYSZ];
        struct crypt_sk    sk = {
                .nid = NID_aes_256_gcm,
                .key = key
        };
        buffer_t           in;
        buffer_t           out;
        buffer_t           out2;
        const char *       cipher;

        cipher = crypt_nid_to_str(nid);
        TEST_START("(%s)", cipher);

        if (random_buffer(key, sizeof(key)) < 0) {
                printf("Failed to generate random key.\n");
                goto fail_init;
        }

        if (random_buffer(pkt, sizeof(pkt)) < 0) {
                printf("Failed to generate random data.\n");
                goto fail_init;
        }

        ctx = crypt_create_ctx(&sk);
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

        TEST_SUCCESS("(%s)", cipher);

        return TEST_RC_SUCCESS;
 fail_chk:
        freebuf(out2);
 fail_decrypt:
        freebuf(out);
 fail_encrypt:
        crypt_destroy_ctx(ctx);
 fail_init:
        TEST_FAIL("(%s)", cipher);
        return TEST_RC_FAIL;
}

static int test_encrypt_decrypt_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; crypt_supported_nids[i] != NID_undef; i++)
                ret |= test_crypt_encrypt_decrypt(crypt_supported_nids[i]);

        return ret;
}

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

static int test_cipher_nid_values(void)
{
        int i;

        TEST_START();

        /* Loop over all supported ciphers and verify NIDs match OpenSSL's */
        for (i = 0; crypt_supported_nids[i] != NID_undef; i++) {
                uint16_t our_nid = crypt_supported_nids[i];
                const char * str = crypt_nid_to_str(our_nid);
                const EVP_CIPHER * cipher;
                int openssl_nid;

                if (str == NULL) {
                        printf("crypt_nid_to_str failed for NID %u\n", our_nid);
                        goto fail;
                }

                cipher = EVP_get_cipherbyname(str);
                if (cipher == NULL) {
                        printf("OpenSSL doesn't recognize cipher '%s'\n", str);
                        goto fail;
                }

                openssl_nid = EVP_CIPHER_nid(cipher);

                if (our_nid != openssl_nid) {
                        printf("NID mismatch for '%s': ours=%u, OpenSSL=%d\n",
                               str, our_nid, openssl_nid);
                        goto fail;
                }

                /* Test reverse conversion */
                if (crypt_str_to_nid(str) != our_nid) {
                        printf("crypt_str_to_nid failed for '%s'\n", str);
                        goto fail;
                }
        }

        /* Test error cases */
        if (crypt_str_to_nid("invalid") != NID_undef) {
                printf("crypt_str_to_nid: no NID_undef for invalid.\n");
                goto fail;
        }

        if (crypt_nid_to_str(9999) != NULL) {
                printf("crypt_nid_to_str should return NULL for invalid NID\n");
                goto fail;
        }

        if (crypt_str_to_nid(NULL) != NID_undef) {
                printf("crypt_str_to_nid should return NID_undef for NULL\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_md_nid_values(void)
{
        int i;

        TEST_START();

        for (i = 0; md_supported_nids[i] != NID_undef; i++) {
                uint16_t our_nid = md_supported_nids[i];
                const EVP_MD * md;
                int openssl_nid;

                md = EVP_get_digestbynid(our_nid);
                if (md == NULL) {
                        printf("OpenSSL doesn't recognize NID %u\n", our_nid);
                        goto fail;
                }

                openssl_nid = EVP_MD_nid(md);
                if (our_nid != openssl_nid) {
                        printf("NID mismatch: ours=%u, OpenSSL=%d\n",
                               our_nid, openssl_nid);
                        goto fail;
                }
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}
#endif

int crypt_test(int     argc,
               char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_crypt_create_destroy();
        ret |= test_encrypt_decrypt_all();
#ifdef HAVE_OPENSSL
        ret |= test_cipher_nid_values();
        ret |= test_md_nid_values();
#endif
        return ret;
}
