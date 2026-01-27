/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Test of the key exchange functions
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

#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <test/test.h>
#include <ouroboros/utils.h>
#include <ouroboros/crypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/x509.h>
#endif

/* Test configuration strings */
#define KEX_CONFIG_CUSTOM \
        "kex=X25519\n"

#define KEX_CONFIG_NONE \
        "none\n"

#define KEX_CONFIG_WHITESPACE \
        "# Comment line\n" \
        "kex = X448" \
        "\n" \
        "# Another comment\n"

#define KEX_CONFIG_CIPHER \
        "kex=X25519\n" \
        "cipher=chacha20-poly1305\n"

#define KEX_CONFIG_DIGEST \
        "kex=X25519\n" \
        "digest=sha384\n"

/* Test key material for key loading tests */
#define X25519_PRIVKEY_PEM \
        "-----BEGIN PRIVATE KEY-----\n" \
        "MC4CAQAwBQYDK2VuBCIEIJDd3+/0k2IZlaH5sZ9Z2e5J8dV2U0nsXaSUm70ZaMhL\n" \
        "-----END PRIVATE KEY-----\n"

#define X25519_PUBKEY_PEM \
        "-----BEGIN PUBLIC KEY-----\n" \
        "MCowBQYDK2VuAyEAKYLIycSZtLFlwAX07YWWgBAYhEnRxHfgK1TVw9+mtBs=\n" \
        "-----END PUBLIC KEY-----\n"

/* Helper macro to open string constant as FILE stream */
#define FMEMOPEN_STR(str) fmemopen((void *) (str), strlen(str), "r")

extern const uint16_t kex_supported_nids[];

int parse_sec_config(struct sec_config * cfg,
                     FILE *              fp);

static int test_kex_create_destroy(void)
{
        struct sec_config cfg;

        TEST_START();

        memset(&cfg, 0, sizeof(cfg));
        cfg.x.nid = NID_X9_62_prime256v1;
        cfg.x.str = kex_nid_to_str(cfg.x.nid);
        cfg.c.nid = NID_aes_256_gcm;
        cfg.c.str = crypt_nid_to_str(cfg.c.nid);

        if (cfg.x.nid == NID_undef || cfg.c.nid == NID_undef) {
                printf("Failed to initialize kex config.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_dh_pkp_create_destroy(void)
{
        struct sec_config kex;
        void *         pkp;
        uint8_t        buf[MSGBUFSZ];

        TEST_START();

        memset(&kex, 0, sizeof(kex));
        SET_KEX_ALGO(&kex, "prime256v1");

        if (kex_pkp_create(&kex, &pkp, buf) < 0) {
                printf("Failed to create DH PKP.\n");
                goto fail;
        }

        kex_pkp_destroy(pkp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_get_algo_from_pk(const char * algo)
{
        struct sec_config kex;
        void *            pkp;
        buffer_t          pk;
        ssize_t           len;
        uint8_t           buf[MSGBUFSZ];
        char              extracted_algo[256];

        TEST_START("(%s)", algo);

        memset(&kex, 0, sizeof(kex));
        SET_KEX_ALGO(&kex, algo);

        len = kex_pkp_create(&kex, &pkp, buf);
        if (len < 0) {
                printf("Failed to create key pair.\n");
                goto fail;
        }

        pk.len  = (size_t) len;
        pk.data = buf;

        /* Use raw decode for hybrid KEMs, DER for others */
        if (IS_HYBRID_KEM(algo)) {
                if (kex_get_algo_from_pk_raw(pk, extracted_algo) < 0) {
                        printf("Failed to extract algo from pk.\n");
                        goto fail_pkp;
                }
        } else {
                if (kex_get_algo_from_pk_der(pk, extracted_algo) < 0) {
                        printf("Failed to extract algo from pk.\n");
                        goto fail_pkp;
                }
        }

        /* All algorithms should now return the specific group name */
        if (strcmp(extracted_algo, algo) != 0) {
                printf("Algo mismatch: expected %s, got %s.\n",
                       algo, extracted_algo);
                goto fail_pkp;
        }

        kex_pkp_destroy(pkp);

        TEST_SUCCESS("(%s)", algo);

        return TEST_RC_SUCCESS;
 fail_pkp:
        kex_pkp_destroy(pkp);
 fail:
        TEST_FAIL("(%s)", algo);
        return TEST_RC_FAIL;
}

static int test_kex_get_algo_from_pk_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);
                ret |= test_kex_get_algo_from_pk(algo);
        }

        return ret;
}

static int test_kex_dhe_derive(const char * algo)
{
        struct sec_config kex;
        void *            pkp1;
        void *            pkp2;
        buffer_t          pk1;
        buffer_t          pk2;
        ssize_t           len;
        uint8_t           buf1[MSGBUFSZ];
        uint8_t           buf2[MSGBUFSZ];
        uint8_t           s1[SYMMKEYSZ];
        uint8_t           s2[SYMMKEYSZ];

        TEST_START("(%s)", algo);

        memset(&kex, 0, sizeof(kex));
        SET_KEX_ALGO(&kex, algo);

        len = kex_pkp_create(&kex, &pkp1, buf1);
        if (len < 0) {
                printf("Failed to create first key pair for %s.\n", algo);
                goto fail;
        }

        pk1.len  = (size_t) len;
        pk1.data = buf1;

        len = kex_pkp_create(&kex, &pkp2, buf2);
        if (len < 0) {
                printf("Failed to create second key pair for %s.\n", algo);
                goto fail_pkp1;
        }

        pk2.len  = (size_t) len;
        pk2.data = buf2;

        if (kex_dhe_derive(&kex, pkp1, pk2, s1) < 0) {
                printf("Failed to derive first key for %s.\n", algo);
                goto fail_pkp2;
        }

        if (kex_dhe_derive(&kex, pkp2, pk1, s2) < 0) {
                printf("Failed to derive second key for %s.\n", algo);
                goto fail_pkp2;
        }

        if (memcmp(s1, s2, SYMMKEYSZ) != 0) {
                printf("Derived keys do not match for %s.\n", algo);
                goto fail_pkp2;
        }

        kex_pkp_destroy(pkp2);
        kex_pkp_destroy(pkp1);

        TEST_SUCCESS("(%s)", algo);

        return TEST_RC_SUCCESS;
 fail_pkp2:
        kex_pkp_destroy(pkp2);
 fail_pkp1:
        kex_pkp_destroy(pkp1);
 fail:
        TEST_FAIL("(%s)", algo);
        return TEST_RC_FAIL;
}

static int test_kex_validate_algo(void)
{
        TEST_START();

        if (kex_validate_algo("prime256v1") != 0) {
                printf("prime256v1 should be valid.\n");
                goto fail;
        }

        if (kex_validate_algo("X25519") != 0) {
                printf("X25519 should be valid.\n");
                goto fail;
        }

#ifdef HAVE_OPENSSL_PQC
        if (kex_validate_algo("ML-KEM-768") != 0) {
                printf("ML-KEM-768 should be valid.\n");
                goto fail;
        }
#endif

        if (kex_validate_algo("ffdhe2048") != 0) {
                printf("ffdhe2048 should be valid.\n");
                goto fail;
        }

        if (kex_validate_algo("invalid_algo") == 0) {
                printf("invalid_algo should be rejected.\n");
                goto fail;
        }

        if (kex_validate_algo("rsa2048") == 0) {
                printf("rsa2048 should be rejected.\n");
                goto fail;
        }

        if (kex_validate_algo(NULL) == 0) {
                printf("NULL should be rejected.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_dhe_corrupted_pubkey(const char * algo)
{
        struct sec_config kex;
        void *            pkp;
        buffer_t          pk;
        ssize_t           len;
        uint8_t           buf[MSGBUFSZ];
        uint8_t           s[SYMMKEYSZ];

        TEST_START("(%s)", algo);

        memset(&kex, 0, sizeof(kex));
        SET_KEX_ALGO(&kex, algo);

        len = kex_pkp_create(&kex, &pkp, buf);
        if (len < 0) {
                printf("Failed to create key pair.\n");
                goto fail;
        }

        pk.len  = (size_t) len;
        pk.data = buf;

        /* Corrupt the public key */
        buf[0] ^= 0xFF;
        buf[len - 1] ^= 0xFF;

        if (kex_dhe_derive(&kex, pkp, pk, s) == 0) {
                printf("Should fail with corrupted public key.\n");
                goto fail_pkp;
        }

        kex_pkp_destroy(pkp);

        TEST_SUCCESS("(%s)", algo);

        return TEST_RC_SUCCESS;
 fail_pkp:
        kex_pkp_destroy(pkp);
 fail:
        TEST_FAIL("(%s)", algo);
        return TEST_RC_FAIL;
}

static int test_kex_dhe_wrong_algo(void)
{
        struct sec_config kex1;
        struct sec_config kex2;
        void *            pkp1;
        void *            pkp2;
        buffer_t          pk2;
        ssize_t           len;
        uint8_t           buf1[MSGBUFSZ];
        uint8_t           buf2[MSGBUFSZ];
        uint8_t           s[SYMMKEYSZ];
        const char *      algo1 = "X25519";
        const char *      algo2 = "X448";

        TEST_START("(%s vs %s)", algo1, algo2);

        memset(&kex1, 0, sizeof(kex1));
        memset(&kex2, 0, sizeof(kex2));
        SET_KEX_ALGO(&kex1, algo1);
        SET_KEX_ALGO(&kex2, algo2);

        if (kex_pkp_create(&kex1, &pkp1, buf1) < 0) {
                printf("Failed to create first key pair.\n");
                goto fail;
        }

        len = kex_pkp_create(&kex2, &pkp2, buf2);
        if (len < 0) {
                printf("Failed to create second key pair.\n");
                goto fail_pkp1;
        }

        pk2.len  = (size_t) len;
        pk2.data = buf2;

        /* Try to derive with mismatched algorithms */
        if (kex_dhe_derive(&kex1, pkp1, pk2, s) == 0) {
                printf("Should fail with mismatched algorithms.\n");
                goto fail_pkp2;
        }

        kex_pkp_destroy(pkp2);
        kex_pkp_destroy(pkp1);

        TEST_SUCCESS("(%s vs %s)", algo1, algo2);

        return TEST_RC_SUCCESS;
 fail_pkp2:
        kex_pkp_destroy(pkp2);
 fail_pkp1:
        kex_pkp_destroy(pkp1);
 fail:
        TEST_FAIL("(%s vs %s)", algo1, algo2);
        return TEST_RC_FAIL;
}

static int test_kex_load_dhe_privkey(void)
{
        void * key;

        TEST_START();

        if (crypt_load_privkey_str(X25519_PRIVKEY_PEM, &key) < 0) {
                printf("Failed to load X25519 private key.\n");
                goto fail;
        }

        crypt_free_key(key);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_load_dhe_pubkey(void)
{
        void * key;

        TEST_START();

        if (crypt_load_pubkey_str(X25519_PUBKEY_PEM, &key) < 0) {
                printf("Failed to load X25519 public key.\n");
                goto fail;
        }

        crypt_free_key(key);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

#ifdef HAVE_OPENSSL
#include <openssl/obj_mac.h>

static int test_kex_nid_values(void)
{
        int i;

        TEST_START();

        /* Verify all KEX algorithm NIDs match OpenSSL's */
        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                uint16_t our_nid = kex_supported_nids[i];
                const char * kex_name;
                int openssl_nid;

                kex_name = kex_nid_to_str(our_nid);
                if (kex_name == NULL) {
                        printf("kex_nid_to_str failed for NID %u\n", our_nid);
                        goto fail;
                }

                /* Test reverse conversion */
                if (kex_str_to_nid(kex_name) != our_nid) {
                        printf("kex_str_to_nid failed for '%s'\n", kex_name);
                        goto fail;
                }

                /* Get OpenSSL's NID for this name */
                openssl_nid = OBJ_txt2nid(kex_name);
                if (openssl_nid != NID_undef) {
                        /* OpenSSL recognizes this algorithm */
                        if (our_nid != openssl_nid) {
                                printf("NID mismatch for '%s': "
                                       "ours=%d, OpenSSL=%d\n",
                                       kex_name, our_nid, openssl_nid);
                                goto fail;
                        }
                } else {
                        /* Verify no NID collision with different algorithm */
                        const char * ossl_name = OBJ_nid2sn(our_nid);
                        if (ossl_name != NULL &&
                            strcmp(ossl_name, kex_name) != 0) {
                                printf("NID collision for '%d': "
                                       "ours=%s, OpenSSL=%s\n",
                                       our_nid, kex_name, ossl_name);
                                goto fail;
                        }
                }
        }

        /* Test error cases */
        if (kex_str_to_nid("invalid") != NID_undef) {
                printf("kex_str_to_nid should return NID_undef for invalid\n");
                goto fail;
        }

        if (kex_nid_to_str(9999) != NULL) {
                printf("kex_nid_to_str should return NULL for invalid NID\n");
                goto fail;
        }

        if (kex_str_to_nid(NULL) != NID_undef) {
                printf("kex_str_to_nid should return NID_undef for NULL\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}
#endif

static int test_kex_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                /* KEM tests are in kex_test_pqc.c */
                if (IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_kex_dhe_derive(algo);
        }

        return ret;
}

static int test_kex_dhe_corrupted_pubkey_all(void)
{
        int ret = 0;
        int i;

        /* Test corruption for all DHE algorithms */
        /* KEM error injection tests are in kex_test_pqc.c */
        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                if (IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_kex_dhe_corrupted_pubkey(algo);
        }

        return ret;
}

static int test_kex_parse_config_empty(void)
{
        struct sec_config kex;
        FILE *         fp;

        TEST_START();

        memset(&kex, 0, sizeof(kex));

        fp = FMEMOPEN_STR("\n");
        if (fp == NULL) {
                printf("Failed to open memory stream.\n");
                goto fail;
        }

        if (parse_sec_config(&kex, fp) < 0) {
                printf("Failed to parse empty config.\n");
                fclose(fp);
                goto fail;
        }

        if (strcmp(kex.x.str, "prime256v1") != 0) {
                printf("Empty config should use prime256v1.\n");
                fclose(fp);
                goto fail;
        }

        fclose(fp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_parse_config_custom(void)
{
        struct sec_config kex;
        FILE *         fp;

        TEST_START();

        memset(&kex, 0, sizeof(kex));

        fp = FMEMOPEN_STR(KEX_CONFIG_CUSTOM);
        if (fp == NULL) {
                printf("Failed to open memory stream.\n");
                goto fail;
        }

        if (parse_sec_config(&kex, fp) < 0) {
                printf("Failed to parse custom config.\n");
                fclose(fp);
                goto fail;
        }

        if (strcmp(kex.x.str, "X25519") != 0) {
                printf("Algorithm not set correctly.\n");
                fclose(fp);
                goto fail;
        }

        fclose(fp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_parse_config_none(void)
{
        struct sec_config kex;
        FILE *         fp;

        TEST_START();

        memset(&kex, 0, sizeof(kex));

        fp = FMEMOPEN_STR(KEX_CONFIG_NONE);
        if (fp == NULL) {
                printf("Failed to open memory stream.\n");
                goto fail;
        }

        if (parse_sec_config(&kex, fp) < 0) {
                printf("Failed to parse 'none' config.\n");
                fclose(fp);
                goto fail;
        }

        if (kex.x.nid != NID_undef) {
                printf("'none' keyword should disable encryption.\n");
                fclose(fp);
                goto fail;
        }

        fclose(fp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_parse_config_whitespace(void)
{
        struct sec_config kex;
        FILE *         fp;

        TEST_START();

        memset(&kex, 0, sizeof(kex));

        fp = FMEMOPEN_STR(KEX_CONFIG_WHITESPACE);
        if (fp == NULL) {
                printf("Failed to open memory stream.\n");
                goto fail;
        }

        if (parse_sec_config(&kex, fp) < 0) {
                printf("Failed to parse config with comments.\n");
                fclose(fp);
                goto fail;
        }

        if (strcmp(kex.x.str, "X448") != 0) {
                printf("Algorithm with whitespace not parsed correctly.\n");
                fclose(fp);
                goto fail;
        }

        fclose(fp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_parse_config_cipher(void)
{
        struct sec_config kex;
        FILE *         fp;

        TEST_START();

        memset(&kex, 0, sizeof(kex));

        fp = FMEMOPEN_STR(KEX_CONFIG_CIPHER);
        if (fp == NULL) {
                printf("Failed to open memory stream.\n");
                goto fail;
        }

        if (parse_sec_config(&kex, fp) < 0) {
                printf("Failed to parse cipher config.\n");
                fclose(fp);
                goto fail;
        }

        if (strcmp(kex.x.str, "X25519") != 0) {
                printf("Algorithm not set correctly.\n");
                fclose(fp);
                goto fail;
        }

        if (kex.c.nid != NID_chacha20_poly1305) {
                printf("Cipher not set correctly.\n");
                fclose(fp);
                goto fail;
        }

        fclose(fp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_parse_config_digest(void)
{
        struct sec_config kex;
        FILE *         fp;

        TEST_START();

        memset(&kex, 0, sizeof(kex));

        fp = FMEMOPEN_STR(KEX_CONFIG_DIGEST);
        if (fp == NULL) {
                printf("Failed to open memory stream.\n");
                goto fail;
        }

        if (parse_sec_config(&kex, fp) < 0) {
                printf("Failed to parse digest config.\n");
                fclose(fp);
                goto fail;
        }

        if (strcmp(kex.x.str, "X25519") != 0) {
                printf("Algorithm not set correctly.\n");
                fclose(fp);
                goto fail;
        }

        if (kex.d.nid != NID_sha384) {
                printf("Digest not set correctly.\n");
                fclose(fp);
                goto fail;
        }

        fclose(fp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int kex_test(int     argc,
             char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_kex_create_destroy();
        ret |= test_kex_parse_config_empty();
        ret |= test_kex_parse_config_none();
#ifdef HAVE_OPENSSL
        ret |= test_kex_parse_config_custom();
        ret |= test_kex_parse_config_whitespace();
        ret |= test_kex_parse_config_cipher();
        ret |= test_kex_parse_config_digest();
        ret |= test_kex_nid_values();
        ret |= test_kex_dh_pkp_create_destroy();
        ret |= test_kex_all();
        ret |= test_kex_validate_algo();
        ret |= test_kex_get_algo_from_pk_all();
        ret |= test_kex_dhe_wrong_algo();
        ret |= test_kex_dhe_corrupted_pubkey_all();
        ret |= test_kex_load_dhe_privkey();
        ret |= test_kex_load_dhe_pubkey();
#else
        (void) test_kex_parse_config_custom;
        (void) test_kex_parse_config_whitespace;
        (void) test_kex_parse_config_cipher;
        (void) test_kex_parse_config_digest;
        (void) test_kex_dh_pkp_create_destroy;
        (void) test_kex_all;
        (void) test_kex_validate_algo;
        (void) test_kex_get_algo_from_pk_all;
        (void) test_kex_dhe_wrong_algo();
        (void) test_kex_dhe_corrupted_pubkey_all;
        (void) test_kex_load_dhe_privkey;
        (void) test_kex_load_dhe_pubkey;

        ret = TEST_RC_SKIP;
#endif
        return ret;
}
