/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the post-quantum key exchange functions
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
#include <ouroboros/random.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/x509.h>
#endif

extern const uint16_t kex_supported_nids[];
extern const uint16_t md_supported_nids[];

static int get_random_kdf(void)
{
        static int idx = 0;
        int        count;

        if (md_supported_nids[0] == NID_undef)
                return NID_undef;

        for (count = 0; md_supported_nids[count] != NID_undef; count++)
                ;

        return md_supported_nids[(idx++) % count];
}

/* ML-KEM-768 test key material */

#define MLKEM768_PRIVKEY_PEM \
        "-----BEGIN PRIVATE KEY-----\n" \
        "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\n" \
        "108=\n" \
        "-----END PRIVATE KEY-----\n"

#define MLKEM768_PUBKEY_PEM \
        "-----BEGIN PUBLIC KEY-----\n" \
        "MIIEsjALBglghkgBZQMEBAIDggShAMPIO3U2cWpYVzqVh5Vrp5FyZjN4BtdqGvHC\n" \
        "KJosh0dcP3lpn/RLr60oEaBDPCZmxvB1eGX6f7KoM0TpKjDZvC56qEPBlVagwK/l\n" \
        "Ir4cAY+1xntRT2hauqmIvTzmbsXkbj0olQRlp1W2Phn3OuR5CSJ1r7gju/djczOx\n" \
        "awYnDDtiFMMmmzHGZKbzlsfDH3yFldKpyQlMvhzacHOCsGW6QhP1aX6oi0y2FW8A\n" \
        "E/OnjAZmF2AqsQhGXfIKeGFSCkuVTFh6DBYMwSNnEqVJsjKXmn2UJLzDaWwHOxDY\n" \
        "UmIDL8xYtrnpoD7AWzcLyyZnoJ+nk1ZrxGb6Tz3wZYHFmK+EXTcIE5njZ27RhRl0\n" \
        "I+gDlXUoLpuHgnJYUjj1UVtAUwaDACpzQSsAfeIxqaYoL3vjpZZqCdQgbejwvKBm\n" \
        "u6y4Z5OiFcmFVRMkPDazSvM2FvDkjKiiSRjkFYQ0oUpMiB0HG9h6U4rBsYTxnfoU\n" \
        "RbQAGWbHtJEIpaU1WNIQAheYyJBUt1AXfdBVgP1FHlyGNrbnhW4kfimWj7knCIpb\n" \
        "PwuUIgGbsJWSJ9kwuh+YyTezcvixe0T4GF+bk+WTdGuAN2Ucf6EruCTrVcZ3KcaM\n" \
        "Njtou0IpnRIyxWyRIuibWlshHkwotixDU+x7iaF8M4UKRYUsjlNKEYy4iijWTtd4\n" \
        "gTqDxChSVXkRfJYceEhVoTjJYY8BWASnRSzAoV56jdKgIB4AMDdTzzKbGkEmnvfI\n" \
        "MiqiTl0zdKCSN89ZkOSCQAjxYewIop6qtI6zWSQTcle0TuRxMdPpcejXrZOaAaSo\n" \
        "xXA5DcSZHoVGljEmFm+5VuMmxLFiNbdJydHhmK+iLur3nKlyjffWkiUhmmpXQ3J1\n" \
        "SkzJBrPVyeg8pgOHXFrouFyoQorxrryJeNCDOCpAEMAGidXJs0O2UnmWdNO4qFqT\n" \
        "w8EUCaaGPUl2s+qgi9BEKYtpquQnv+r1Eu2TqRM4nSq0t7aqrALEnDKgx3ZDkXj7\n" \
        "FNZke73SWNF1ydh7BqupwrOgvbu1ylM6ZXPzwjWFhVQkRXtoHfpAyFNLV2q5Oolk\n" \
        "IPSEE9YAxOgSgPg4W8paZsWbNpbGsxzgQJh4MAApizZiqhdIt8CLEGZmNvpQMHrW\n" \
        "XYYDnykUlbRnA3xLm0CkDY1GL7ugL/OAyAEYd+3oTT45RVvwi3z2ljW3vJurn5+Q\n" \
        "G8SLEMh3d/WkreCpxpiob9iGgwkwlaSpjEI0aZ1nyAWjjpXor7jFlRuVBYrKk3r5\n" \
        "Fg7iQOHSSimlYYRQuOAGgIf5XwTsZygTxJF1BjUEgyhFVZvxSvxlghVTyWqBpk+V\n" \
        "YzehEKJaTSRHF7EUXSLlaUgsgr0ZPyxpf5uZF30pLLcmuk+FCfn0KkkFHHPxYp0n\n" \
        "fDC2oT/ZNvFCEuigRYdhWtkQbkRKQig6RQAlRH4LMssUMx1QTzDcJqwTjKz6Fyjs\n" \
        "ADlMCazbgDUVdzEyA1vpUcDRuLlzys8Jm+O5stdHgDT8DZRqWjhzLdQCv2TSttk4\n" \
        "meOqTx4TGR5rFvKHjZwmlTvmLg40tixFkmSD1uQKk+BkpvvTuw9k7vYJfeH+VB1d\n" \
        "WAaRntOp\n" \
        "-----END PUBLIC KEY-----\n"

/* Helper macro to open string constant as FILE stream */
#define FMEMOPEN_STR(str) fmemopen((void *) (str), strlen(str), "r")

static int test_kex_load_kem_privkey(void)
{
        void * key;

        TEST_START();

        if (crypt_load_privkey_str(MLKEM768_PRIVKEY_PEM, &key) < 0) {
                printf("Failed to load ML-KEM-768 private key.\n");
                goto fail;
        }

        crypt_free_key(key);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_load_kem_pubkey(void)
{
        void * key;

        TEST_START();

        if (crypt_load_pubkey_str(MLKEM768_PUBKEY_PEM, &key) < 0) {
                printf("Failed to load ML-KEM-768 public key.\n");
                goto fail;
        }

        crypt_free_key(key);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_kex_kem(const char * algo)
{
        struct sec_config kex;
        void *            pkp;
        buffer_t          pk;
        buffer_t          ct;
        ssize_t           len;
        ssize_t           ct_len;
        uint8_t           buf1[MSGBUFSZ];
        uint8_t           buf2[MSGBUFSZ];
        uint8_t           s1[SYMMKEYSZ];
        uint8_t           s2[SYMMKEYSZ];
        int               kdf;

        TEST_START("(%s)", algo);

        kdf = get_random_kdf();

        memset(&kex, 0, sizeof(kex));
        SET_KEX_ALGO(&kex, algo);

        len = kex_pkp_create(&kex, &pkp, buf1);
        if (len < 0) {
                printf("Failed to create key pair for %s.\n", algo);
                goto fail;
        }

        pk.len  = (size_t) len;
        pk.data = buf1;

        if (IS_HYBRID_KEM(algo))
                ct_len = kex_kem_encap_raw(pk, buf2, kdf, s1);
        else
                ct_len = kex_kem_encap(pk, buf2, kdf, s1);

        if (ct_len < 0) {
                printf("Failed to encapsulate for %s.\n", algo);
                goto fail_pkp;
        }

        ct.len  = (size_t) ct_len;
        ct.data = buf2;

        if (kex_kem_decap(pkp, ct, kdf, s2) < 0) {
                printf("Failed to decapsulate for %s.\n", algo);
                goto fail_pkp;
        }

        if (memcmp(s1, s2, SYMMKEYSZ) != 0) {
                printf("Shared secrets don't match for %s.\n", algo);
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

static int test_kex_kem_corrupted_ciphertext(const char * algo)
{
        struct sec_config kex;
        void *            pkp;
        buffer_t          pk;
        buffer_t          ct;
        ssize_t           len;
        ssize_t           ct_len;
        uint8_t           buf1[MSGBUFSZ];
        uint8_t           buf2[MSGBUFSZ];
        uint8_t           s1[SYMMKEYSZ];
        uint8_t           s2[SYMMKEYSZ];
        int               kdf;

        TEST_START("(%s)", algo);

        kdf = get_random_kdf();

        memset(&kex, 0, sizeof(kex));
        SET_KEX_ALGO(&kex, algo);

        len = kex_pkp_create(&kex, &pkp, buf1);
        if (len < 0) {
                printf("Failed to create key pair.\n");
                goto fail;
        }

        pk.len  = (size_t) len;
        pk.data = buf1;

        if (IS_HYBRID_KEM(algo))
                ct_len = kex_kem_encap_raw(pk, buf2, kdf, s1);
        else
                ct_len = kex_kem_encap(pk, buf2, kdf, s1);

        if (ct_len < 0) {
                printf("Failed to encapsulate.\n");
                goto fail_pkp;
        }

        ct.len  = (size_t) ct_len;
        ct.data = buf2;

        /* Corrupt the ciphertext */
        buf2[0] ^= 0xFF;
        buf2[ct_len - 1] ^= 0xFF;

        /* ML-KEM uses implicit rejection */
        if (kex_kem_decap(pkp, ct, kdf, s2) < 0) {
                printf("Decapsulation failed unexpectedly.\n");
                goto fail_pkp;
        }

        /* The shared secrets should NOT match with corrupted CT */
        if (memcmp(s1, s2, SYMMKEYSZ) == 0) {
                printf("Corrupted ciphertext produced same secret.\n");
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

static int test_kex_kem_wrong_keypair(const char * algo)
{
        struct sec_config kex;
        void *            pkp1;
        void *            pkp2;
        buffer_t          pk1;
        buffer_t          ct;
        ssize_t           len;
        ssize_t           ct_len;
        uint8_t           buf1[MSGBUFSZ];
        uint8_t           buf2[MSGBUFSZ];
        uint8_t           buf3[MSGBUFSZ];
        uint8_t           s1[SYMMKEYSZ];
        uint8_t           s2[SYMMKEYSZ];

        TEST_START("(%s)", algo);

        memset(&kex, 0, sizeof(kex));
        SET_KEX_ALGO(&kex, algo);

        len = kex_pkp_create(&kex, &pkp1, buf1);
        if (len < 0) {
                printf("Failed to create first key pair.\n");
                goto fail;
        }

        pk1.len  = (size_t) len;
        pk1.data = buf1;

        if (kex_pkp_create(&kex, &pkp2, buf2) < 0) {
                printf("Failed to create second key pair.\n");
                goto fail_pkp1;
        }

        if (IS_HYBRID_KEM(algo))
                ct_len = kex_kem_encap_raw(pk1, buf3, NID_sha256, s1);
        else
                ct_len = kex_kem_encap(pk1, buf3, NID_sha256, s1);

        if (ct_len < 0) {
                printf("Failed to encapsulate.\n");
                goto fail_pkp2;
        }

        ct.len  = (size_t) ct_len;
        ct.data = buf3;

        if (kex_kem_decap(pkp2, ct, NID_sha256, s2) == 0) {
                if (memcmp(s1, s2, SYMMKEYSZ) == 0) {
                        printf("Wrong keypair produced same secret.\n");
                        goto fail_pkp2;
                }
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

static int test_kex_kem_truncated_ciphertext(const char * algo)
{
        struct sec_config kex;
        void *            pkp;
        buffer_t          pk;
        buffer_t          ct;
        ssize_t           len;
        ssize_t           ct_len;
        uint8_t           buf1[MSGBUFSZ];
        uint8_t           buf2[MSGBUFSZ];
        uint8_t           s1[SYMMKEYSZ];
        uint8_t           s2[SYMMKEYSZ];

        TEST_START("(%s)", algo);

        memset(&kex, 0, sizeof(kex));
        SET_KEX_ALGO(&kex, algo);

        len = kex_pkp_create(&kex, &pkp, buf1);
        if (len < 0) {
                printf("Failed to create key pair.\n");
                goto fail;
        }

        pk.len  = (size_t) len;
        pk.data = buf1;

        if (IS_HYBRID_KEM(algo))
                ct_len = kex_kem_encap_raw(pk, buf2, NID_sha256, s1);
        else
                ct_len = kex_kem_encap(pk, buf2, NID_sha256, s1);

        if (ct_len < 0) {
                printf("Failed to encapsulate.\n");
                goto fail_pkp;
        }

        /* Truncate the ciphertext */
        ct.len  = (size_t) ct_len / 2;
        ct.data = buf2;

        if (kex_kem_decap(pkp, ct, NID_sha256, s2) == 0) {
                printf("Should fail with truncated ciphertext.\n");
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

static int test_kex_kem_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                if (!IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_kex_kem(algo);
        }

        return ret;
}

static int test_kex_kem_corrupted_ciphertext_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                if (!IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_kex_kem_corrupted_ciphertext(algo);
        }

        return ret;
}

static int test_kex_kem_wrong_keypair_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                if (!IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_kex_kem_wrong_keypair(algo);
        }

        return ret;
}

static int test_kex_kem_truncated_ciphertext_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                if (!IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_kex_kem_truncated_ciphertext(algo);
        }

        return ret;
}

int kex_test_pqc(int     argc,
                 char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

#ifdef HAVE_OPENSSL_PQC
        ret |= test_kex_load_kem_privkey();
        ret |= test_kex_load_kem_pubkey();
        ret |= test_kex_kem_all();
        ret |= test_kex_kem_corrupted_ciphertext_all();
        ret |= test_kex_kem_wrong_keypair_all();
        ret |= test_kex_kem_truncated_ciphertext_all();
#else
        (void) test_kex_load_kem_privkey;
        (void) test_kex_load_kem_pubkey;
        (void) test_kex_kem_all;
        (void) test_kex_kem_corrupted_ciphertext_all;
        (void) test_kex_kem_wrong_keypair_all;
        (void) test_kex_kem_truncated_ciphertext_all;

        ret = TEST_RC_SKIP;
#endif
        return ret;
}
