/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Unit tests of Ouroboros Allocation Protocol (OAP)
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

#if defined(__linux__) || defined(__CYGWIN__)
 #ifndef _DEFAULT_SOURCE
  #define _DEFAULT_SOURCE
 #endif
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include <ouroboros/crypt.h>
#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/flow.h>
#include <ouroboros/name.h>
#include <ouroboros/random.h>
#include <ouroboros/time.h>

#include <test/test.h>
#include <test/certs/ecdsa.h>

#include "oap.h"
#include "oap/auth.h"
#include "common.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

extern const uint16_t kex_supported_nids[];
extern const uint16_t md_supported_nids[];

struct test_cfg test_cfg;

/* Mock load - called by load_*_credentials in common.c */
int mock_load_credentials(void ** pkp,
                          void ** crt)
{
        *crt = NULL;

        if (crypt_load_privkey_str(server_pkp_ec, pkp) < 0)
                goto fail_privkey;

        if (crypt_load_crt_str(signed_server_crt_ec, crt) < 0)
                goto fail_crt;

        return 0;

 fail_crt:
        crypt_free_key(*pkp);
 fail_privkey:
        *pkp = NULL;
        return -1;
}

/* Stub KEM functions - ECDSA tests don't use KEM */
int load_server_kem_keypair(__attribute__((unused)) const char * name,
                            __attribute__((unused)) bool         raw_fmt,
                            __attribute__((unused)) void **      pkp)
{
        return -1;
}

int load_server_kem_pk(__attribute__((unused)) const char *        name,
                       __attribute__((unused)) struct sec_config * cfg,
                       __attribute__((unused)) buffer_t *          pk)
{
        return -1;
}

static void test_default_cfg(void)
{
        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: X25519, AES-256-GCM, SHA-256, with auth */
        test_cfg.srv.kex    = NID_X25519;
        test_cfg.srv.cipher = NID_aes_256_gcm;
        test_cfg.srv.kdf    = NID_sha256;
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = AUTH;

        /* Client: same KEX/cipher/kdf/md, no auth */
        test_cfg.cli.kex    = NID_X25519;
        test_cfg.cli.cipher = NID_aes_256_gcm;
        test_cfg.cli.kdf    = NID_sha256;
        test_cfg.cli.md     = NID_sha256;
        test_cfg.cli.auth   = NO_AUTH;
}

/* Encrypted, unauthenticated on both sides. */
static void test_enc_noauth_cfg(void)
{
        test_default_cfg();
        test_cfg.srv.auth = NO_AUTH;
}

static int test_oap_auth_init_fini(void)
{
        TEST_START();

        if (oap_auth_init() < 0) {
                printf("Failed to init OAP.\n");
                goto fail;
        }

        oap_auth_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_oap_roundtrip(int kex)
{
        struct oap_test_ctx ctx;
        const char *        kex_str = kex_nid_to_str(kex);

        TEST_START("(%s)", kex_str);

        test_default_cfg();
        test_cfg.srv.kex = kex;
        test_cfg.cli.kex = kex;

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Client complete failed.\n");
                goto fail_cleanup;
        }

        if (memcmp(ctx.cli.key, ctx.srv.key, SYMMKEYSZ) != 0) {
                printf("Client and server keys do not match!\n");
                goto fail_cleanup;
        }

        if (ctx.cli.nid == NID_undef || ctx.srv.nid == NID_undef) {
                printf("Cipher not set in flow.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS("(%s)", kex_str);

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL("(%s)", kex_str);
        return TEST_RC_FAIL;
}

static int test_oap_roundtrip_auth_only(void)
{
        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: auth only, no encryption */
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = AUTH;

        /* Client: no auth, no encryption */
        test_cfg.cli.md     = NID_sha256;
        test_cfg.cli.auth   = NO_AUTH;

        return roundtrip_auth_only(root_ca_crt_ec, im_ca_crt_ec);
}

static int test_oap_rekey(bool srv_auth,
                          bool cli_auth)
{
        test_default_cfg();
        test_cfg.srv.auth = srv_auth;
        test_cfg.cli.auth = cli_auth;

        return roundtrip_rekey(root_ca_crt_ec, im_ca_crt_ec,
                               srv_auth, cli_auth);
}

static int test_oap_rekey_all(void)
{
        int ret = 0;

        ret |= test_oap_rekey(AUTH, NO_AUTH);
        ret |= test_oap_rekey(AUTH, AUTH);
        ret |= test_oap_rekey(NO_AUTH, AUTH);
        ret |= test_oap_rekey(NO_AUTH, NO_AUTH);

        return ret;
}

static int test_oap_rekey_srv_badcache(bool srv_auth)
{
        test_default_cfg();
        test_cfg.srv.auth = srv_auth;
        test_cfg.cli.auth = AUTH;

        return roundtrip_rekey_srv_badcache(root_ca_crt_ec, im_ca_crt_ec,
                                            srv_auth);
}

static int test_oap_rekey_srv_badcache_all(void)
{
        int ret = 0;

        ret |= test_oap_rekey_srv_badcache(AUTH);
        ret |= test_oap_rekey_srv_badcache(NO_AUTH);

        return ret;
}

static int test_oap_rekey_badcache(bool cli_auth)
{
        test_default_cfg();
        test_cfg.cli.auth = cli_auth;

        return roundtrip_rekey_badcache(root_ca_crt_ec, im_ca_crt_ec,
                                        cli_auth);
}

static int test_oap_rekey_badcache_all(void)
{
        int ret = 0;

        ret |= test_oap_rekey_badcache(NO_AUTH);
        ret |= test_oap_rekey_badcache(AUTH);

        return ret;
}

/* Absent sec config (ENOENT) clears the KEX; a re-key must fail closed. */
static int test_oap_cli_rejects_rekey_no_kex(void)
{
        struct oap_test_ctx ctx;

        TEST_START();

        test_enc_noauth_cfg();
        test_cfg.cli.kex = NID_undef;

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        ctx.rekey = true;

        if (oap_cli_prepare_ctx(&ctx) == 0) {
                printf("Client prepared a re-key without KEX.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_oap_srv_rejects_rekey_no_kex(void)
{
        struct oap_test_ctx ctx;

        TEST_START();

        test_enc_noauth_cfg();
        test_cfg.cli.kex = NID_undef;
        test_cfg.srv.kex = NID_undef;

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        /* First-contact plaintext request, replayed as a re-key. */
        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        ctx.rekey = true;

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server accepted a re-key without KEX.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_oap_roundtrip_kex_only(void)
{
        test_enc_noauth_cfg();

        return roundtrip_kex_only();
}

static int test_oap_piggyback_data(void)
{
        struct oap_test_ctx ctx;
        const char *        cli_data_str = "client_data";
        const char *        srv_data_str = "server_data";
        buffer_t            srv_data = BUF_INIT;

        TEST_START();

        test_default_cfg();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        /* Client prepares request with piggybacked data */
        ctx.data.len  = strlen(cli_data_str);
        ctx.data.data = malloc(ctx.data.len);
        if (ctx.data.data == NULL)
                goto fail_cleanup;

        memcpy(ctx.data.data, cli_data_str, ctx.data.len);

        if (oap_cli_prepare_ctx(&ctx) < 0)
                goto fail_cleanup;

        /* Set server's response data (ctx.data will take cli data) */
        srv_data.len  = strlen(srv_data_str);
        srv_data.data = (uint8_t *) srv_data_str;

        freebuf(ctx.data);
        ctx.data.data = srv_data.data;
        ctx.data.len  = srv_data.len;
        srv_data.data = NULL;
        srv_data.len  = 0;

        if (oap_srv_process_ctx(&ctx) < 0)
                goto fail_cleanup;

        /* Verify server received client's piggybacked data */
        if (ctx.data.len != strlen(cli_data_str) ||
            memcmp(ctx.data.data, cli_data_str, ctx.data.len) != 0) {
                printf("Server did not receive correct client data.\n");
                goto fail_cleanup;
        }

        freebuf(ctx.data);

        if (oap_cli_complete_ctx(&ctx) < 0)
                goto fail_cleanup;

        /* Verify client received server's piggybacked data */
        if (ctx.data.len != strlen(srv_data_str) ||
            memcmp(ctx.data.data, srv_data_str, ctx.data.len) != 0) {
                printf("Client did not receive correct server data.\n");
                goto fail_cleanup;
        }

        /* Free the copied data */
        free(ctx.data.data);
        ctx.data.data = NULL;
        ctx.data.len = 0;

        if (memcmp(ctx.cli.key, ctx.srv.key, SYMMKEYSZ) != 0) {
                printf("Client and server keys do not match!\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        freebuf(srv_data);
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_oap_corrupted_request(void)
{
        test_default_cfg();
        test_cfg.cli.auth = AUTH;

        return corrupted_request(root_ca_crt_ec, im_ca_crt_ec);
}

static int test_oap_corrupted_response(void)
{
        test_default_cfg();

        return corrupted_response(root_ca_crt_ec, im_ca_crt_ec);
}

static int test_oap_truncated_request(void)
{
        test_default_cfg();

        return truncated_request(root_ca_crt_ec, im_ca_crt_ec);
}

/* After ID (16), timestamp (8), cipher_nid (2), kdf_nid (2), md (2) */
#define OAP_CERT_LEN_OFFSET 30
static int test_oap_inflated_length_field(void)
{
        struct oap_test_ctx ctx;
        uint16_t            fake;

        test_default_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (ctx.req_hdr.len < OAP_CERT_LEN_OFFSET + 2) {
                printf("Request too short for test.\n");
                goto fail_cleanup;
        }

        /* Set cert length to claim more bytes than packet contains */
        fake = hton16(60000);
        memcpy(ctx.req_hdr.data + OAP_CERT_LEN_OFFSET, &fake, sizeof(fake));

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject inflated length field.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Attacker claims cert is smaller - causes misparse of subsequent fields */
static int test_oap_deflated_length_field(void)
{
        struct oap_test_ctx ctx;
        uint16_t            fake;

        test_default_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (ctx.req_hdr.len < OAP_CERT_LEN_OFFSET + 2) {
                printf("Request too short for test.\n");
                goto fail_cleanup;
        }

        /* Set cert length to claim fewer bytes - will misparse rest */
        fake = hton16(1);
        memcpy(ctx.req_hdr.data + OAP_CERT_LEN_OFFSET, &fake, sizeof(fake));

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject deflated length field.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Header field offsets for byte manipulation */
#define OAP_CIPHER_NID_OFFSET 24
#define OAP_KDF_NID_OFFSET    26
#define OAP_MD_NID_OFFSET     28
#define OAP_KEX_LEN_OFFSET    32

/* A NID the crypto backend does not recognise; guarded by a test below. */
#define UNSUPPORTED_NID       9999

/* Server rejects request when cipher NID set but no KEX data provided */
static int test_oap_nid_without_kex(void)
{
        struct oap_test_ctx ctx;
        uint16_t            cipher_nid;
        uint16_t            zero = 0;

        test_enc_noauth_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        /* Tamper: keep cipher_nid but set kex_len=0, truncate KEX data */
        cipher_nid = hton16(NID_aes_256_gcm);
        memcpy(ctx.req_hdr.data + OAP_CIPHER_NID_OFFSET, &cipher_nid,
               sizeof(cipher_nid));
        memcpy(ctx.req_hdr.data + OAP_KEX_LEN_OFFSET, &zero, sizeof(zero));
        ctx.req_hdr.len = 36; /* Fixed header only, no KEX data */

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject cipher NID without KEX data.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Guard: the tamper tests below rely on UNSUPPORTED_NID being invalid. */
static int test_oap_unsupported_nid_undefined(void)
{
        TEST_START();

        if (crypt_cipher_rank(UNSUPPORTED_NID) >= 0) {
                printf("UNSUPPORTED_NID is a valid cipher NID.\n");
                goto fail;
        }

        if (crypt_kdf_rank(UNSUPPORTED_NID) >= 0) {
                printf("UNSUPPORTED_NID is a valid KDF NID.\n");
                goto fail;
        }

        if (md_validate_nid(UNSUPPORTED_NID) >= 0) {
                printf("UNSUPPORTED_NID is a valid digest NID.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Server rejects a request whose cipher/kdf/digest NID is unsupported */
static int test_oap_unsupported_nid(size_t       offset,
                                    const char * label)
{
        struct oap_test_ctx ctx;
        uint16_t            bad_nid;

        test_enc_noauth_cfg();

        TEST_START("(%s)", label);

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        bad_nid = hton16(UNSUPPORTED_NID);
        memcpy(ctx.req_hdr.data + offset, &bad_nid, sizeof(bad_nid));

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject unsupported %s NID.\n", label);
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS("(%s)", label);

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL("(%s)", label);
        return TEST_RC_FAIL;
}

static int test_oap_unsupported_nid_all(void)
{
        int ret = 0;

        ret |= test_oap_unsupported_nid(OAP_CIPHER_NID_OFFSET, "cipher");
        ret |= test_oap_unsupported_nid(OAP_KDF_NID_OFFSET, "kdf");
        ret |= test_oap_unsupported_nid(OAP_MD_NID_OFFSET, "digest");

        return ret;
}

/* Client rejects a response whose key-confirmation tag is tampered */
static int test_oap_key_confirm_mismatch(void)
{
        struct oap_test_ctx ctx;

        /* Unauthenticated + encrypted: response unsigned, KC is the gate */
        test_enc_noauth_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        /* The key-confirm tag is the last field of an unsigned response */
        ctx.resp_hdr.data[ctx.resp_hdr.len - 1] ^= 0xFF;

        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client accepted a bad key-confirmation tag.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_oap_roundtrip_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                /* Skip KEM algorithms - tested in oap_test_ml_dsa */
                if (IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_oap_roundtrip(kex_supported_nids[i]);
        }

        return ret;
}

/* Cipher negotiation - strongest cipher and KDF are selected */
static int test_oap_cipher_mismatch(void)
{
        struct oap_test_ctx ctx;

        TEST_START();

        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: AES-128-GCM, SHA-256 */
        test_cfg.srv.kex    = NID_X25519;
        test_cfg.srv.cipher = NID_aes_128_gcm;
        test_cfg.srv.kdf    = NID_sha256;
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = AUTH;

        /* Client: AES-256-GCM, SHA-512 */
        test_cfg.cli.kex    = NID_X25519;
        test_cfg.cli.cipher = NID_aes_256_gcm;
        test_cfg.cli.kdf    = NID_sha512;
        test_cfg.cli.md     = NID_sha256;
        test_cfg.cli.auth   = NO_AUTH;

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Client complete failed.\n");
                goto fail_cleanup;
        }

        /* Verify: both should have the strongest cipher */
        if (ctx.srv.nid != NID_aes_256_gcm) {
                printf("Server cipher mismatch: expected %s, got %s\n",
                       crypt_nid_to_str(NID_aes_256_gcm),
                       crypt_nid_to_str(ctx.srv.nid));
                goto fail_cleanup;
        }

        if (ctx.cli.nid != NID_aes_256_gcm) {
                printf("Client cipher mismatch: expected %s, got %s\n",
                       crypt_nid_to_str(NID_aes_256_gcm),
                       crypt_nid_to_str(ctx.cli.nid));
                goto fail_cleanup;
        }

        /* Parse response header to check negotiated KDF */
        if (ctx.resp_hdr.len > 26) {
                uint16_t resp_kdf_nid;
                /* KDF NID at offset 26: ID(16) + ts(8) + cipher(2) */
                resp_kdf_nid = ntoh16(*(uint16_t *)(ctx.resp_hdr.data + 26));

                if (resp_kdf_nid != NID_sha512) {
                        printf("Response KDF mismatch: expected %s, got %s\n",
                               md_nid_to_str(NID_sha512),
                               md_nid_to_str(resp_kdf_nid));
                        goto fail_cleanup;
                }
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Server encryption, client none: server rejects (no KEX data) */
static int test_oap_srv_enc_cli_none(void)
{
        struct oap_test_ctx ctx;

        TEST_START();

        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: encryption configured */
        test_cfg.srv.kex    = NID_X25519;
        test_cfg.srv.cipher = NID_aes_256_gcm;
        test_cfg.srv.kdf    = NID_sha256;
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = AUTH;

        /* Client: no encryption */
        test_cfg.cli.md     = NID_sha256;
        test_cfg.cli.auth   = NO_AUTH;

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        /* Server should reject: KEX required but client sent none */
        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should have rejected.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Client encryption, server none: use client settings */
static int test_oap_cli_enc_srv_none(void)
{
        struct oap_test_ctx ctx;

        TEST_START();

        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: no encryption configured */
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = AUTH;

        /* Client: encryption configured */
        test_cfg.cli.kex    = NID_X25519;
        test_cfg.cli.cipher = NID_aes_256_gcm;
        test_cfg.cli.kdf    = NID_sha256;
        test_cfg.cli.md     = NID_sha256;
        test_cfg.cli.auth   = NO_AUTH;

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Client complete failed.\n");
                goto fail_cleanup;
        }

        if (memcmp(ctx.cli.key, ctx.srv.key, SYMMKEYSZ) != 0) {
                printf("Key mismatch.\n");
                goto fail_cleanup;
        }

        if (ctx.cli.nid != NID_aes_256_gcm) {
                printf("Expected %s, got %s.\n",
                       crypt_nid_to_str(NID_aes_256_gcm),
                       crypt_nid_to_str(ctx.cli.nid));
                goto fail_cleanup;
        }

        if (ctx.srv.nid != NID_aes_256_gcm) {
                printf("Expected %s, got %s.\n",
                       crypt_nid_to_str(NID_aes_256_gcm),
                       crypt_nid_to_str(ctx.srv.nid));
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Unauthenticated server: client floor-rejects a downgraded cipher */
static int test_oap_cli_rejects_downgrade(void)
{
        struct oap_test_ctx ctx;
        uint16_t            weak;

        test_enc_noauth_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        /* Tamper: replace cipher NID with weaker one */
        weak = hton16(NID_aes_128_gcm);
        memcpy(ctx.resp_hdr.data + OAP_CIPHER_NID_OFFSET,
               &weak, sizeof(weak));

        /* Client should reject the downgraded cipher */
        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client accepted downgrade.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * Suite binding: a cipher swapped to a higher rank clears the client floor
 * check, but the bound key commits to the negotiated suite, so the swap must
 * still fail key confirmation.
 */
static int test_oap_cli_rejects_suite_swap(void)
{
        struct oap_test_ctx ctx;
        uint16_t            swap;

        /* Both AES-128-GCM: a swap to AES-256 outranks the client floor */
        test_enc_noauth_cfg();
        test_cfg.srv.cipher = NID_aes_128_gcm;
        test_cfg.cli.cipher = NID_aes_128_gcm;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        /* Swap the response cipher to a higher-ranked one */
        swap = hton16(NID_aes_256_gcm);
        memcpy(ctx.resp_hdr.data + OAP_CIPHER_NID_OFFSET,
               &swap, sizeof(swap));

        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client accepted a swapped cipher suite.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Server rejects client with weaker KEX algorithm */
static int test_oap_srv_rejects_weak_kex(void)
{
        struct oap_test_ctx ctx;

        TEST_START();

        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: secp521r1 (strong) */
        test_cfg.srv.kex    = NID_secp521r1;
        test_cfg.srv.cipher = NID_aes_256_gcm;
        test_cfg.srv.kdf    = NID_sha256;
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = AUTH;

        /* Client: ffdhe2048 (weakest) */
        test_cfg.cli.kex    = NID_ffdhe2048;
        test_cfg.cli.cipher = NID_aes_256_gcm;
        test_cfg.cli.kdf    = NID_sha256;
        test_cfg.cli.md     = NID_sha256;
        test_cfg.cli.auth   = NO_AUTH;

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        /* Server should reject: client KEX too weak */
        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject weak KEX.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Test roundtrip with different signature digest algorithms */
static int test_oap_roundtrip_md(int md)
{
        struct oap_test_ctx ctx;
        const char *        md_str = md_nid_to_str(md);

        TEST_START("(%s)", md_str ? md_str : "default");

        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: auth + KEX with specified md */
        test_cfg.srv.kex    = NID_X25519;
        test_cfg.srv.cipher = NID_aes_256_gcm;
        test_cfg.srv.kdf    = NID_sha256;
        test_cfg.srv.md     = md;
        test_cfg.srv.auth   = AUTH;

        /* Client: no auth */
        test_cfg.cli.kex    = NID_X25519;
        test_cfg.cli.cipher = NID_aes_256_gcm;
        test_cfg.cli.kdf    = NID_sha256;
        test_cfg.cli.md     = md;
        test_cfg.cli.auth   = NO_AUTH;

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Client complete failed.\n");
                goto fail_cleanup;
        }

        if (memcmp(ctx.cli.key, ctx.srv.key, SYMMKEYSZ) != 0) {
                printf("Client and server keys do not match!\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS("(%s)", md_str ? md_str : "default");

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL("(%s)", md_str ? md_str : "default");
        return TEST_RC_FAIL;
}

static int test_oap_roundtrip_md_all(void)
{
        int ret = 0;
        int i;

        /* Test with default */
        ret |= test_oap_roundtrip_md(NID_undef);

        /* Test with all supported digest NIDs */
        for (i = 0; md_supported_nids[i] != NID_undef; i++)
                ret |= test_oap_roundtrip_md(md_supported_nids[i]);

        return ret;
}

/* Timestamp is at offset 16 (after the 16-byte ID) */
#define OAP_TIMESTAMP_OFFSET 16
/* Test that packets with outdated timestamps are rejected */
/* Server rejects a request whose timestamp is outside the replay window */
static int test_oap_ts_reject(int          delta_sec,
                              const char * label)
{
        struct oap_test_ctx ctx;
        struct timespec     ts;
        uint64_t            stamp;

        test_default_cfg();

        TEST_START("(%s)", label);

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (ctx.req_hdr.len < OAP_TIMESTAMP_OFFSET + sizeof(uint64_t)) {
                printf("Request too short for test.\n");
                goto fail_cleanup;
        }

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += delta_sec;
        stamp = hton64(TS_TO_UINT64(ts));
        memcpy(ctx.req_hdr.data + OAP_TIMESTAMP_OFFSET, &stamp,
               sizeof(stamp));

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject %s packet.\n", label);
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS("(%s)", label);

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL("(%s)", label);
        return TEST_RC_FAIL;
}

static int test_oap_ts_reject_all(void)
{
        int ret = 0;

        /* Past the 20s replay window, and past the 100ms future slack. */
        ret |= test_oap_ts_reject(-(OAP_REPLAY_TIMER + 10), "outdated");
        ret |= test_oap_ts_reject(1, "future");

        return ret;
}

/* Test that replayed packets (same ID + timestamp) are rejected */
static int test_oap_replay_packet(void)
{
        struct oap_test_ctx ctx;
        buffer_t            saved_req;

        test_default_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        /* Save the request for replay */
        saved_req.len = ctx.req_hdr.len;
        saved_req.data = malloc(saved_req.len);
        if (saved_req.data == NULL) {
                printf("Failed to allocate saved request.\n");
                goto fail_cleanup;
        }
        memcpy(saved_req.data, ctx.req_hdr.data, saved_req.len);

        /* First request should succeed */
        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("First request should succeed.\n");
                free(saved_req.data);
                goto fail_cleanup;
        }

        /* Free response from first request before replay */
        freebuf(ctx.resp_hdr);

        /* Restore the saved request for replay */
        freebuf(ctx.req_hdr);
        ctx.req_hdr = saved_req;

        /* Replay must return -EREPLAY so callers can drop silently. */
        if (oap_srv_process_ctx(&ctx) != -EREPLAY) {
                printf("Replayed packet rejection != -EREPLAY.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Encode a distinct OAP session ID from an index */
static void make_id(uint8_t * id,
                    size_t    idx)
{
        memset(id, 0, OAP_ID_SIZE);
        memcpy(id, &idx, sizeof(idx));
}

/*
 * Replay cache fails closed at capacity: a flood is rejected and no genuine
 * entry is evicted (so it cannot be replayed).
 */
static int test_oap_replay_cap(void)
{
        struct oap_hdr  h;
        struct timespec now;
        uint8_t         id[OAP_ID_SIZE];
        uint64_t        stamp;
        size_t          i;

        TEST_START();

        if (oap_auth_init() < 0) {
                printf("Failed to init OAP.\n");
                goto fail;
        }

        clock_gettime(CLOCK_REALTIME, &now);
        stamp = TS_TO_UINT64(now);

        memset(&h, 0, sizeof(h));
        h.id.data   = id;
        h.id.len    = OAP_ID_SIZE;
        h.timestamp = stamp;

        /* Fill one generation bucket to capacity with distinct IDs */
        for (i = 0; i < OAP_REPLAY_MAX; i++) {
                make_id(id, i);
                if (oap_check_hdr(&h) != 0) {
                        printf("Distinct header %zu rejected.\n", i);
                        goto fail_fini;
                }
        }

        /* One past capacity fails closed (rejected, not evict-oldest) */
        make_id(id, OAP_REPLAY_MAX);
        if (oap_check_hdr(&h) != -EAUTH) {
                printf("Header past capacity not fail-closed.\n");
                goto fail_fini;
        }

        /* No genuine entry was evicted: the oldest still reads as a replay */
        make_id(id, 0);
        if (oap_check_hdr(&h) != -EREPLAY) {
                printf("Genuine entry evicted under flood.\n");
                goto fail_fini;
        }

        oap_auth_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_fini:
        oap_auth_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * Distinct timestamp generations use separate buckets and are detected
 * independently (covers the multi-generation / rotation path).
 */
static int test_oap_replay_generations(void)
{
        struct oap_hdr  h;
        struct timespec now;
        struct timespec wait;
        uint8_t         id[OAP_ID_SIZE];
        uint64_t        cur;
        uint64_t        gen_ns;
        uint64_t        off;
        uint64_t        wait_ns;
        uint64_t        stamp_a;
        uint64_t        stamp_b;

        TEST_START();

        if (oap_auth_init() < 0) {
                printf("Failed to init OAP.\n");
                goto fail;
        }

        gen_ns = (uint64_t) OAP_REPLAY_TIMER * BILLION;

        /* Prev-gen stamp flakes on staleness near a generation top. */
        clock_gettime(CLOCK_REALTIME, &now);
        cur = TS_TO_UINT64(now);
        off = cur % gen_ns;
        if (gen_ns - off < BILLION) {
                wait_ns      = gen_ns - off + MILLION;
                wait.tv_sec  = (time_t) (wait_ns / BILLION);
                wait.tv_nsec = (long) (wait_ns % BILLION);
                nanosleep(&wait, NULL);
                clock_gettime(CLOCK_REALTIME, &now);
                cur = TS_TO_UINT64(now);
        }

        /* stamp_a in the current generation, stamp_b one generation older */
        stamp_a = cur;
        stamp_b = (cur / gen_ns) * gen_ns - 1;

        memset(&h, 0, sizeof(h));
        h.id.data = id;
        h.id.len  = OAP_ID_SIZE;
        make_id(id, 1);

        /* First sighting in each generation is accepted */
        h.timestamp = stamp_a;
        if (oap_check_hdr(&h) != 0) {
                printf("Gen-A header rejected.\n");
                goto fail_fini;
        }

        h.timestamp = stamp_b;
        if (oap_check_hdr(&h) != 0) {
                printf("Gen-B header rejected.\n");
                goto fail_fini;
        }

        /* Each generation independently detects its own replay */
        h.timestamp = stamp_a;
        if (oap_check_hdr(&h) != -EREPLAY) {
                printf("Gen-A replay not detected.\n");
                goto fail_fini;
        }

        h.timestamp = stamp_b;
        if (oap_check_hdr(&h) != -EREPLAY) {
                printf("Gen-B replay not detected.\n");
                goto fail_fini;
        }

        oap_auth_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_fini:
        oap_auth_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Server rejects client certificate when root CA is missing from store */
static int test_oap_missing_root_ca(void)
{
        struct oap_test_ctx ctx;
        void *              im_ca = NULL;

        test_default_cfg();

        TEST_START();

        memset(&ctx, 0, sizeof(ctx));

        strcpy(ctx.srv.info.name, "test-1.unittest.o7s");
        strcpy(ctx.cli.info.name, "test-1.unittest.o7s");

        if (oap_auth_init() < 0) {
                printf("Failed to init OAP.\n");
                goto fail;
        }

        /* Load intermediate CA but intentionally omit the root CA */
        if (crypt_load_crt_str(im_ca_crt_ec, &im_ca) < 0) {
                printf("Failed to load intermediate CA cert.\n");
                goto fail_fini;
        }

        ctx.im_ca = im_ca;

        if (oap_auth_add_ca_crt(im_ca) < 0) {
                printf("Failed to add intermediate CA cert to store.\n");
                goto fail_fini;
        }

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_fini;
        }

        /* Server processes and signs response - succeeds without root CA */
        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_teardown;
        }

        /* Client verifies server certificate against trust store:
         * should reject because root CA is not in the store */
        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client should reject without root CA.\n");
                goto fail_teardown;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_teardown:
        oap_test_teardown(&ctx);
        TEST_FAIL();
        return TEST_RC_FAIL;
 fail_fini:
        crypt_free_crt(im_ca);
        oap_auth_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Test that client rejects server with wrong certificate name */
static int test_oap_server_name_mismatch(void)
{
        struct oap_test_ctx ctx;

        test_default_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        /* Set client's expected name to something different from cert name */
        strcpy(ctx.cli.info.name, "wrong.server.name");

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        /* Client should reject due to name mismatch */
        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client should reject server with wrong cert name.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Client requiring auth rejects a response without certificate */
static int test_oap_cli_requires_srv_auth(void)
{
        struct oap_test_ctx ctx;

        test_default_cfg();
        test_cfg.srv.auth     = NO_AUTH;
        test_cfg.cli.req_auth = true;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client should reject unauthenticated server.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Server requiring auth rejects a request without certificate */
static int test_oap_srv_requires_cli_auth(void)
{
        struct oap_test_ctx ctx;

        test_default_cfg();
        test_cfg.srv.req_auth = true;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject unauthenticated client.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Roundtrip succeeds when both sides require and provide auth */
static int test_oap_mutual_req_auth(void)
{
        struct oap_test_ctx ctx;

        test_default_cfg();
        test_cfg.srv.req_auth = true;
        test_cfg.cli.auth     = AUTH;
        test_cfg.cli.req_auth = true;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Client complete failed.\n");
                goto fail_cleanup;
        }

        if (memcmp(ctx.cli.key, ctx.srv.key, SYMMKEYSZ) != 0) {
                printf("Client and server keys do not match!\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Client rejects a server signature with a different digest */
static int test_oap_cli_rejects_md_mismatch(void)
{
        struct oap_test_ctx ctx;

        test_default_cfg();
        test_cfg.srv.md = NID_sha384;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client should reject digest mismatch.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Server rejects a client signature with a different digest */
static int test_oap_srv_rejects_md_mismatch(void)
{
        struct oap_test_ctx ctx;

        test_default_cfg();
        test_cfg.cli.auth = AUTH;
        test_cfg.cli.md   = NID_sha384;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject digest mismatch.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Naive substring search over raw bytes (memmem is not portable here). */
static bool buf_contains(const uint8_t * hay,
                         size_t          hlen,
                         const uint8_t * needle,
                         size_t          nlen)
{
        size_t i;

        if (nlen == 0 || nlen > hlen)
                return false;

        for (i = 0; i + nlen <= hlen; i++) {
                if (memcmp(hay + i, needle, nlen) == 0)
                        return true;
        }

        return false;
}

/* The server certificate must not appear in cleartext on the wire */
static int test_oap_server_cert_hidden(void)
{
        struct oap_test_ctx ctx;
        void *              crt = NULL;
        buffer_t            der = BUF_INIT;

        test_default_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (crypt_load_crt_str(signed_server_crt_ec, &crt) < 0) {
                printf("Failed to load server crt.\n");
                goto fail_cleanup;
        }

        if (crypt_crt_der(crt, &der) < 0) {
                printf("Failed to DER-encode server crt.\n");
                goto fail_crt;
        }

        if (der.len == 0 || der.len > ctx.resp_hdr.len) {
                printf("Unexpected cert/response sizes.\n");
                goto fail_der;
        }

        if (buf_contains(ctx.resp_hdr.data, ctx.resp_hdr.len,
                         der.data, der.len)) {
                printf("Server certificate found in cleartext.\n");
                goto fail_der;
        }

        /* The handshake must still complete and agree on a key */
        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Client complete failed.\n");
                goto fail_der;
        }

        if (memcmp(ctx.cli.key, ctx.srv.key, SYMMKEYSZ) != 0) {
                printf("Client and server keys do not match!\n");
                goto fail_der;
        }

        freebuf(der);
        crypt_free_crt(crt);
        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_der:
        freebuf(der);
 fail_crt:
        crypt_free_crt(crt);
 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Tampering the sealed identity block fails the handshake */
static int test_oap_sealed_tamper(void)
{
        struct oap_test_ctx ctx;
        size_t              pos;

        test_default_cfg();

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        if (ctx.resp_hdr.len < 64) {
                printf("Response too short for test.\n");
                goto fail_cleanup;
        }

        /* Flip a byte inside the sealed ciphertext, before the AEAD tag */
        pos = ctx.resp_hdr.len - 32;
        ctx.resp_hdr.data[pos] ^= 0xFF;

        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client accepted a tampered identity block.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Cleartext md-only: rsp_tag echoes H(request) and is the sole gate */
static int test_oap_cleartext_echo_tamper(void)
{
        struct oap_test_ctx ctx;

        memset(&test_cfg, 0, sizeof(test_cfg));
        test_cfg.srv.md   = NID_sha256;
        test_cfg.srv.auth = NO_AUTH;
        test_cfg.cli.md   = NID_sha256;
        test_cfg.cli.auth = NO_AUTH;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        /* rsp_tag is the trailing field of an unsealed, unsigned response */
        ctx.resp_hdr.data[ctx.resp_hdr.len - 1] ^= 0xFF;

        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client accepted a tampered request echo.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Client rejects a response whose session ID does not match the request */
static int test_oap_response_id_tamper(void)
{
        struct oap_test_ctx ctx;

        /* Cleartext md-only: no seal, so the ID check itself must reject. */
        memset(&test_cfg, 0, sizeof(test_cfg));
        test_cfg.srv.md   = NID_sha256;
        test_cfg.srv.auth = NO_AUTH;
        test_cfg.cli.md   = NID_sha256;
        test_cfg.cli.auth = NO_AUTH;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca_crt_ec, im_ca_crt_ec) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        /* The session ID is the first field of the fixed header. */
        ctx.resp_hdr.data[0] ^= 0xFF;

        if (oap_cli_complete_ctx(&ctx) == 0) {
                printf("Client accepted a mismatched response ID.\n");
                goto fail_cleanup;
        }

        oap_test_teardown(&ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int oap_test(int    argc,
             char **argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_oap_auth_init_fini();
        ret |= test_oap_replay_cap();
        ret |= test_oap_replay_generations();

#ifdef HAVE_OPENSSL
        ret |= test_oap_roundtrip_auth_only();
        ret |= test_oap_roundtrip_kex_only();
        ret |= test_oap_piggyback_data();
        ret |= test_oap_rekey_all();
        ret |= test_oap_rekey_badcache_all();
        ret |= test_oap_rekey_srv_badcache_all();
        ret |= test_oap_cli_rejects_rekey_no_kex();
        ret |= test_oap_srv_rejects_rekey_no_kex();

        ret |= test_oap_roundtrip_all();
        ret |= test_oap_roundtrip_md_all();

        ret |= test_oap_corrupted_request();
        ret |= test_oap_corrupted_response();
        ret |= test_oap_key_confirm_mismatch();
        ret |= test_oap_truncated_request();
        ret |= test_oap_inflated_length_field();
        ret |= test_oap_deflated_length_field();
        ret |= test_oap_nid_without_kex();
        ret |= test_oap_unsupported_nid_undefined();
        ret |= test_oap_unsupported_nid_all();

        ret |= test_oap_cipher_mismatch();
        ret |= test_oap_srv_enc_cli_none();
        ret |= test_oap_cli_enc_srv_none();
        ret |= test_oap_cli_rejects_downgrade();
        ret |= test_oap_cli_rejects_suite_swap();
        ret |= test_oap_srv_rejects_weak_kex();

        ret |= test_oap_ts_reject_all();
        ret |= test_oap_replay_packet();
        ret |= test_oap_missing_root_ca();
        ret |= test_oap_server_name_mismatch();

        ret |= test_oap_cli_requires_srv_auth();
        ret |= test_oap_srv_requires_cli_auth();
        ret |= test_oap_mutual_req_auth();


        ret |= test_oap_cli_rejects_md_mismatch();
        ret |= test_oap_srv_rejects_md_mismatch();

        ret |= test_oap_server_cert_hidden();
        ret |= test_oap_sealed_tamper();
        ret |= test_oap_cleartext_echo_tamper();
        ret |= test_oap_response_id_tamper();
#else
        (void) test_oap_roundtrip_auth_only;
        (void) test_oap_roundtrip_kex_only;
        (void) test_oap_piggyback_data;
        (void) test_oap_rekey_all;
        (void) test_oap_rekey_badcache_all;
        (void) test_oap_rekey_srv_badcache_all;
        (void) test_oap_cli_rejects_rekey_no_kex;
        (void) test_oap_srv_rejects_rekey_no_kex;
        (void) test_oap_roundtrip;
        (void) test_oap_roundtrip_all;
        (void) test_oap_roundtrip_md;
        (void) test_oap_roundtrip_md_all;
        (void) test_oap_corrupted_request;
        (void) test_oap_corrupted_response;
        (void) test_oap_key_confirm_mismatch;
        (void) test_oap_truncated_request;
        (void) test_oap_inflated_length_field;
        (void) test_oap_deflated_length_field;
        (void) test_oap_nid_without_kex;
        (void) test_oap_unsupported_nid;
        (void) test_oap_unsupported_nid_undefined;
        (void) test_oap_unsupported_nid_all;
        (void) test_oap_cipher_mismatch;
        (void) test_oap_srv_enc_cli_none;
        (void) test_oap_cli_enc_srv_none;
        (void) test_oap_cli_rejects_downgrade;
        (void) test_oap_cli_rejects_suite_swap;
        (void) test_oap_srv_rejects_weak_kex;
        (void) test_oap_ts_reject_all;
        (void) test_oap_replay_packet;
        (void) test_oap_replay_generations;
        (void) test_oap_missing_root_ca;
        (void) test_oap_server_name_mismatch;
        (void) test_oap_cli_requires_srv_auth;
        (void) test_oap_srv_requires_cli_auth;
        (void) test_oap_mutual_req_auth;
        (void) test_oap_cli_rejects_md_mismatch;
        (void) test_oap_srv_rejects_md_mismatch;
        (void) test_oap_server_cert_hidden;
        (void) test_oap_sealed_tamper;
        (void) test_oap_cleartext_echo_tamper;
        (void) test_oap_response_id_tamper;
        (void) test_oap_rekey;
        (void) test_oap_rekey_badcache;

        ret = TEST_RC_SKIP;
#endif
        crypt_cleanup();

        return ret;
}
