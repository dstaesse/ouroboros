/*
 * Ouroboros - Copyright (C) 2016 - 2024
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
#include <ouroboros/flow.h>
#include <ouroboros/name.h>
#include <ouroboros/random.h>
#include <ouroboros/time.h>

#include <test/test.h>
#include <test/certs.h>

#include "oap.h"
#include "common.h"

#include <stdbool.h>
#include <string.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#define AUTH    true
#define NO_AUTH false

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

static int test_oap_roundtrip_kex_only(void)
{
        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: KEX only, no auth */
        test_cfg.srv.kex    = NID_X25519;
        test_cfg.srv.cipher = NID_aes_256_gcm;
        test_cfg.srv.kdf    = NID_sha256;
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = NO_AUTH;

        /* Client: KEX only, no auth */
        test_cfg.cli.kex    = NID_X25519;
        test_cfg.cli.cipher = NID_aes_256_gcm;
        test_cfg.cli.kdf    = NID_sha256;
        test_cfg.cli.md     = NID_sha256;
        test_cfg.cli.auth   = NO_AUTH;

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
        srv_data.data = malloc(srv_data.len);
        if (srv_data.data == NULL)
                goto fail_cleanup;
        memcpy(srv_data.data, srv_data_str, srv_data.len);

        freebuf(ctx.data);
        ctx.data = srv_data;
        clrbuf(srv_data);

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
#define OAP_KEX_LEN_OFFSET    32

/* Server rejects request when cipher NID set but no KEX data provided */
static int test_oap_nid_without_kex(void)
{
        struct oap_test_ctx ctx;
        uint16_t            cipher_nid;
        uint16_t            zero = 0;

        TEST_START();

        /* Configure unsigned KEX-only mode */
        memset(&test_cfg, 0, sizeof(test_cfg));
        test_cfg.srv.kex    = NID_X25519;
        test_cfg.srv.cipher = NID_aes_256_gcm;
        test_cfg.srv.kdf    = NID_sha256;
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = NO_AUTH;
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

/* Server rejects OAP request with unsupported cipher NID */
static int test_oap_unsupported_nid(void)
{
        struct oap_test_ctx ctx;
        uint16_t            bad_nid;

        TEST_START();

        /* Configure unsigned KEX-only mode */
        memset(&test_cfg, 0, sizeof(test_cfg));
        test_cfg.srv.kex    = NID_X25519;
        test_cfg.srv.cipher = NID_aes_256_gcm;
        test_cfg.srv.kdf    = NID_sha256;
        test_cfg.srv.md     = NID_sha256;
        test_cfg.srv.auth   = NO_AUTH;
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

        /* Tamper: set cipher_nid to unsupported value */
        bad_nid = hton16(9999);
        memcpy(ctx.req_hdr.data + OAP_CIPHER_NID_OFFSET, &bad_nid,
               sizeof(bad_nid));

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject unsupported cipher NID.\n");
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

                /* Skip KEM algorithms - they're tested in oap_test_pqc */
                if (IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_oap_roundtrip(kex_supported_nids[i]);
        }

        return ret;
}

/* Cipher negotiation - client should accept server's chosen cipher */
static int test_oap_cipher_mismatch(void)
{
        struct oap_test_ctx ctx;

        TEST_START();

        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: ChaCha20-Poly1305, SHA3-256, SHA-384 */
        test_cfg.srv.kex    = NID_X25519;
        test_cfg.srv.cipher = NID_chacha20_poly1305;
        test_cfg.srv.kdf    = NID_sha3_256;
        test_cfg.srv.md     = NID_sha384;
        test_cfg.srv.auth   = AUTH;

        /* Client: AES-256-GCM, SHA-256, SHA-256 */
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

        /* Verify: both should have the server's chosen cipher and KDF */
        if (ctx.srv.nid != test_cfg.srv.cipher) {
                printf("Server cipher mismatch: expected %s, got %s\n",
                       crypt_nid_to_str(test_cfg.srv.cipher),
                       crypt_nid_to_str(ctx.srv.nid));
                goto fail_cleanup;
        }

        if (ctx.cli.nid != test_cfg.srv.cipher) {
                printf("Client cipher mismatch: expected %s, got %s\n",
                       crypt_nid_to_str(test_cfg.srv.cipher),
                       crypt_nid_to_str(ctx.cli.nid));
                goto fail_cleanup;
        }

        /* Parse response header to check negotiated KDF */
        if (ctx.resp_hdr.len > 26) {
                uint16_t resp_kdf_nid;
                /* KDF NID at offset 26: ID(16) + ts(8) + cipher(2) */
                resp_kdf_nid = ntoh16(*(uint16_t *)(ctx.resp_hdr.data + 26));

                if (resp_kdf_nid != test_cfg.srv.kdf) {
                        printf("Response KDF mismatch: expected %s, got %s\n",
                               md_nid_to_str(test_cfg.srv.kdf),
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

        /* Test with default (0) */
        ret |= test_oap_roundtrip_md(0);

        /* Test with all supported digest NIDs */
        for (i = 0; md_supported_nids[i] != NID_undef; i++)
                ret |= test_oap_roundtrip_md(md_supported_nids[i]);

        return ret;
}

/* Timestamp is at offset 16 (after the 16-byte ID) */
#define OAP_TIMESTAMP_OFFSET 16
/* Test that packets with outdated timestamps are rejected */
static int test_oap_outdated_packet(void)
{
        struct oap_test_ctx ctx;
        struct timespec     old_ts;
        uint64_t            old_stamp;

        test_default_cfg();

        TEST_START();

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

        /* Set timestamp to 30 seconds in the past (> 20s replay timer) */
        clock_gettime(CLOCK_REALTIME, &old_ts);
        old_ts.tv_sec -= OAP_REPLAY_TIMER + 10;
        old_stamp = hton64(TS_TO_UINT64(old_ts));
        memcpy(ctx.req_hdr.data + OAP_TIMESTAMP_OFFSET, &old_stamp,
               sizeof(old_stamp));

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject outdated packet.\n");
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

/* Test that packets from the future are rejected */
static int test_oap_future_packet(void)
{
        struct oap_test_ctx ctx;
        struct timespec     future_ts;
        uint64_t            future_stamp;

        test_default_cfg();

        TEST_START();

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

        /* Set timestamp to 1 second in the future (> 100ms slack) */
        clock_gettime(CLOCK_REALTIME, &future_ts);
        future_ts.tv_sec += 1;
        future_stamp = hton64(TS_TO_UINT64(future_ts));
        memcpy(ctx.req_hdr.data + OAP_TIMESTAMP_OFFSET, &future_stamp,
               sizeof(future_stamp));

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject future packet.\n");
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

        /* Replayed request should fail */
        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject replayed packet.\n");
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

int oap_test(int    argc,
             char **argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_oap_auth_init_fini();

#ifdef HAVE_OPENSSL
        ret |= test_oap_roundtrip_auth_only();
        ret |= test_oap_roundtrip_kex_only();
        ret |= test_oap_piggyback_data();

        ret |= test_oap_roundtrip_all();
        ret |= test_oap_roundtrip_md_all();

        ret |= test_oap_corrupted_request();
        ret |= test_oap_corrupted_response();
        ret |= test_oap_truncated_request();
        ret |= test_oap_inflated_length_field();
        ret |= test_oap_deflated_length_field();
        ret |= test_oap_nid_without_kex();
        ret |= test_oap_unsupported_nid();

        ret |= test_oap_cipher_mismatch();

        ret |= test_oap_outdated_packet();
        ret |= test_oap_future_packet();
        ret |= test_oap_replay_packet();
        ret |= test_oap_server_name_mismatch();
#else
        (void) test_oap_roundtrip_auth_only;
        (void) test_oap_roundtrip_kex_only;
        (void) test_oap_piggyback_data;
        (void) test_oap_roundtrip;
        (void) test_oap_roundtrip_all;
        (void) test_oap_roundtrip_md;
        (void) test_oap_roundtrip_md_all;
        (void) test_oap_corrupted_request;
        (void) test_oap_corrupted_response;
        (void) test_oap_truncated_request;
        (void) test_oap_inflated_length_field;
        (void) test_oap_deflated_length_field;
        (void) test_oap_nid_without_kex;
        (void) test_oap_unsupported_nid;
        (void) test_oap_cipher_mismatch;
        (void) test_oap_outdated_packet;
        (void) test_oap_future_packet;
        (void) test_oap_replay_packet;
        (void) test_oap_server_name_mismatch;

        ret = TEST_RC_SKIP;
#endif
        return ret;
}
