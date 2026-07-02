/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Unit tests of OAP ML-KEM/ML-DSA key exchange
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
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include <ouroboros/crypt.h>
#include <ouroboros/endian.h>
#include <ouroboros/flow.h>
#include <ouroboros/name.h>
#include <ouroboros/random.h>
#include <test/test.h>

#include <test/certs/ml_dsa.h>

#include "oap.h"
#include "common.h"

#include <stdbool.h>
#include <string.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#define CLI_ENCAP KEM_MODE_CLIENT_ENCAP
#define SRV_ENCAP KEM_MODE_SERVER_ENCAP

/* Wire constants for inspecting the encoded kex_len field. */
#define OAP_KEX_LEN_OFFSET 32
#define OAP_KEX_ROLE_BIT   0x4000 /* bit 14: 1 = client encaps */

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

struct test_cfg test_cfg;

/* KEM keypair storage for tests (server-side keypair for KEM modes) */
static void *   test_kem_pkp    = NULL;  /* Private key pair  */
static uint8_t  test_kem_pk[4096];       /* Public key buffer */
static size_t   test_kem_pk_len = 0;

/* Mock load - called by load_*_credentials in common.c */
int mock_load_credentials(void ** pkp,
                          void ** crt)
{
        *pkp = NULL;
        *crt = NULL;

        if (crypt_load_privkey_str(server_pkp_ml, pkp) < 0)
                return -1;

        if (crypt_load_crt_str(signed_server_crt_ml, crt) < 0) {
                crypt_free_key(*pkp);
                *pkp = NULL;
                return -1;
        }

        return 0;
}

int load_server_kem_keypair(const char * name,
                            bool         raw_fmt,
                            void **      pkp)
{
#ifdef HAVE_OPENSSL
        struct sec_config local_cfg;
        ssize_t           pk_len;

        (void) name;
        (void) raw_fmt;

        /*
        * Uses reference counting. The caller will call
        * EVP_PKEY_free which decrements the count.
        */
        if (test_kem_pkp != NULL) {
                if (EVP_PKEY_up_ref((EVP_PKEY *)test_kem_pkp) != 1)
                        return -1;

                *pkp = test_kem_pkp;
                return 0;
        }

        /*
         * Generate a new KEM keypair from test_cfg.srv.kex.
         */
        memset(&local_cfg, 0, sizeof(local_cfg));
        if (test_cfg.srv.kex == NID_undef)
                goto fail;

        SET_KEX_ALGO_NID(&local_cfg, test_cfg.srv.kex);

        pk_len = kex_pkp_create(&local_cfg, &test_kem_pkp, test_kem_pk);
        if (pk_len < 0)
                goto fail;

        test_kem_pk_len = (size_t) pk_len;

        if (EVP_PKEY_up_ref((EVP_PKEY *)test_kem_pkp) != 1)
                goto fail_ref;

        *pkp = test_kem_pkp;

        return 0;
 fail_ref:
        kex_pkp_destroy(test_kem_pkp);
        test_kem_pkp = NULL;
        test_kem_pk_len = 0;
 fail:
        return -1;

#else
        (void) name;
        (void) raw_fmt;
        (void) pkp;
        return -1;
#endif
}

int load_server_kem_pk(const char *        name,
                       struct sec_config * cfg,
                       buffer_t *          pk)
{
        ssize_t len;

        (void) name;

        if (test_kem_pk_len > 0) {
                pk->data = malloc(test_kem_pk_len);
                if (pk->data == NULL)
                        return -1;
                memcpy(pk->data, test_kem_pk, test_kem_pk_len);
                pk->len = test_kem_pk_len;
                return 0;
        }

        /* Generate keypair on demand if not already done */
        len = kex_pkp_create(cfg, &test_kem_pkp, test_kem_pk);
        if (len < 0)
                return -1;

        test_kem_pk_len = (size_t) len;
        pk->data = malloc(test_kem_pk_len);
        if (pk->data == NULL)
                return -1;

        memcpy(pk->data, test_kem_pk, test_kem_pk_len);
        pk->len = test_kem_pk_len;

        return 0;
}

static void reset_kem_state(void)
{
        if (test_kem_pkp != NULL) {
                kex_pkp_destroy(test_kem_pkp);
                test_kem_pkp = NULL;
        }
        test_kem_pk_len = 0;
}

static void test_cfg_init(int  kex,
                          int  cipher,
                          int  kdf,
                          int  kem_mode,
                          bool cli_auth)
{
        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server config */
        test_cfg.srv.kex      = kex;
        test_cfg.srv.cipher   = cipher;
        test_cfg.srv.kdf      = kdf;
        test_cfg.srv.kem_mode = kem_mode;
        test_cfg.srv.auth     = true;

        /* Client config */
        test_cfg.cli.kex      = kex;
        test_cfg.cli.cipher   = cipher;
        test_cfg.cli.kdf      = kdf;
        test_cfg.cli.kem_mode = kem_mode;
        test_cfg.cli.auth     = cli_auth;
}

static int oap_test_setup_kem(struct oap_test_ctx * ctx,
                              const char *          root_ca,
                              const char *          im_ca)
{
        reset_kem_state();
        return oap_test_setup(ctx, root_ca, im_ca);
}

static void oap_test_teardown_kem(struct oap_test_ctx * ctx)
{
        oap_test_teardown(ctx);
}

static int test_oap_roundtrip_auth_only(void)
{
        test_cfg_init(NID_undef, NID_undef, NID_undef, 0, false);

        return roundtrip_auth_only(root_ca_crt_ml, im_ca_crt_ml);
}

/* Digest pin does not apply to PQC: the digest is intrinsic */
static int test_oap_cli_md_pin_exempts_pqc(void)
{
        test_cfg_init(NID_undef, NID_undef, NID_undef, 0, NO_AUTH);
        test_cfg.cli.md = NID_sha256;

        return roundtrip_auth_only(root_ca_crt_ml, im_ca_crt_ml);
}

static int test_oap_srv_md_pin_exempts_pqc(void)
{
        test_cfg_init(NID_undef, NID_undef, NID_undef, 0, AUTH);
        test_cfg.srv.md = NID_sha256;

        return roundtrip_auth_only(root_ca_crt_ml, im_ca_crt_ml);
}

static int test_oap_rekey(bool srv_auth,
                          bool cli_auth)
{
        test_cfg_init(NID_X25519, NID_aes_256_gcm, NID_sha256,
                      0, cli_auth);
        test_cfg.srv.auth = srv_auth;

        return roundtrip_rekey(root_ca_crt_ml, im_ca_crt_ml,
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

static int test_oap_rekey_badcache(bool cli_auth)
{
        test_cfg_init(NID_X25519, NID_aes_256_gcm, NID_sha256,
                      0, cli_auth);

        return roundtrip_rekey_badcache(root_ca_crt_ml, im_ca_crt_ml,
                                        cli_auth);
}

static int test_oap_rekey_badcache_all(void)
{
        int ret = 0;

        ret |= test_oap_rekey_badcache(NO_AUTH);
        ret |= test_oap_rekey_badcache(AUTH);

        return ret;
}

static int test_oap_rekey_srv_badcache(bool srv_auth)
{
        test_cfg_init(NID_X25519, NID_aes_256_gcm, NID_sha256,
                      0, AUTH);
        test_cfg.srv.auth = srv_auth;

        return roundtrip_rekey_srv_badcache(root_ca_crt_ml, im_ca_crt_ml,
                                            srv_auth);
}

static int test_oap_rekey_srv_badcache_all(void)
{
        int ret = 0;

        ret |= test_oap_rekey_srv_badcache(AUTH);
        ret |= test_oap_rekey_srv_badcache(NO_AUTH);

        return ret;
}

static int test_oap_corrupted_request(void)
{
        test_cfg_init(NID_MLKEM768, NID_aes_256_gcm, get_random_kdf(),
                      SRV_ENCAP, AUTH);

        return corrupted_request(root_ca_crt_ml, im_ca_crt_ml);
}

static int test_oap_corrupted_response(void)
{
        test_cfg_init(NID_MLKEM768, NID_aes_256_gcm, get_random_kdf(),
                      SRV_ENCAP, NO_AUTH);

        return corrupted_response(root_ca_crt_ml, im_ca_crt_ml);
}

static int test_oap_truncated_request(void)
{
        test_cfg_init(NID_MLKEM768, NID_aes_256_gcm, get_random_kdf(),
                      SRV_ENCAP, NO_AUTH);

        return truncated_request(root_ca_crt_ml, im_ca_crt_ml);
}

static int test_oap_roundtrip_kem(int kex,
                                  int kem_mode)
{
        struct oap_test_ctx ctx;
        const char *        kex_str  = kex_nid_to_str(kex);
        const char *        mode_str = kem_mode == CLI_ENCAP ? "cli" : "srv";

        test_cfg_init(kex, NID_aes_256_gcm, get_random_kdf(),
                      kem_mode, NO_AUTH);

        TEST_START("(%s, %s encaps)", kex_str, mode_str);

        if (oap_test_setup_kem(&ctx, root_ca_crt_ml, im_ca_crt_ml) < 0)
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

        if (ctx.cli.nid == NID_undef ||
            ctx.srv.nid == NID_undef) {
                printf("Cipher not set in flow.\n");
                goto fail_cleanup;
        }

        oap_test_teardown_kem(&ctx);

        TEST_SUCCESS("(%s, %s encaps)", kex_str, mode_str);
        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown_kem(&ctx);
 fail:
        TEST_FAIL("(%s, %s encaps)", kex_str, mode_str);
        return TEST_RC_FAIL;
}

static int test_oap_roundtrip_kem_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                if (!IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_oap_roundtrip_kem(kex_supported_nids[i], SRV_ENCAP);
                ret |= test_oap_roundtrip_kem(kex_supported_nids[i], CLI_ENCAP);
        }

        return ret;
}

/* Re-key over a KEM KEX: forced ephemeral server-encap + cert-drop cache. */
static int test_oap_rekey_kem(int kex,
                              int kem_mode)
{
        struct oap_test_ctx ctx;
        const char *        kex_str  = kex_nid_to_str(kex);
        const char *        mode_str = "srv";
        uint8_t             key0[SYMMKEYSZ];

        if (kem_mode == CLI_ENCAP)
                mode_str = "cli";

        test_cfg_init(kex, NID_aes_256_gcm, get_random_kdf(),
                      kem_mode, NO_AUTH);

        TEST_START("(%s, %s encaps)", kex_str, mode_str);

        if (oap_test_setup_kem(&ctx, root_ca_crt_ml, im_ca_crt_ml) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Initial client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Initial server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Initial client complete failed.\n");
                goto fail_cleanup;
        }

        if (memcmp(ctx.cli.key, ctx.srv.key, SYMMKEYSZ) != 0) {
                printf("Initial keys do not match.\n");
                goto fail_cleanup;
        }

        if (ctx.cli_crt.len == 0) {
                printf("Server cert was not cached for re-key.\n");
                goto fail_cleanup;
        }

        memcpy(key0, ctx.cli.key, SYMMKEYSZ);

        freebuf(ctx.req_hdr);
        freebuf(ctx.resp_hdr);
        freebuf(ctx.data);

        ctx.rekey = true;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Re-key client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Re-key server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Re-key client complete failed.\n");
                goto fail_cleanup;
        }

        if (memcmp(ctx.cli.key, ctx.srv.key, SYMMKEYSZ) != 0) {
                printf("Re-key keys do not match.\n");
                goto fail_cleanup;
        }

        if (memcmp(ctx.cli.key, key0, SYMMKEYSZ) == 0) {
                printf("Re-key did not produce a fresh key.\n");
                goto fail_cleanup;
        }

        oap_test_teardown_kem(&ctx);

        TEST_SUCCESS("(%s, %s encaps)", kex_str, mode_str);
        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown_kem(&ctx);
 fail:
        TEST_FAIL("(%s, %s encaps)", kex_str, mode_str);
        return TEST_RC_FAIL;
}

static int test_oap_rekey_kem_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo = kex_nid_to_str(kex_supported_nids[i]);

                if (!IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_oap_rekey_kem(kex_supported_nids[i], SRV_ENCAP);
                ret |= test_oap_rekey_kem(kex_supported_nids[i], CLI_ENCAP);
        }

        return ret;
}

/*
 * Client-encap bakes the KDF into the ciphertext, so the server cannot
 * upgrade it: a client KDF weaker than the server floor must be rejected.
 */
static int test_oap_kem_kdf_floor(int kex)
{
        struct oap_test_ctx ctx;
        const char *        kex_str = kex_nid_to_str(kex);

        test_cfg_init(kex, NID_aes_256_gcm, NID_sha256,
                      CLI_ENCAP, NO_AUTH);
        test_cfg.srv.kdf = NID_sha512;
        test_cfg.cli.kdf = NID_sha256;

        TEST_START("(%s)", kex_str);

        if (oap_test_setup_kem(&ctx, root_ca_crt_ml, im_ca_crt_ml) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server accepted a client KDF below its floor.\n");
                goto fail_cleanup;
        }

        oap_test_teardown_kem(&ctx);

        TEST_SUCCESS("(%s)", kex_str);
        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown_kem(&ctx);
 fail:
        TEST_FAIL("(%s)", kex_str);
        return TEST_RC_FAIL;
}

/*
 * A client-encap flow re-keys to ephemeral server-encap, so it keeps
 * forward secrecy. The re-key request must advertise server-encap
 * (kex_len Role bit clear) rather than re-using client encapsulation.
 */
static int test_oap_rekey_kem_forcing(int kex)
{
        struct oap_test_ctx ctx;
        const char *        kex_str = kex_nid_to_str(kex);
        uint16_t            kex_len;

        test_cfg_init(kex, NID_aes_256_gcm, NID_sha256,
                      CLI_ENCAP, NO_AUTH);

        TEST_START("(%s)", kex_str);

        if (oap_test_setup_kem(&ctx, root_ca_crt_ml, im_ca_crt_ml) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Initial client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Initial server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Initial client complete failed.\n");
                goto fail_cleanup;
        }

        freebuf(ctx.req_hdr);
        freebuf(ctx.resp_hdr);
        freebuf(ctx.data);

        ctx.rekey = true;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Re-key client prepare failed.\n");
                goto fail_cleanup;
        }

        memcpy(&kex_len, ctx.req_hdr.data + OAP_KEX_LEN_OFFSET,
               sizeof(kex_len));
        kex_len = ntoh16(kex_len);

        if (kex_len & OAP_KEX_ROLE_BIT) {
                printf("Re-key did not force server-encap KEX.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Re-key server process failed.\n");
                goto fail_cleanup;
        }

        if (oap_cli_complete_ctx(&ctx) < 0) {
                printf("Re-key client complete failed.\n");
                goto fail_cleanup;
        }

        oap_test_teardown_kem(&ctx);

        TEST_SUCCESS("(%s)", kex_str);
        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown_kem(&ctx);
 fail:
        TEST_FAIL("(%s)", kex_str);
        return TEST_RC_FAIL;
}

static int test_oap_kem_srv_uncfg(int kex)
{
        struct oap_test_ctx ctx;
        const char *        kex_str = kex_nid_to_str(kex);

        memset(&test_cfg, 0, sizeof(test_cfg));

        /* Server: auth only, no KEX configured */
        test_cfg.srv.auth = true;

        /* Client: requests KEM with server-side encapsulation */
        test_cfg.cli.kex      = kex;
        test_cfg.cli.cipher   = NID_aes_256_gcm;
        test_cfg.cli.kdf      = get_random_kdf();
        test_cfg.cli.kem_mode = SRV_ENCAP;
        test_cfg.cli.auth     = false;

        TEST_START("(%s)", kex_str);

        if (oap_test_setup_kem(&ctx, root_ca_crt_ml,
                               im_ca_crt_ml) < 0)
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

        if (ctx.cli.nid == NID_undef ||
            ctx.srv.nid == NID_undef) {
                printf("Cipher not set in flow.\n");
                goto fail_cleanup;
        }

        oap_test_teardown_kem(&ctx);

        TEST_SUCCESS("(%s)", kex_str);
        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown_kem(&ctx);
 fail:
        TEST_FAIL("(%s)", kex_str);
        return TEST_RC_FAIL;
}

static int test_oap_kem_srv_uncfg_all(void)
{
        int ret = 0;
        int i;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                const char * algo;

                algo = kex_nid_to_str(kex_supported_nids[i]);

                if (!IS_KEM_ALGORITHM(algo))
                        continue;

                ret |= test_oap_kem_srv_uncfg(kex_supported_nids[i]);
        }

        return ret;
}

int oap_test_ml_dsa(int    argc,
                    char **argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

#ifdef HAVE_ML
        ret |= test_oap_roundtrip_auth_only();
        ret |= test_oap_cli_md_pin_exempts_pqc();
        ret |= test_oap_srv_md_pin_exempts_pqc();

        ret |= test_oap_roundtrip_kem_all();

        ret |= test_oap_kem_srv_uncfg_all();

        ret |= test_oap_corrupted_request();
        ret |= test_oap_corrupted_response();
        ret |= test_oap_truncated_request();

        ret |= test_oap_rekey_all();
        ret |= test_oap_rekey_badcache_all();
        ret |= test_oap_rekey_srv_badcache_all();
        ret |= test_oap_rekey_kem_all();
        ret |= test_oap_kem_kdf_floor(NID_MLKEM768);
        ret |= test_oap_rekey_kem_forcing(NID_MLKEM768);
#else
        (void) test_oap_roundtrip_auth_only;
        (void) test_oap_cli_md_pin_exempts_pqc;
        (void) test_oap_srv_md_pin_exempts_pqc;
        (void) test_oap_rekey;
        (void) test_oap_rekey_all;
        (void) test_oap_rekey_badcache;
        (void) test_oap_rekey_badcache_all;
        (void) test_oap_rekey_srv_badcache;
        (void) test_oap_rekey_srv_badcache_all;
        (void) test_oap_roundtrip_kem;
        (void) test_oap_roundtrip_kem_all;
        (void) test_oap_rekey_kem;
        (void) test_oap_rekey_kem_all;
        (void) test_oap_kem_kdf_floor;
        (void) test_oap_rekey_kem_forcing;
        (void) test_oap_kem_srv_uncfg;
        (void) test_oap_kem_srv_uncfg_all;
        (void) test_oap_corrupted_request;
        (void) test_oap_corrupted_response;
        (void) test_oap_truncated_request;

        ret = TEST_RC_SKIP;
#endif
        crypt_cleanup();

        return ret;
}
