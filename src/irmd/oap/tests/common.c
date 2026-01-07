/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Common test helper functions for OAP tests
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

#include "common.h"

#include <ouroboros/crypt.h>

#include "oap.h"

#include <string.h>
#include <stdio.h>

int load_srv_kex_config(const struct name_info * info,
                        struct sec_config *      cfg)
{
        (void) info;

        memset(cfg, 0, sizeof(*cfg));

        if (test_cfg.srv.kex == NID_undef)
                return 0;

        SET_KEX_ALGO_NID(cfg, test_cfg.srv.kex);
        SET_KEX_CIPHER_NID(cfg, test_cfg.srv.cipher);
        SET_KEX_KDF_NID(cfg, test_cfg.srv.kdf);
        SET_KEX_DIGEST_NID(cfg, test_cfg.srv.md);
        SET_KEX_KEM_MODE(cfg, test_cfg.srv.kem_mode);

        return 0;
}

int load_cli_kex_config(const struct name_info * info,
                        struct sec_config *      cfg)
{
        (void) info;

        memset(cfg, 0, sizeof(*cfg));

        if (test_cfg.cli.kex == NID_undef)
                return 0;

        SET_KEX_ALGO_NID(cfg, test_cfg.cli.kex);
        SET_KEX_CIPHER_NID(cfg, test_cfg.cli.cipher);
        SET_KEX_KDF_NID(cfg, test_cfg.cli.kdf);
        SET_KEX_DIGEST_NID(cfg, test_cfg.cli.md);
        SET_KEX_KEM_MODE(cfg, test_cfg.cli.kem_mode);

        return 0;
}

int load_srv_credentials(const struct name_info * info,
                         void **                  pkp,
                         void **                  crt)
{
        (void) info;

        *pkp = NULL;
        *crt = NULL;

        if (!test_cfg.srv.auth)
                return 0;

        return mock_load_credentials(pkp, crt);
}

int load_cli_credentials(const struct name_info * info,
                         void **                  pkp,
                         void **                  crt)
{
        (void) info;

        *pkp = NULL;
        *crt = NULL;

        if (!test_cfg.cli.auth)
                return 0;

        return mock_load_credentials(pkp, crt);
}

int oap_test_setup(struct oap_test_ctx * ctx,
                   const char *          root_ca_str,
                   const char *          im_ca_str)
{
        memset(ctx, 0, sizeof(*ctx));

        strcpy(ctx->srv.info.name, "test-1.unittest.o7s");
        strcpy(ctx->cli.info.name, "test-1.unittest.o7s");

        if (oap_auth_init() < 0) {
                printf("Failed to init OAP.\n");
                goto fail_init;
        }

        if (crypt_load_crt_str(root_ca_str, &ctx->root_ca) < 0) {
                printf("Failed to load root CA cert.\n");
                goto fail_root_ca;
        }

        if (crypt_load_crt_str(im_ca_str, &ctx->im_ca) < 0) {
                printf("Failed to load intermediate CA cert.\n");
                goto fail_im_ca;
        }

        if (oap_auth_add_ca_crt(ctx->root_ca) < 0) {
                printf("Failed to add root CA cert to store.\n");
                goto fail_add_ca;
        }

        if (oap_auth_add_ca_crt(ctx->im_ca) < 0) {
                printf("Failed to add intermediate CA cert to store.\n");
                goto fail_add_ca;
        }

        return 0;

 fail_add_ca:
        crypt_free_crt(ctx->im_ca);
 fail_im_ca:
        crypt_free_crt(ctx->root_ca);
 fail_root_ca:
        oap_auth_fini();
 fail_init:
        memset(ctx, 0, sizeof(*ctx));
        return -1;
}

void oap_test_teardown(struct oap_test_ctx * ctx)
{
        struct crypt_sk res;
        buffer_t        dummy = BUF_INIT;

        if (ctx->cli.state != NULL) {
                res.key = ctx->cli.key;
                oap_cli_complete(ctx->cli.state, &ctx->cli.info, dummy,
                                 &ctx->data, &res);
                ctx->cli.state = NULL;
        }

        freebuf(ctx->data);
        freebuf(ctx->resp_hdr);
        freebuf(ctx->req_hdr);

        crypt_free_crt(ctx->im_ca);
        crypt_free_crt(ctx->root_ca);

        oap_auth_fini();
        memset(ctx, 0, sizeof(*ctx));
}

int oap_cli_prepare_ctx(struct oap_test_ctx * ctx)
{
        return oap_cli_prepare(&ctx->cli.state, &ctx->cli.info, &ctx->req_hdr,
                               ctx->data);
}

int oap_srv_process_ctx(struct oap_test_ctx * ctx)
{
        struct crypt_sk res = { .nid = NID_undef, .key = ctx->srv.key };
        int            ret;

        ret = oap_srv_process(&ctx->srv.info, ctx->req_hdr,
                              &ctx->resp_hdr, &ctx->data, &res);
        if (ret == 0)
                ctx->srv.nid = res.nid;

        return ret;
}

int oap_cli_complete_ctx(struct oap_test_ctx * ctx)
{
        struct crypt_sk res = { .nid = NID_undef, .key = ctx->cli.key };
        int            ret;

        ret = oap_cli_complete(ctx->cli.state, &ctx->cli.info, ctx->resp_hdr,
                               &ctx->data, &res);
        ctx->cli.state = NULL;

        if (ret == 0)
                ctx->cli.nid = res.nid;

        return ret;
}

int roundtrip_auth_only(const char * root_ca,
                        const char * im_ca_str)
{
        struct oap_test_ctx ctx;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca, im_ca_str) < 0)
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

        if (ctx.cli.nid != NID_undef || ctx.srv.nid != NID_undef) {
                printf("Cipher should not be set for auth-only.\n");
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

int roundtrip_kex_only(void)
{
        struct name_info cli_info;
        struct name_info srv_info;
        struct crypt_sk   res;
        uint8_t          cli_key[SYMMKEYSZ];
        uint8_t          srv_key[SYMMKEYSZ];
        int              cli_nid;
        int              srv_nid;
        buffer_t         req_hdr   = BUF_INIT;
        buffer_t         resp_hdr  = BUF_INIT;
        buffer_t         data      = BUF_INIT;
        void *           cli_state = NULL;

        TEST_START();

        memset(&cli_info, 0, sizeof(cli_info));
        memset(&srv_info, 0, sizeof(srv_info));

        strcpy(cli_info.name, "test-1.unittest.o7s");
        strcpy(srv_info.name, "test-1.unittest.o7s");

        if (oap_auth_init() < 0) {
                printf("Failed to init OAP.\n");
                goto fail;
        }

        if (oap_cli_prepare(&cli_state, &cli_info, &req_hdr,
                            data) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        res.key = srv_key;

        if (oap_srv_process(&srv_info, req_hdr, &resp_hdr, &data, &res) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        srv_nid = res.nid;

        res.key = cli_key;

        if (oap_cli_complete(cli_state, &cli_info, resp_hdr, &data, &res) < 0) {
                printf("Client complete failed.\n");
                cli_state = NULL;
                goto fail_cleanup;
        }

        cli_nid = res.nid;
        cli_state = NULL;

        if (memcmp(cli_key, srv_key, SYMMKEYSZ) != 0) {
                printf("Client and server keys do not match!\n");
                goto fail_cleanup;
        }

        if (cli_nid == NID_undef || srv_nid == NID_undef) {
                printf("Cipher should be set for kex-only.\n");
                goto fail_cleanup;
        }

        freebuf(resp_hdr);
        freebuf(req_hdr);
        oap_auth_fini();

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_cleanup:
        if (cli_state != NULL) {
                res.key = cli_key;
                oap_cli_complete(cli_state, &cli_info, resp_hdr, &data, &res);
        }
        freebuf(resp_hdr);
        freebuf(req_hdr);
        oap_auth_fini();
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int corrupted_request(const char * root_ca,
                      const char * im_ca_str)
{
        struct oap_test_ctx ctx;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca, im_ca_str) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        /* Corrupt the request */
        if (ctx.req_hdr.len > 100) {
                ctx.req_hdr.data[50] ^= 0xFF;
                ctx.req_hdr.data[51] ^= 0xAA;
                ctx.req_hdr.data[52] ^= 0x55;
        }

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject corrupted request.\n");
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

int corrupted_response(const char * root_ca,
                       const char * im_ca_str)
{
        struct oap_test_ctx ctx;
        struct crypt_sk      res;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca, im_ca_str) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        if (oap_srv_process_ctx(&ctx) < 0) {
                printf("Server process failed.\n");
                goto fail_cleanup;
        }

        /* Corrupt the response */
        if (ctx.resp_hdr.len > 100) {
                ctx.resp_hdr.data[50] ^= 0xFF;
                ctx.resp_hdr.data[51] ^= 0xAA;
                ctx.resp_hdr.data[52] ^= 0x55;
        }

        res.key = ctx.cli.key;

        if (oap_cli_complete(ctx.cli.state, &ctx.cli.info, ctx.resp_hdr,
                             &ctx.data, &res) == 0) {
                printf("Client should reject corrupted response.\n");
                ctx.cli.state = NULL;
                goto fail_cleanup;
        }

        ctx.cli.state = NULL;

        oap_test_teardown(&ctx);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int truncated_request(const char * root_ca,
                      const char * im_ca_str)
{
        struct oap_test_ctx ctx;
        size_t              orig_len;

        TEST_START();

        if (oap_test_setup(&ctx, root_ca, im_ca_str) < 0)
                goto fail;

        if (oap_cli_prepare_ctx(&ctx) < 0) {
                printf("Client prepare failed.\n");
                goto fail_cleanup;
        }

        /* Truncate the request buffer */
        orig_len = ctx.req_hdr.len;
        ctx.req_hdr.len = orig_len / 2;

        if (oap_srv_process_ctx(&ctx) == 0) {
                printf("Server should reject truncated request.\n");
                ctx.req_hdr.len = orig_len;
                goto fail_cleanup;
        }

        ctx.req_hdr.len = orig_len;

        oap_test_teardown(&ctx);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_cleanup:
        oap_test_teardown(&ctx);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}
