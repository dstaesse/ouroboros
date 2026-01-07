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

#ifndef IRMD_TESTS_COMMON_H
#define IRMD_TESTS_COMMON_H

#include <ouroboros/utils.h>
#include <ouroboros/flow.h>
#include <ouroboros/name.h>
#include <test/test.h>

#include <stdbool.h>

/* Per-side security configuration for tests */
struct test_sec_cfg {
        int  kex;       /* KEX algorithm NID */
        int  cipher;    /* Cipher NID for encryption */
        int  kdf;       /* KDF NID for key derivation */
        int  md;        /* Digest NID for signatures */
        int  kem_mode;  /* KEM encapsulation mode (0 for ECDH) */
        bool auth;      /* Use authentication (certificates) */
};

/* Test configuration - set by each test before running roundtrip */
extern struct test_cfg {
        struct test_sec_cfg srv;
        struct test_sec_cfg cli;
} test_cfg;

/* Each test file defines this with its own certificates */
extern int mock_load_credentials(void ** pkp,
                                 void ** crt);

/* Per-side test context */
struct oap_test_side {
        struct name_info info;
        struct flow_info flow;
        uint8_t          key[SYMMKEYSZ];
        int              nid;
        void *           state;
};

/* Test context - holds all common state for OAP tests */
struct oap_test_ctx {
        struct oap_test_side srv;
        struct oap_test_side cli;

        buffer_t             req_hdr;
        buffer_t             resp_hdr;
        buffer_t             data;
        void *               root_ca;
        void *               im_ca;
};

int  oap_test_setup(struct oap_test_ctx * ctx,
                    const char *          root_ca_str,
                    const char *          im_ca_str);

void oap_test_teardown(struct oap_test_ctx * ctx);

int  oap_cli_prepare_ctx(struct oap_test_ctx * ctx);

int  oap_srv_process_ctx(struct oap_test_ctx * ctx);

int  oap_cli_complete_ctx(struct oap_test_ctx * ctx);

int  roundtrip_auth_only(const char * root_ca,
                         const char * im_ca_str);

int  roundtrip_kex_only(void);

int  corrupted_request(const char * root_ca,
                       const char * im_ca_str);

int  corrupted_response(const char * root_ca,
                        const char * im_ca_str);

int  truncated_request(const char * root_ca,
                       const char * im_ca_str);

#endif /* IRMD_TESTS_COMMON_H */
