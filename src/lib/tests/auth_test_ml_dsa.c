/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the ML-DSA-65 authentication functions
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
#include <ouroboros/crypt.h>
#include <ouroboros/random.h>
#include <ouroboros/utils.h>

#include <test/certs/ml_dsa.h>

#define TEST_MSG_SIZE 1500

static int test_auth_create_destroy_ctx(void)
{
        struct auth_ctx * ctx;

        TEST_START();

        ctx = auth_create_ctx();
        if (ctx == NULL) {
                printf("Failed to create auth context.\n");
                goto fail_create;
        }

        auth_destroy_ctx(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_load_free_crt(void)
{
        void * crt;

        TEST_START();

        if (crypt_load_crt_str(root_ca_crt_ml, &crt) < 0) {
                printf("Failed to load root crt from string.\n");
                goto fail_load;
        }

        crypt_free_crt(crt);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_load:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_load_free_privkey(void)
{
        void * key;

        TEST_START();

        if (crypt_load_privkey_str(server_pkp_ml, &key) < 0) {
                printf("Failed to load server key pair from string.\n");
                goto fail_load;
        }

        crypt_free_key(key);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_load:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_load_free_pubkey(void)
{
        void * key;

        TEST_START();

        if (crypt_load_pubkey_str(server_pk_ml, &key) < 0) {
                printf("Failed to load server public key from string.\n");
                goto fail_load;
        }

        crypt_free_key(key);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_load:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_verify_crt(void)
{
        struct auth_ctx * auth;
        void *            _server_crt;
        void *            _signed_server_crt;
        void *            _root_ca_crt;
        void *            _im_ca_crt;

        TEST_START();

        auth = auth_create_ctx();
        if (auth == NULL) {
                printf("Failed to create auth context.\n");
                goto fail_create_ctx;
        }

        if (crypt_load_crt_str(server_crt_ml, &_server_crt) < 0) {
                printf("Failed to load self-signed crt from string.\n");
                goto fail_load_server_crt;
        }

        if (crypt_load_crt_str(signed_server_crt_ml, &_signed_server_crt) < 0) {
                printf("Failed to load signed crt from string.\n");
                goto fail_load_signed_server_crt;
        }

        if (crypt_load_crt_str(root_ca_crt_ml, &_root_ca_crt) < 0) {
                printf("Failed to load root crt from string.\n");
                goto fail_load_root_ca_crt;
        }

        if (crypt_load_crt_str(im_ca_crt_ml, &_im_ca_crt) < 0) {
                printf("Failed to load intermediate crt from string.\n");
                goto fail_load_im_ca_crt;
        }

        if (auth_add_crt_to_store(auth, _root_ca_crt) < 0) {
                printf("Failed to add root ca crt to auth store.\n");
                goto fail_verify;
        }

        if (auth_add_crt_to_store(auth, _im_ca_crt) < 0) {
                printf("Failed to add intermediate ca crt to auth store.\n");
                goto fail_verify;
        }

        if (auth_verify_crt(auth, _signed_server_crt) < 0) {
                printf("Failed to verify signed crt with ca crt.\n");
                goto fail_verify;
        }

        if (auth_verify_crt(auth, _server_crt) == 0) {
                printf("Failed to detect untrusted crt.\n");
                goto fail_verify;
        }

        crypt_free_crt(_im_ca_crt);
        crypt_free_crt(_root_ca_crt);
        crypt_free_crt(_signed_server_crt);
        crypt_free_crt(_server_crt);

        auth_destroy_ctx(auth);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_verify:
        crypt_free_crt(_im_ca_crt);
 fail_load_im_ca_crt:
        crypt_free_crt(_root_ca_crt);
 fail_load_root_ca_crt:
        crypt_free_crt(_signed_server_crt);
 fail_load_signed_server_crt:
        crypt_free_crt(_server_crt);
 fail_load_server_crt:
        auth_destroy_ctx(auth);
 fail_create_ctx:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_auth_sign(void)
{
        uint8_t  buf[TEST_MSG_SIZE];
        void *   pkp;
        void *   pk;
        buffer_t msg;
        buffer_t sig;

        TEST_START();

        msg.data = buf;
        msg.len  = sizeof(buf);

        if (random_buffer(msg.data, msg.len) < 0) {
                printf("Failed to generate random message.\n");
                goto fail_init;
        }

        if (crypt_load_privkey_str(server_pkp_ml, &pkp) < 0) {
                printf("Failed to load server key pair from string.\n");
                goto fail_init;
        }

        if (crypt_load_pubkey_str(server_pk_ml, &pk) < 0) {
                printf("Failed to load public key from string.\n");
                goto fail_pubkey;
        }

        if (auth_sign(pkp, 0, msg, &sig) < 0) {
                printf("Failed to sign message.\n");
                goto fail_sign;
        }

        if (auth_verify_sig(pk, 0, msg, sig) < 0) {
                printf("Failed to verify signature.\n");
                goto fail_verify;
        }

        freebuf(sig);

        crypt_free_key(pk);
        crypt_free_key(pkp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_verify:
        freebuf(sig);
 fail_sign:
        crypt_free_key(pk);
 fail_pubkey:
        crypt_free_key(pkp);
 fail_init:
        return TEST_RC_FAIL;
}

static int test_auth_bad_signature(void)
{
        uint8_t  buf[TEST_MSG_SIZE];
        void *   pkp;
        void *   pk;
        buffer_t msg;
        buffer_t sig;
        buffer_t fake_sig;

        TEST_START();

        msg.data = buf;
        msg.len  = sizeof(buf);

        if (random_buffer(msg.data, msg.len) < 0) {
                printf("Failed to generate random message.\n");
                goto fail_init;
        }

        if (crypt_load_privkey_str(server_pkp_ml, &pkp) < 0) {
                printf("Failed to load server key pair from string.\n");
                goto fail_init;
        }

        if (crypt_load_pubkey_str(server_pk_ml, &pk) < 0) {
                printf("Failed to load public key from string.\n");
                goto fail_pubkey;
        }

        if (auth_sign(pkp, 0, msg, &sig) < 0) {
                printf("Failed to sign message.\n");
                goto fail_sign;
        }

        fake_sig.data = malloc(sig.len);
        if (fake_sig.data == NULL) {
                printf("Failed to allocate memory for fake signature.\n");
                goto fail_malloc;
        }

        fake_sig.len = sig.len;
        if (random_buffer(fake_sig.data, fake_sig.len) < 0) {
                printf("Failed to generate random fake signature.\n");
                goto fail_malloc;
        }

        if (auth_verify_sig(pk, 0, msg, fake_sig) == 0) {
                printf("Failed to detect bad ML-DSA-65 signature.\n");
                goto fail_verify;
        }

        freebuf(fake_sig);
        freebuf(sig);

        crypt_free_key(pk);
        crypt_free_key(pkp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_verify:
        freebuf(fake_sig);
 fail_malloc:
        freebuf(sig);
 fail_sign:
        crypt_free_key(pk);
 fail_pubkey:
        crypt_free_key(pkp);
 fail_init:
        return TEST_RC_FAIL;
}

int auth_test_ml_dsa(int     argc,
                     char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

#ifdef HAVE_OPENSSL_ML_DSA
        ret |= test_auth_create_destroy_ctx();
        ret |= test_load_free_crt();
        ret |= test_load_free_privkey();
        ret |= test_load_free_pubkey();
        ret |= test_verify_crt();
        ret |= test_auth_sign();
        ret |= test_auth_bad_signature();
#else
        (void) test_auth_create_destroy_ctx;
        (void) test_load_free_crt;
        (void) test_load_free_privkey;
        (void) test_load_free_pubkey;
        (void) test_verify_crt;
        (void) test_auth_sign;
        (void) test_auth_bad_signature;

        ret = TEST_RC_SKIP;
#endif
        return ret;
}
