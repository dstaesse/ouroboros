/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Test of the authentication functions
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

#include <test/certs.h>

#define TEST_MSG_SIZE 1500

/*
* Certificates created following the guide
*   Building an openssl certificate authority
* on
*   https://community.f5.com/kb/technicalarticles/
*/

/* Root certificate for CA ca.unittest.o7s */
static const char * root_ca_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIICXTCCAgOgAwIBAgIURlENlCOy1OsA/AXFscPUQ2li8OYwCgYIKoZIzj0EAwIw\n"
"fDELMAkGA1UEBhMCQkUxDDAKBgNVBAgMA09WTDEOMAwGA1UEBwwFR2hlbnQxDDAK\n"
"BgNVBAoMA283czEVMBMGA1UECwwMdW5pdHRlc3QubzdzMRgwFgYDVQQDDA9jYS51\n"
"bml0dGVzdC5vN3MxEDAOBgkqhkiG9w0BCQEWASAwHhcNMjUwODAzMTg1MzE1WhcN\n"
"NDUwNzI5MTg1MzE1WjB8MQswCQYDVQQGEwJCRTEMMAoGA1UECAwDT1ZMMQ4wDAYD\n"
"VQQHDAVHaGVudDEMMAoGA1UECgwDbzdzMRUwEwYDVQQLDAx1bml0dGVzdC5vN3Mx\n"
"GDAWBgNVBAMMD2NhLnVuaXR0ZXN0Lm83czEQMA4GCSqGSIb3DQEJARYBIDBZMBMG\n"
"ByqGSM49AgEGCCqGSM49AwEHA0IABEPMseCScbd/d5TlHmyYVszn/YGVeNdUCnFR\n"
"naOr95WlTNo3MyKKBuoiEFwHhjPASgXr/VDVjJLSyM3JUPebAcGjYzBhMB0GA1Ud\n"
"DgQWBBQkxjMILHH6lZ+rnCMnD/63GO3y1zAfBgNVHSMEGDAWgBQkxjMILHH6lZ+r\n"
"nCMnD/63GO3y1zAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAKBggq\n"
"hkjOPQQDAgNIADBFAiEA1jVJWW4idkCgAYv0m2LT9C33Dq42aLyRkJ+9YdzDqLwC\n"
"IHT6MS4I0k52YP/hxoqWVBbpOW79PKYMRLyXTk1r7+Fa\n"
"-----END CERTIFICATE-----\n";


/* Certificate for intermediary im.unittest.o7s used for signing */
static const char * intermediate_ca_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIICbTCCAhOgAwIBAgICEAMwCgYIKoZIzj0EAwIwfDELMAkGA1UEBhMCQkUxDDAK\n"
"BgNVBAgMA09WTDEOMAwGA1UEBwwFR2hlbnQxDDAKBgNVBAoMA283czEVMBMGA1UE\n"
"CwwMdW5pdHRlc3QubzdzMRgwFgYDVQQDDA9jYS51bml0dGVzdC5vN3MxEDAOBgkq\n"
"hkiG9w0BCQEWASAwHhcNMjUwODAzMTkwMjU3WhcNNDUwNzI5MTkwMjU3WjBaMQsw\n"
"CQYDVQQGEwJCRTEMMAoGA1UECAwDT1ZMMQwwCgYDVQQKDANvN3MxFTATBgNVBAsM\n"
"DHVuaXR0ZXN0Lm83czEYMBYGA1UEAwwPaW0udW5pdHRlc3QubzdzMFkwEwYHKoZI\n"
"zj0CAQYIKoZIzj0DAQcDQgAEdlra08XItIPtVl5veaq4UF6LIcBXj2mZFqKNEXFh\n"
"l9uAz6UAbIc+FUPNfom6dwKbg/AjQ82a100eh6K/jCY7eKOBpjCBozAdBgNVHQ4E\n"
"FgQUy8Go8BIO6i0lJ+mgBr9lvh2L0eswHwYDVR0jBBgwFoAUJMYzCCxx+pWfq5wj\n"
"Jw/+txjt8tcwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEQYD\n"
"VR0fBAowCDAGoASgAoYAMCoGCCsGAQUFBwEBBB4wHDAMBggrBgEFBQcwAoYAMAwG\n"
"CCsGAQUFBzABhgAwCgYIKoZIzj0EAwIDSAAwRQIhAN3ZYhqu6mVLGidmONsbANk5\n"
"rzT6aHJcmvj19OxMusaXAiBKy0gBFCri/GLizi4wZo09wf31yZMqfr8IrApvPaLw\n"
"qA==\n"
"-----END CERTIFICATE-----\n";

/* Server test-1.unittest.o7s private-public key pair */
static const char * server_ec_pkp = \
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIA4/bcmquVvGrY4+TtfnFSy1SpXs896r5xJjGuD6NmGRoAoGCCqGSM49\n"
"AwEHoUQDQgAE4BSOhv36q4bCMLSkJaCvzwZ3pPy2M0YzRKFKeV48tG5eD+MBaTrT\n"
"eoHUcRfpz0EO/inq3FVDzEoAQ2NWpnz0kA==\n"
"-----END EC PRIVATE KEY-----\n";

/* Public key for the Private key */
static const char * server_ec_pk = \
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4BSOhv36q4bCMLSkJaCvzwZ3pPy2\n"
"M0YzRKFKeV48tG5eD+MBaTrTeoHUcRfpz0EO/inq3FVDzEoAQ2NWpnz0kA==\n"
"-----END PUBLIC KEY-----\n";

/* Valid signed server certificate for test-1.unittest.o7s */
static const char * signed_server_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIIDiTCCAy+gAwIBAgICEAUwCgYIKoZIzj0EAwIwWjELMAkGA1UEBhMCQkUxDDAK\n"
"BgNVBAgMA09WTDEMMAoGA1UECgwDbzdzMRUwEwYDVQQLDAx1bml0dGVzdC5vN3Mx\n"
"GDAWBgNVBAMMD2ltLnVuaXR0ZXN0Lm83czAeFw0yNTA4MDgxODQ4NTNaFw00NTA4\n"
"MDMxODQ4NTNaMG4xCzAJBgNVBAYTAkJFMQwwCgYDVQQIDANPVkwxDjAMBgNVBAcM\n"
"BUdoZW50MQwwCgYDVQQKDANvN3MxFTATBgNVBAsMDHVuaXR0ZXN0Lm83czEcMBoG\n"
"A1UEAwwTdGVzdC0xLnVuaXR0ZXN0Lm83czBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
"A0IABOAUjob9+quGwjC0pCWgr88Gd6T8tjNGM0ShSnlePLRuXg/jAWk603qB1HEX\n"
"6c9BDv4p6txVQ8xKAENjVqZ89JCjggHPMIIByzAJBgNVHRMEAjAAMBEGCWCGSAGG\n"
"+EIBAQQEAwIGQDA4BglghkgBhvhCAQ0EKxYpbzdzIHVuaXR0ZXN0IEdlbmVyYXRl\n"
"ZCBTZXJ2ZXIgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFI+htsK0xxy6e1CqCyxn7mqi\n"
"wRrpMIGoBgNVHSMEgaAwgZ2AFMvBqPASDuotJSfpoAa/Zb4di9HroYGApH4wfDEL\n"
"MAkGA1UEBhMCQkUxDDAKBgNVBAgMA09WTDEOMAwGA1UEBwwFR2hlbnQxDDAKBgNV\n"
"BAoMA283czEVMBMGA1UECwwMdW5pdHRlc3QubzdzMRgwFgYDVQQDDA9jYS51bml0\n"
"dGVzdC5vN3MxEDAOBgkqhkiG9w0BCQEWASCCAhADMA4GA1UdDwEB/wQEAwIFoDAT\n"
"BgNVHSUEDDAKBggrBgEFBQcDATAoBgNVHR8EITAfMB2gG6AZhhdodHRwczovL291\n"
"cm9ib3Jvcy5yb2NrczBYBggrBgEFBQcBAQRMMEowIwYIKwYBBQUHMAKGF2h0dHBz\n"
"Oi8vb3Vyb2Jvcm9zLnJvY2tzMCMGCCsGAQUFBzABhhdodHRwczovL291cm9ib3Jv\n"
"cy5yb2NrczAKBggqhkjOPQQDAgNIADBFAiBZuw/Yb2pq925H7pEiOXr4fMo0wknz\n"
"ktkxoHAFbjQEPQIhAMInHI7lvRmS0IMw1wBF/WlUZWKvhyU/TeMIZfk/JGCS\n"
"-----END CERTIFICATE-----\n";

/* Self-signed by server test-1.unittest.o7s using its key */
static const char * server_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIIBfjCCASWgAwIBAgIUB5VYxp7i+sgYjvLiwfpf0W5NfqQwCgYIKoZIzj0EAwIw\n"
"HjEcMBoGA1UEAwwTdGVzdC0xLnVuaXR0ZXN0Lm83czAeFw0yNTA4MDMxOTI4MzVa\n"
"Fw00NTA3MjkxOTI4MzVaMB4xHDAaBgNVBAMME3Rlc3QtMS51bml0dGVzdC5vN3Mw\n"
"WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATgFI6G/fqrhsIwtKQloK/PBnek/LYz\n"
"RjNEoUp5Xjy0bl4P4wFpOtN6gdRxF+nPQQ7+KercVUPMSgBDY1amfPSQo0EwPzAe\n"
"BgNVHREEFzAVghN0ZXN0LTEudW5pdHRlc3QubzdzMB0GA1UdDgQWBBSPobbCtMcc\n"
"untQqgssZ+5qosEa6TAKBggqhkjOPQQDAgNHADBEAiAoFC/rqgrRXmMUx4y5cPbv\n"
"jOKpoL3FpehRgGkPatmL/QIgMRHc2TSGo6q1SG22Xt1dHAIBsaN2AlSfhjKULMH5\n"
"gRo=\n"
"-----END CERTIFICATE-----\n";

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

        if (crypt_load_crt_str(root_ca_crt_ec, &crt) < 0) {
                printf("Failed to load certificate string.\n");
                goto fail_load;
        }

        crypt_free_crt(crt);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_load:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_crypt_get_pubkey_crt(void)
{
        void * pk;
        void * crt;

        TEST_START();

        if (crypt_load_crt_str(signed_server_crt_ec, &crt) < 0) {
                printf("Failed to load server certificate from string.\n");
                goto fail_load;
        }

        if (crypt_get_pubkey_crt(crt, &pk) < 0) {
                printf("Failed to get public key from certificate.\n");
                goto fail_get_pubkey;
        }

        crypt_free_key(pk);
        crypt_free_crt(crt);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_get_pubkey:
        crypt_free_crt(crt);
 fail_load:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_check_crt_name(void)
{
        void * crt;

        TEST_START();

        if (crypt_load_crt_str(signed_server_crt_ec, &crt) < 0) {
                printf("Failed to load certificate from string.\n");
                goto fail_load;
        }

        if (crypt_check_crt_name(crt, "test-1.unittest.o7s") < 0) {
                printf("Failed to verify correct name.\n");
                goto fail_check;
        }

        if (crypt_check_crt_name(crt, "bogus.name") == 0) {
                printf("Failed to detect incorrect name.\n");
                goto fail_check;
        }

        crypt_free_crt(crt);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_check:
        crypt_free_crt(crt);
 fail_load:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_load_free_privkey(void)
{
        void * key;

        TEST_START();

        if (crypt_load_privkey_str(server_pkp_ec, &key) < 0) {
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

        if (crypt_load_pubkey_str(server_pk_ec, &key) < 0) {
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

static int test_crypt_check_pubkey_crt(void)
{
        void * pk;
        void * crt_pk;
        void * crt;

        TEST_START();

        if (crypt_load_crt_str(signed_server_crt_ec, &crt) < 0) {
                printf("Failed to load public certificate from string.\n");
                goto fail_crt;
        }

        if (crypt_load_pubkey_str(server_pk_ec, &pk) < 0) {
                printf("Failed to load public key from string.\n");
                goto fail_pubkey;
        }

        if (crypt_get_pubkey_crt(crt, &crt_pk) < 0) {
                printf("Failed to get public key from certificate.\n");
                goto fail_get_pubkey;
        }

        if (crypt_cmp_key(pk, crt_pk) != 0) {
                printf("Public keys do not match .\n");
                goto fail_check;
        }


        crypt_free_key(crt_pk);
        crypt_free_key(pk);
        crypt_free_crt(crt);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_check:
        crypt_free_key(crt_pk);
 fail_get_pubkey:
        crypt_free_key(pk);
 fail_pubkey:
        crypt_free_crt(crt);
 fail_crt:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_store_add(void)
{
        struct auth_ctx * ctx;
        void *            _root_ca_crt;

        TEST_START();

        ctx = auth_create_ctx();
        if (ctx == NULL) {
                printf("Failed to create auth context.\n");
                goto fail_create;
        }

        if (crypt_load_crt_str(root_ca_crt_ec, &_root_ca_crt) < 0) {
                printf("Failed to load root crt from string.\n");
                goto fail_load;
        }

        if (auth_add_crt_to_store(ctx, _root_ca_crt) < 0) {
                printf("Failed to add root crt to auth store.\n");
                goto fail_add;
        }

        crypt_free_crt(_root_ca_crt);
        auth_destroy_ctx(ctx);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_add:
        crypt_free_crt(_root_ca_crt);
 fail_load:
        crypt_free_crt(_root_ca_crt);
 fail_create:
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

        if (crypt_load_crt_str(server_crt_ec, &_server_crt) < 0) {
                printf("Failed to load self-signed crt from string.\n");
                goto fail_load_server_crt;
        }

        if (crypt_load_crt_str(signed_server_crt_ec, &_signed_server_crt) < 0) {
                printf("Failed to load signed crt from string.\n");
                goto fail_load_signed_server_crt;
        }

        if (crypt_load_crt_str(root_ca_crt_ec, &_root_ca_crt) < 0) {
                printf("Failed to load root crt from string.\n");
                goto fail_load_root_ca_crt;
        }

        if (crypt_load_crt_str(im_ca_crt_ec, &_im_ca_crt) < 0) {
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

int test_auth_sign(void)
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

        if (crypt_load_privkey_str(server_pkp_ec, &pkp) < 0) {
                printf("Failed to load server key pair from string.\n");
                goto fail_init;
        }

        if (crypt_load_pubkey_str(server_pk_ec, &pk) < 0) {
                printf("Failed to load public key.\n");
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

int test_auth_bad_signature(void)
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

        if (crypt_load_privkey_str(server_pkp_ec, &pkp) < 0) {
                printf("Failed to load server key pair from string.\n");
                goto fail_init;
        }

        if (crypt_load_pubkey_str(server_pk_ec, &pk) < 0) {
                printf("Failed to load public key.\n");
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
                printf("Failed to detect bad signature.\n");
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

#define SSC_BUF_SIZE 4096 /* OpenSSL version my return different lengths */
int test_crt_str(void)
{
        char str[SSC_BUF_SIZE];
        void * crt;

        TEST_START();

        if (crypt_load_crt_str(signed_server_crt_ec, &crt) < 0) {
                printf("Failed to load certificate from string.\n");
                goto fail_load;
        }

        if (crypt_crt_str(crt, str) < 0) {
                printf("Failed to convert certificate to string.\n");
                goto fail_to_str;
        }

        printf("Certificate string:\n%s\n", str);

        crypt_free_crt(crt);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_to_str:
        crypt_free_crt(crt);
 fail_load:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int auth_test(int     argc,
              char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_auth_create_destroy_ctx();
#ifdef HAVE_OPENSSL
        ret |= test_load_free_crt();
        ret |= test_check_crt_name();
        ret |= test_crypt_get_pubkey_crt();
        ret |= test_load_free_privkey();
        ret |= test_load_free_pubkey();
        ret |= test_crypt_check_pubkey_crt();
        ret |= test_store_add();
        ret |= test_verify_crt();
        ret |= test_auth_sign();
        ret |= test_auth_bad_signature();
        ret |= test_crt_str();
#else
        (void) test_load_free_crt;
        (void) test_check_crt_name;
        (void) test_crypt_get_pubkey_crt;
        (void) test_load_free_privkey;
        (void) test_load_free_pubkey;
        (void) test_crypt_check_pubkey_crt;
        (void) test_store_add;
        (void) test_verify_crt;
        (void) test_auth_sign;
        (void) test_auth_bad_signature;
        (void) test_crt_str;

        ret = TEST_RC_SKIP;
#endif
        return ret;
}
