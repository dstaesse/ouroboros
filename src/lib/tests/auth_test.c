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

#include <ouroboros/test.h>
#include <ouroboros/crypt.h>
#include <ouroboros/random.h>
#include <ouroboros/utils.h>

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
"MIICiTCCAi+gAwIBAgIUe4iFIymeUTgutBrdvcxFihOVHnowCgYIKoZIzj0EAwIw\n"
"gZExCzAJBgNVBAYTAkJFMQwwCgYDVQQIDANPVkwxDjAMBgNVBAcMBUdoZW50MQww\n"
"CgYDVQQKDANvN3MxFTATBgNVBAsMDHVuaXR0ZXN0Lm83czEZMBcGA1UEAwwQY2Ey\n"
"LnVuaXR0ZXN0Lm83czEkMCIGCSqGSIb3DQEJARYVZHVtbXlAb3Vyb2Jvcm9zLnJv\n"
"Y2tzMB4XDTI1MDcwNDEyMDUwOVoXDTI1MDgwMzEyMDUwOVowgZExCzAJBgNVBAYT\n"
"AkJFMQwwCgYDVQQIDANPVkwxDjAMBgNVBAcMBUdoZW50MQwwCgYDVQQKDANvN3Mx\n"
"FTATBgNVBAsMDHVuaXR0ZXN0Lm83czEZMBcGA1UEAwwQY2EyLnVuaXR0ZXN0Lm83\n"
"czEkMCIGCSqGSIb3DQEJARYVZHVtbXlAb3Vyb2Jvcm9zLnJvY2tzMFkwEwYHKoZI\n"
"zj0CAQYIKoZIzj0DAQcDQgAE7L882J12ELmVTAO3JBhG/CiEsh4VwgZnP5FXEcgI\n"
"3oVavhep7lhBCVcv8zcjHcQuUJvoVUA8IZrtSZIhgCBdSaNjMGEwHQYDVR0OBBYE\n"
"FLG49fb2lqFmH2OSD/dNaA2DfeLXMB8GA1UdIwQYMBaAFLG49fb2lqFmH2OSD/dN\n"
"aA2DfeLXMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49\n"
"BAMCA0gAMEUCIQCHLdjzuop33phYcxTMs12pQcRk9GDbiKd1VZr6/SxutAIgBU1/\n"
"JSTSWB29kFFiM9ZdMV7M/tiZH9nSz1M8XhsTIGk=\n"
"-----END CERTIFICATE-----\n";

/* Certificate for intermediary im.unittest.o7s used for signing */
static const char * intermediate_ca_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIIChTCCAiqgAwIBAgICEAIwCgYIKoZIzj0EAwIwgZExCzAJBgNVBAYTAkJFMQww\n"
"CgYDVQQIDANPVkwxDjAMBgNVBAcMBUdoZW50MQwwCgYDVQQKDANvN3MxFTATBgNV\n"
"BAsMDHVuaXR0ZXN0Lm83czEZMBcGA1UEAwwQY2EyLnVuaXR0ZXN0Lm83czEkMCIG\n"
"CSqGSIb3DQEJARYVZHVtbXlAb3Vyb2Jvcm9zLnJvY2tzMB4XDTI1MDcwNDEzMTc1\n"
"N1oXDTM1MDcwMjEzMTc1N1owWzELMAkGA1UEBhMCQkUxDDAKBgNVBAgMA09WTDEM\n"
"MAoGA1UECgwDbzdzMRUwEwYDVQQLDAx1bml0dGVzdC5vN3MxGTAXBgNVBAMMEGlt\n"
"Mi51bml0dGVzdC5vN3MwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQXhtgyz2ot\n"
"xWMC5PW3lchYyzYLIU0VsI4aAALjRcRoq3ZunC1cvBWv34fkSrwBCCsQvLIBP+8j\n"
"qgi5j2kve8QIo4GmMIGjMB0GA1UdDgQWBBQV95lHHxBZYpCvsDDzOMO7ayG9xDAf\n"
"BgNVHSMEGDAWgBSxuPX29pahZh9jkg/3TWgNg33i1zASBgNVHRMBAf8ECDAGAQH/\n"
"AgEAMA4GA1UdDwEB/wQEAwIBhjARBgNVHR8ECjAIMAagBKAChgAwKgYIKwYBBQUH\n"
"AQEEHjAcMAwGCCsGAQUFBzAChgAwDAYIKwYBBQUHMAGGADAKBggqhkjOPQQDAgNJ\n"
"ADBGAiEAlw7Q08qDZ/OftfTPdoTvNezDW/1ChQQcwsmQxcbBTfsCIQDWCaB+PHVo\n"
"NnkLn+73oMj8w4pXGLNKAkX0z7yPJ4QhwA==\n"
"-----END CERTIFICATE-----\n";

/* Server server-1.unittest.o7s private-public key pair */
static const char * server_ec_pkp = \
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIC13y+5jdKe80HBJD7WITpQamcn3rrkTX1r0v+JwSk4NoAoGCCqGSM49\n"
"AwEHoUQDQgAEcC0yLAfUtufH8cdLybrdWPc6U+xRuhDhqqrEcBO5+eob2xyqEaNk\n"
"nIV/86724zPptGRahWz0rzW2PvNppJdNBg==\n"
"-----END EC PRIVATE KEY-----\n";

/* Public key for the Private key */
static const char * server_ec_pk = \
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcC0yLAfUtufH8cdLybrdWPc6U+xR\n"
"uhDhqqrEcBO5+eob2xyqEaNknIV/86724zPptGRahWz0rzW2PvNppJdNBg==\n"
"-----END PUBLIC KEY-----\n";

/* Valid signed server certificate for server-1.unittest.o7s, SHA2 */
static const char * signed_server_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIIDgjCCAyigAwIBAgICEAIwCgYIKoZIzj0EAwIwWzELMAkGA1UEBhMCQkUxDDAK\n"
"BgNVBAgMA09WTDEMMAoGA1UECgwDbzdzMRUwEwYDVQQLDAx1bml0dGVzdC5vN3Mx\n"
"GTAXBgNVBAMMEGltMi51bml0dGVzdC5vN3MwHhcNMjUwNzA0MTMxODI5WhcNMzUw\n"
"NzAyMTMxODI5WjBwMQswCQYDVQQGEwJCRTEMMAoGA1UECAwDT1ZMMQ4wDAYDVQQH\n"
"DAVHaGVudDEMMAoGA1UECgwDbzdzMRUwEwYDVQQLDAx1bml0dGVzdC5vN3MxHjAc\n"
"BgNVBAMMFXNlcnZlci0yLnVuaXR0ZXN0Lm83czBZMBMGByqGSM49AgEGCCqGSM49\n"
"AwEHA0IABHAtMiwH1Lbnx/HHS8m63Vj3OlPsUboQ4aqqxHATufnqG9scqhGjZJyF\n"
"f/Ou9uMz6bRkWoVs9K81tj7zaaSXTQajggHFMIIBwTAJBgNVHRMEAjAAMBEGCWCG\n"
"SAGG+EIBAQQEAwIGQDA6BglghkgBhvhCAQ0ELRYrR3JpbGxlZCBDaGVlc2UgR2Vu\n"
"ZXJhdGVkIFNlcnZlciBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUTt3xHTwE9amoglxh\n"
"cEMqWv+PpDMwgb8GA1UdIwSBtzCBtIAUFfeZRx8QWWKQr7Aw8zjDu2shvcShgZek\n"
"gZQwgZExCzAJBgNVBAYTAkJFMQwwCgYDVQQIDANPVkwxDjAMBgNVBAcMBUdoZW50\n"
"MQwwCgYDVQQKDANvN3MxFTATBgNVBAsMDHVuaXR0ZXN0Lm83czEZMBcGA1UEAwwQ\n"
"Y2EyLnVuaXR0ZXN0Lm83czEkMCIGCSqGSIb3DQEJARYVZHVtbXlAb3Vyb2Jvcm9z\n"
"LnJvY2tzggIQAjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEw\n"
"EQYDVR0fBAowCDAGoASgAoYAMCoGCCsGAQUFBwEBBB4wHDAMBggrBgEFBQcwAoYA\n"
"MAwGCCsGAQUFBzABhgAwIAYDVR0RBBkwF4IVc2VydmVyLTEudW5pdHRlc3Qubzdz\n"
"MAoGCCqGSM49BAMCA0gAMEUCIQDHuDb62w/Uah4nKwUFoJVkr4rgdNGh2Rn3SWaK\n"
"0FV/gAIgOLKorTwSgrTFdyOUkuPOhRs8BEMpah+dp8UTO8AnLvY=\n"
"-----END CERTIFICATE-----\n";

/* Self-signed by server server-1.unittest.o7s using its key */
static const char * server_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIICNzCCAdygAwIBAgIUaKYySFvp8nmd7LcJjdCyyHrgv0owCwYJYIZIAWUDBAMK\n"
"MHAxCzAJBgNVBAYTAkJFMQwwCgYDVQQIDANPVkwxDjAMBgNVBAcMBUdoZW50MQww\n"
"CgYDVQQKDANvN3MxFTATBgNVBAsMDHVuaXR0ZXN0Lm83czEeMBwGA1UEAwwVc2Vy\n"
"dmVyLTEudW5pdHRlc3QubzdzMB4XDTI1MDYyMjE0NTU1MFoXDTM1MDYyMDE0NTU1\n"
"MFowcDELMAkGA1UEBhMCQkUxDDAKBgNVBAgMA09WTDEOMAwGA1UEBwwFR2hlbnQx\n"
"DDAKBgNVBAoMA283czEVMBMGA1UECwwMdW5pdHRlc3QubzdzMR4wHAYDVQQDDBVz\n"
"ZXJ2ZXItMS51bml0dGVzdC5vN3MwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATM\n"
"eWbXFNidadw7KYnb25sndwdKEbrskT5+WhPsvyKmpE1bj8VTA83NH/j2IzT4Dc2r\n"
"QiaPOQDoHsTcu+WvCiRho1MwUTAdBgNVHQ4EFgQUIKmznLlTbfKaP78EuSNauQ/4\n"
"McwwHwYDVR0jBBgwFoAUIKmznLlTbfKaP78EuSNauQ/4McwwDwYDVR0TAQH/BAUw\n"
"AwEB/zALBglghkgBZQMEAwoDSAAwRQIhAMrhCV+4QY4Pzcn11qY8AW24xSYE77jN\n"
"oWkJQKoLEhSdAiBCFzCBItjChcDavsuy++HDo3e6VdpmAh0PlTlQTR6Wog==\n"
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

        if (crypt_load_crt_str(root_ca_crt, &crt) < 0) {
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

        if (crypt_load_crt_str(signed_server_crt, &crt) < 0) {
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

        if (crypt_load_crt_str(signed_server_crt, &crt) < 0) {
                printf("Failed to load certificate from string.\n");
                goto fail_load;
        }

        if (crypt_check_crt_name(crt, "server-2.unittest.o7s") < 0) {
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

        if (crypt_load_privkey_str(server_ec_pkp, &key) < 0) {
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

        if (crypt_load_pubkey_str(server_ec_pk, &key) < 0) {
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

        if (crypt_load_crt_str(signed_server_crt, &crt) < 0) {
                printf("Failed to load public certificate from string.\n");
                goto fail_crt;
        }

        if (crypt_load_pubkey_str(server_ec_pk, &pk) < 0) {
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

static int test_verify_crt(void)
{
        struct auth_ctx * auth;
        void *            _server_crt;
        void *            _signed_server_crt;
        void *            _root_ca_crt;
        void *            _intermediate_ca_crt;

        TEST_START();

        auth = auth_create_ctx();
        if (auth == NULL) {
                printf("Failed to create auth context.\n");
                goto fail_create_ctx;
        }

        if (crypt_load_crt_str(server_crt, &_server_crt) < 0) {
                printf("Failed to load self-signed crt from string.\n");
                goto fail_load_server_crt;
        }

        if (crypt_load_crt_str(signed_server_crt, &_signed_server_crt) < 0) {
                printf("Failed to load signed crt from string.\n");
                goto fail_load_signed_server_crt;
        }

        if (crypt_load_crt_str(root_ca_crt, &_root_ca_crt) < 0) {
                printf("Failed to load root crt from string.\n");
                goto fail_load_root_ca_crt;
        }

        if (crypt_load_crt_str(intermediate_ca_crt, &_intermediate_ca_crt) < 0) {
                printf("Failed to load intermediate crt from string.\n");
                goto fail_load_intermediate_ca_crt;
        }

        if (auth_add_crt_to_store(auth, _root_ca_crt) < 0) {
                printf("Failed to add root ca crt to auth store.\n");
                goto fail_verify;
        }

        if (auth_add_crt_to_store(auth, _intermediate_ca_crt) < 0) {
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

        crypt_free_crt(_intermediate_ca_crt);
        crypt_free_crt(_root_ca_crt);
        crypt_free_crt(_signed_server_crt);
        crypt_free_crt(_server_crt);

        auth_destroy_ctx(auth);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_verify:
        crypt_free_crt(_intermediate_ca_crt);
 fail_load_intermediate_ca_crt:
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

        if (crypt_load_privkey_str(server_ec_pkp, &pkp) < 0) {
                printf("Failed to load server key pair from string.\n");
                goto fail_init;
        }

        if (crypt_load_pubkey_str(server_ec_pk, &pk) < 0) {
                printf("Failed to load public key.\n");
                goto fail_pubkey;
        }

        if (auth_sign(pkp, msg, &sig) < 0) {
                printf("Failed to sign message.\n");
                goto fail_sign;
        }

        if (auth_verify_sig(pk, msg, sig) < 0) {
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

        if (crypt_load_privkey_str(server_ec_pkp, &pkp) < 0) {
                printf("Failed to load server key pair from string.\n");
                goto fail_init;
        }

        if (crypt_load_pubkey_str(server_ec_pk, &pk) < 0) {
                printf("Failed to load public key.\n");
                goto fail_pubkey;
        }

        if (auth_sign(pkp, msg, &sig) < 0) {
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

        if (auth_verify_sig(pk, msg, fake_sig) == 0) {
                printf("Failed to detect bad signature.\n");
                goto fail_verify;
        }

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
        ret |= test_verify_crt();
        ret |= test_auth_sign();
        ret |= test_auth_bad_signature();
#else
        (void) test_load_free_crt;
        (void) test_check_crt_name;
        (void) test_crypt_get_pubkey_crt;
        (void) test_load_free_privkey;
        (void) test_load_free_pubkey;
        (void) test_crypt_check_pubkey_crt;
        (void) test_verify_crt;
        (void) test_auth_sign;
        (void) test_auth_bad_signature;

        ret = TEST_RC_SKIP;
#endif
        return ret;
}
