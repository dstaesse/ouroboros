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
"MIICiTCCAi6gAwIBAgIUbTYRdvvGJpI99I3ag0Epj8PzOHwwCwYJYIZIAWUDBAMK\n"
"MIGQMQswCQYDVQQGEwJCRTEMMAoGA1UECAwDT1ZMMQ4wDAYDVQQHDAVHaGVudDEM\n"
"MAoGA1UECgwDbzdzMRUwEwYDVQQLDAx1bml0dGVzdC5vN3MxGDAWBgNVBAMMD2Nh\n"
"LnVuaXR0ZXN0Lm83czEkMCIGCSqGSIb3DQEJARYVZHVtbXlAb3Vyb2Jvcm9zLnJv\n"
"Y2tzMB4XDTI1MDYyMjEzNDcwOVoXDTI1MDcyMjEzNDcwOVowgZAxCzAJBgNVBAYT\n"
"AkJFMQwwCgYDVQQIDANPVkwxDjAMBgNVBAcMBUdoZW50MQwwCgYDVQQKDANvN3Mx\n"
"FTATBgNVBAsMDHVuaXR0ZXN0Lm83czEYMBYGA1UEAwwPY2EudW5pdHRlc3Qubzdz\n"
"MSQwIgYJKoZIhvcNAQkBFhVkdW1teUBvdXJvYm9yb3Mucm9ja3MwWTATBgcqhkjO\n"
"PQIBBggqhkjOPQMBBwNCAATsvzzYnXYQuZVMA7ckGEb8KISyHhXCBmc/kVcRyAje\n"
"hVq+F6nuWEEJVy/zNyMdxC5Qm+hVQDwhmu1JkiGAIF1Jo2MwYTAdBgNVHQ4EFgQU\n"
"sbj19vaWoWYfY5IP901oDYN94tcwHwYDVR0jBBgwFoAUsbj19vaWoWYfY5IP901o\n"
"DYN94tcwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCwYJYIZIAWUD\n"
"BAMKA0gAMEUCIQCniTsnEYel6HscrUO7JWs+VnvyqGV5CkRIwgGCN5neQwIgCco6\n"
"aVh8ZrDsPkjclhFBXF70Qoh9T56f2LdYFvjybdc=\n"
"-----END CERTIFICATE-----\n";

/* Certificate for intermediary im.unittest.o7s used for signing */
static const char * intermediate_ca_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIICgzCCAimgAwIBAgICEAAwCwYJYIZIAWUDBAMKMIGQMQswCQYDVQQGEwJCRTEM\n"
"MAoGA1UECAwDT1ZMMQ4wDAYDVQQHDAVHaGVudDEMMAoGA1UECgwDbzdzMRUwEwYD\n"
"VQQLDAx1bml0dGVzdC5vN3MxGDAWBgNVBAMMD2NhLnVuaXR0ZXN0Lm83czEkMCIG\n"
"CSqGSIb3DQEJARYVZHVtbXlAb3Vyb2Jvcm9zLnJvY2tzMB4XDTI1MDYyMjE0MTU0\n"
"M1oXDTM1MDYyMDE0MTU0M1owWjELMAkGA1UEBhMCQkUxDDAKBgNVBAgMA09WTDEM\n"
"MAoGA1UECgwDbzdzMRUwEwYDVQQLDAx1bml0dGVzdC5vN3MxGDAWBgNVBAMMD2lt\n"
"LnVuaXR0ZXN0Lm83czBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC1/rn6yG22c\n"
"38lxYGym4VcEZ6+lET5AfcaBsRKpvQj4NwfPG5BCoWwl/rwqKEGmcuwzubiGS1K9\n"
"hZaxZWp6WfejgaYwgaMwHQYDVR0OBBYEFBfSiMt8k7TKMp2lVsdlunBLGJQhMB8G\n"
"A1UdIwQYMBaAFLG49fb2lqFmH2OSD/dNaA2DfeLXMBIGA1UdEwEB/wQIMAYBAf8C\n"
"AQAwDgYDVR0PAQH/BAQDAgGGMBEGA1UdHwQKMAgwBqAEoAKGADAqBggrBgEFBQcB\n"
"AQQeMBwwDAYIKwYBBQUHMAKGADAMBggrBgEFBQcwAYYAMAsGCWCGSAFlAwQDCgNH\n"
"ADBEAiBjgMvCgnPz+xy4I1Msb6EwfwdIHr4eHqEfsGQjWf9M8gIgJyy6Bkg6Nkb4\n"
"uLdf/8CFP5yKKP1H26F8gx1VrGtr+PM=\n"
"-----END CERTIFICATE-----\n";

/* Server server-1.unittest.o7s private-public key pair */
static const char * server_ec_pkp = \
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIOLEoARQqt9oQkZhdqYrrDltVtcX7TIOYTQqE+GWCIwEoAoGCCqGSM49\n"
"AwEHoUQDQgAEzHlm1xTYnWncOymJ29ubJ3cHShG67JE+floT7L8ipqRNW4/FUwPN\n"
"zR/49iM0+A3Nq0ImjzkA6B7E3LvlrwokYQ==\n"
"-----END EC PRIVATE KEY-----\n";

/* Public key for the Private key */
static const char * server_ec_pk = \
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzHlm1xTYnWncOymJ29ubJ3cHShG6\n"
"7JE+floT7L8ipqRNW4/FUwPNzR/49iM0+A3Nq0ImjzkA6B7E3LvlrwokYQ==\n"
"-----END PUBLIC KEY-----\n";

/* Valid signed server certificate for server-1.unittest.o7s */
static const char * signed_server_crt = \
"-----BEGIN CERTIFICATE-----\n"
"MIIDgzCCAyegAwIBAgICEAAwCwYJYIZIAWUDBAMKMFoxCzAJBgNVBAYTAkJFMQww\n"
"CgYDVQQIDANPVkwxDDAKBgNVBAoMA283czEVMBMGA1UECwwMdW5pdHRlc3Qubzdz\n"
"MRgwFgYDVQQDDA9pbS51bml0dGVzdC5vN3MwHhcNMjUwNjIyMTQzODMxWhcNMjcw\n"
"NjIyMTQzODMxWjBwMQswCQYDVQQGEwJCRTEMMAoGA1UECAwDT1ZMMQ4wDAYDVQQH\n"
"DAVHaGVudDEMMAoGA1UECgwDbzdzMRUwEwYDVQQLDAx1bml0dGVzdC5vN3MxHjAc\n"
"BgNVBAMMFXNlcnZlci0xLnVuaXR0ZXN0Lm83czBZMBMGByqGSM49AgEGCCqGSM49\n"
"AwEHA0IABMx5ZtcU2J1p3Dspidvbmyd3B0oRuuyRPn5aE+y/IqakTVuPxVMDzc0f\n"
"+PYjNPgNzatCJo85AOgexNy75a8KJGGjggHEMIIBwDAJBgNVHRMEAjAAMBEGCWCG\n"
"SAGG+EIBAQQEAwIGQDA6BglghkgBhvhCAQ0ELRYrR3JpbGxlZCBDaGVlc2UgR2Vu\n"
"ZXJhdGVkIFNlcnZlciBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUIKmznLlTbfKaP78E\n"
"uSNauQ/4Mcwwgb4GA1UdIwSBtjCBs4AUF9KIy3yTtMoynaVWx2W6cEsYlCGhgZak\n"
"gZMwgZAxCzAJBgNVBAYTAkJFMQwwCgYDVQQIDANPVkwxDjAMBgNVBAcMBUdoZW50\n"
"MQwwCgYDVQQKDANvN3MxFTATBgNVBAsMDHVuaXR0ZXN0Lm83czEYMBYGA1UEAwwP\n"
"Y2EudW5pdHRlc3QubzdzMSQwIgYJKoZIhvcNAQkBFhVkdW1teUBvdXJvYm9yb3Mu\n"
"cm9ja3OCAhAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAR\n"
"BgNVHR8ECjAIMAagBKAChgAwKgYIKwYBBQUHAQEEHjAcMAwGCCsGAQUFBzAChgAw\n"
"DAYIKwYBBQUHMAGGADAgBgNVHREEGTAXghVzZXJ2ZXItMS51bml0dGVzdC5vN3Mw\n"
"CwYJYIZIAWUDBAMKA0kAMEYCIQDVoRxvr9j4mbX/CpxsQr5HhjxLnjYzI2SVM+0l\n"
"z2dxVgIhALwq2q6d8WDHPq59trrlNlnYO+kDqDLS3smnS6LOQYiq\n"
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

        if (crypt_check_crt_name(crt, "server-1.unittest.o7s") < 0) {
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
