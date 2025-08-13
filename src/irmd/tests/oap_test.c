/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Unit tests of Ouroboros flow allocation protocol
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

#include "oap.c"

#include <ouroboros/random.h>
#include <ouroboros/test.h>

static const char * pkp_str = \
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIC13y+5jdKe80HBJD7WITpQamcn3rrkTX1r0v+JwSk4NoAoGCCqGSM49\n"
"AwEHoUQDQgAEcC0yLAfUtufH8cdLybrdWPc6U+xRuhDhqqrEcBO5+eob2xyqEaNk\n"
"nIV/86724zPptGRahWz0rzW2PvNppJdNBg==\n"
"-----END EC PRIVATE KEY-----\n";

/* Valid signed server certificate for server-2.unittest.o7s */
static const char * crt_str = \
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

static int test_oap_hdr_init_fini(void)
{
        struct oap_hdr  oap_hdr;
        struct timespec now;
        uint64_t        stamp;
        buffer_t        ephkey = BUF_INIT;
        buffer_t        data   = BUF_INIT;
        uint8_t         buf[OAP_ID_SIZE];
        buffer_t        id;
        void *          pkp    = NULL;
        void *          pubcrt = NULL;

        TEST_START();

        random_buffer(buf, OAP_ID_SIZE);
        id.data = buf;
        id.len  = OAP_ID_SIZE;

        clock_gettime(CLOCK_REALTIME, &now);
        stamp = TS_TO_UINT64(now);

        if (oap_hdr_init(id, pkp, pubcrt, ephkey, data, &oap_hdr) < 0) {
                printf("Failed to init OAP request header.\n");
                goto fail_req_hdr;
        }

        if (oap_hdr.hdr.len != OAP_HDR_MIN_SIZE) {
                printf("OAP request header wrong: %zu < %zu.\n",
                       oap_hdr.hdr.len, OAP_HDR_MIN_SIZE);
                goto fail_req_hdr_chk;
        }

        if (oap_hdr.id.len != OAP_ID_SIZE) {
                printf("OAP request header ID wrong size: %zu != %zu.\n",
                       oap_hdr.id.len, (size_t) OAP_ID_SIZE);
                goto fail_req_hdr_chk;
        }

        if (memcmp(oap_hdr.id.data, id.data, OAP_ID_SIZE) != 0) {
                printf("OAP request header ID mismatch.\n");
                goto fail_req_hdr_chk;
        }

        if (oap_hdr.timestamp < stamp) {
                printf("OAP request header timestamp is too old.\n");
                goto fail_req_hdr_chk;
        }

        if (oap_hdr.timestamp > stamp + 1 * BILLION) {
                printf("OAP request header timestamp is too new.\n");
                goto fail_req_hdr_chk;
        }

        oap_hdr_fini(&oap_hdr);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_req_hdr_chk:
        oap_hdr_fini(&oap_hdr);
 fail_req_hdr:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_oap_hdr_init_fini_data(void)

{
        struct oap_hdr oap_hdr;
        buffer_t       data;
        buffer_t       ephkey = BUF_INIT;
        uint8_t         buf[OAP_ID_SIZE];
        buffer_t        id;
        void *         pkp    = NULL;
        void *         pubcrt = NULL;

        TEST_START();

        random_buffer(buf, OAP_ID_SIZE);
        id.data = buf;
        id.len  = OAP_ID_SIZE;

        data.len = 100;
        data.data = malloc(data.len);
        if (data.data == NULL) {
                printf("Failed to allocate data buffer.\n");
                goto fail_data;
        }

        random_buffer(data.data, data.len);

        if (oap_hdr_init(id, pkp, pubcrt, ephkey, data, &oap_hdr) < 0) {
                printf("Failed to create OAP request header.\n");
                goto fail_req_hdr;
        }

        if (oap_hdr.hdr.len != OAP_HDR_MIN_SIZE + data.len) {
                printf("OAP request header wrong: %zu < %zu.\n",
                       oap_hdr.hdr.len, OAP_HDR_MIN_SIZE + data.len);
                goto fail_req_hdr_sz;
        }

        freebuf(data);
        oap_hdr_fini(&oap_hdr);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_req_hdr_sz:
        oap_hdr_fini(&oap_hdr);
 fail_req_hdr:
        freebuf(data);
 fail_data:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_oap_hdr_init_fini_signed(void)
{
        struct oap_hdr oap_hdr;
        buffer_t       ephkey = BUF_INIT;
        buffer_t       data   = BUF_INIT;
        buffer_t       sign;
        buffer_t       id;
        uint8_t        buf[OAP_ID_SIZE];
        void *         pkp;
        void *         pk;
        void *         pubcrt;
        void *         pubcrt2;

        TEST_START();

        random_buffer(buf, OAP_ID_SIZE);
        id.data = buf;
        id.len  = OAP_ID_SIZE;

        if (crypt_load_privkey_str(pkp_str, &pkp) < 0) {
                printf("Failed to load private key.\n");
                goto fail_pkp;
        }

        if (crypt_load_crt_str(crt_str, &pubcrt) < 0) {
                printf("Failed to load public certificate.\n");
                goto fail_pubcrt;
        }

        if (oap_hdr_init(id, pkp, pubcrt, ephkey, data, &oap_hdr) < 0) {
                printf("Failed to create OAP request header.\n");
                goto fail_req_hdr;
        }

        if (oap_hdr.crt.len == 0) {
                printf("OAP request header has no public certificate.\n");
                goto fail_req_hdr;
        }

        if (oap_hdr.sig.len == 0) {
                printf("OAP request header no signature.\n");
                goto fail_req_hdr;
        }

        if (crypt_load_crt_der(oap_hdr.crt, &pubcrt2) < 0) {
                printf("Failed to load public certificate from DER.\n");
                goto fail_crt_der;
        }

        if (crypt_get_pubkey_crt(pubcrt2, &pk) < 0) {
                printf("Failed to get public key from certificate.\n");
                goto fail_crt_pk;
        }

        sign = oap_hdr.hdr;
        sign.len -= (oap_hdr.sig.len + sizeof(uint16_t));

        if (auth_verify_sig(pk, sign, oap_hdr.sig) < 0) {
                printf("Failed to verify OAP request header signature.\n");
                goto fail_check_sig;
        }

        oap_hdr_fini(&oap_hdr);

        crypt_free_crt(pubcrt2);
        crypt_free_crt(pubcrt);
        crypt_free_key(pk);
        crypt_free_key(pkp);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_check_sig:
        crypt_free_key(pk);
 fail_crt_pk:
        crypt_free_crt(pubcrt2);
 fail_crt_der:
        oap_hdr_fini(&oap_hdr);
 fail_req_hdr:
        crypt_free_crt(pubcrt);
 fail_pubcrt:
        crypt_free_key(pkp);
 fail_pkp:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int oap_test(int    argc,
             char **argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_oap_hdr_init_fini();
        ret |= test_oap_hdr_init_fini_data();
#ifdef HAVE_OPENSSL
        ret |= test_oap_hdr_init_fini_signed();
#else
        (void) test_oap_hdr_init_fini_signed;

        ret = TEST_RC_SKIP;
#endif
        return ret;
}
