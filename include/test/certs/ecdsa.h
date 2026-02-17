/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test certificates - ECDSA/P-256 signed certificates
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef TEST_CERTS_ECDSA_H
#define TEST_CERTS_ECDSA_H

/*
* Certificates created following the guide
*   Building an openssl certificate authority
* on
*   https://community.f5.com/kb/technicalarticles/
*/

/* Root certificate for CA ca.unittest.o7s */
static const char * root_ca_crt_ec = \
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
static const char * im_ca_crt_ec = \
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
static const char * server_pkp_ec = \
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIA4/bcmquVvGrY4+TtfnFSy1SpXs896r5xJjGuD6NmGRoAoGCCqGSM49\n"
"AwEHoUQDQgAE4BSOhv36q4bCMLSkJaCvzwZ3pPy2M0YzRKFKeV48tG5eD+MBaTrT\n"
"eoHUcRfpz0EO/inq3FVDzEoAQ2NWpnz0kA==\n"
"-----END EC PRIVATE KEY-----\n";

/* Public key for the Private key */
static __attribute__((unused)) const char * server_pk_ec = \
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4BSOhv36q4bCMLSkJaCvzwZ3pPy2\n"
"M0YzRKFKeV48tG5eD+MBaTrTeoHUcRfpz0EO/inq3FVDzEoAQ2NWpnz0kA==\n"
"-----END PUBLIC KEY-----\n";

/* Valid signed server certificate for test-1.unittest.o7s */
#define SSC_TEXT_SIZE 2295 /* size of cleartext certificate */
static const char * signed_server_crt_ec = \
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
static __attribute__((unused)) const char * server_crt_ec = \
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

#endif /* TEST_CERTS_H */

