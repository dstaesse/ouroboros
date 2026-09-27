/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Cryptographic operations
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#endif

#include <config.h>

#include <ouroboros/errno.h>
#include <ouroboros/pthread.h>
#include <ouroboros/random.h>
#include <ouroboros/crypt.h>

#include "crypt/keyrot.h"

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "crypt/openssl.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define DEFAULT_DIGEST NID_sha256 /* when sec.conf is absent or silent */

struct nid_map {
        uint16_t     nid;
        const char * name;
};

static const struct nid_map cipher_nid_map[] = {
        {NID_aes_128_gcm,       "aes-128-gcm"},
        {NID_aes_192_gcm,       "aes-192-gcm"},
        {NID_aes_256_gcm,       "aes-256-gcm"},
        {NID_chacha20_poly1305, "chacha20-poly1305"},
        {NID_undef,             NULL}
};

/* Ordered in strength preference, lowest first */
const uint16_t crypt_supported_nids[] = {
#ifdef HAVE_OPENSSL
        NID_aes_128_gcm,
        NID_aes_192_gcm,
        NID_aes_256_gcm,
        NID_chacha20_poly1305,
#endif
        NID_undef
};

static const struct nid_map kex_nid_map[] = {
        {NID_X9_62_prime256v1,   "prime256v1"},
        {NID_secp384r1,          "secp384r1"},
        {NID_secp521r1,          "secp521r1"},
        {NID_X25519,             "X25519"},
        {NID_X448,               "X448"},
        {NID_ffdhe2048,          "ffdhe2048"},
        {NID_ffdhe3072,          "ffdhe3072"},
        {NID_ffdhe4096,          "ffdhe4096"},
        {NID_MLKEM512,           "ML-KEM-512"},
        {NID_MLKEM768,           "ML-KEM-768"},
        {NID_MLKEM1024,          "ML-KEM-1024"},
        {NID_X25519MLKEM768,     "X25519MLKEM768"},
        {NID_X448MLKEM1024,      "X448MLKEM1024"},
        {NID_SecP256r1MLKEM768,  "SecP256r1MLKEM768"},
        {NID_SecP384r1MLKEM1024, "SecP384r1MLKEM1024"},
        {NID_undef,              NULL}
};

/* Ordered in strength preference, lowest first (NIST SP 800-57 levels) */
const uint16_t kex_supported_nids[] = {
#ifdef HAVE_OPENSSL
        NID_ffdhe2048,          /* FFDHE-2048,  ~112-bit          */
        NID_X9_62_prime256v1,   /* ECDH P-256,   128-bit          */
        NID_X25519,             /* ECDH X25519,  128-bit          */
        NID_ffdhe3072,          /* FFDHE-3072,  ~128-bit          */
        NID_ffdhe4096,          /* FFDHE-4096,  ~152-bit          */
        NID_secp384r1,          /* ECDH P-384,   192-bit          */
        NID_X448,               /* ECDH X448,    224-bit          */
        NID_secp521r1,          /* ECDH P-521,   256-bit          */
#ifdef HAVE_ML
        NID_MLKEM512,           /* ML-KEM-512,  PQC L1 (~AES-128) */
        NID_MLKEM768,           /* ML-KEM-768,  PQC L3 (~AES-192) */
        NID_MLKEM1024,          /* ML-KEM-1024, PQC L5 (~AES-256) */
        NID_SecP256r1MLKEM768,  /* P-256 + ML-KEM-768,   PQC L3   */
        NID_X25519MLKEM768,     /* X25519 + ML-KEM-768,  PQC L3   */
        NID_SecP384r1MLKEM1024, /* P-384 + ML-KEM-1024,  PQC L5   */
        NID_X448MLKEM1024,      /* X448 + ML-KEM-1024,   PQC L5   */
#endif
#endif
        NID_undef
};

static const struct nid_map md_nid_map[] = {
        {NID_sha256,     "sha256"},
        {NID_sha384,     "sha384"},
        {NID_sha512,     "sha512"},
        {NID_sha3_256,   "sha3-256"},
        {NID_sha3_384,   "sha3-384"},
        {NID_sha3_512,   "sha3-512"},
        {NID_blake2b512, "blake2b512"},
        {NID_blake2s256, "blake2s256"},
        {NID_undef,      NULL}
};

/* Ordered in strength preference, lowest first */
const uint16_t md_supported_nids[] = {
#ifdef HAVE_OPENSSL
        NID_blake2s256,
        NID_sha256,
        NID_sha3_256,
        NID_sha384,
        NID_sha3_384,
        NID_blake2b512,
        NID_sha512,
        NID_sha3_512,
#endif
        NID_undef
};

struct crypt_ctx {
        struct keyrot * kr;     /* backend-independent key rotation */
        void *          cipher; /* backend AEAD cipher context      */
};

struct auth_ctx {
        void * store; /* trusted anchors             */
        void * chain; /* untrusted build-only interm */
};

static int parse_kex_value(const char *        value,
                           struct sec_config * cfg)
{
        SET_KEX_ALGO(cfg, value);
        if (cfg->x.nid == NID_undef)
                return -ENOTSUP;

        return 0;
}

/* not in header, but non-static for unit testing */
int parse_sec_config(struct sec_config * cfg,
                     FILE *              fp)
{
        char   line[256];
        char * equals;
        char * key;
        char * value;
        bool   no_enc = false;

        assert(cfg != NULL);
        assert(fp != NULL);

        /* Set defaults */
        SET_KEX_ALGO_NID(cfg, NID_X9_62_prime256v1);
        cfg->x.mode = KEM_MODE_SERVER_ENCAP;
        SET_KEX_KDF_NID(cfg, NID_sha256);
        SET_KEX_CIPHER_NID(cfg, NID_aes_256_gcm);
        SET_KEX_DIGEST_NID(cfg, DEFAULT_DIGEST);
        /* a.req is seeded per-role by the caller; only auth= overrides it */

        while (fgets(line, sizeof(line), fp) != NULL) {
                char * trimmed;

                /* Skip comments and empty lines */
                if (line[0] == '#' || line[0] == '\n')
                        continue;

                /* Bare 'none' keyword replaced by encryption=none */
                trimmed = trim_whitespace(line);
                if (strcmp(trimmed, "none") == 0)
                        return -EINVAL;

                /* Find the = separator */
                equals = strchr(line, '=');
                if (equals == NULL)
                        continue;

                /* Split into key and value */
                *equals = '\0';
                key = trim_whitespace(line);
                value = trim_whitespace(equals + 1);

                /* Parse key exchange field */
                if (strcmp(key, "kex") == 0) {
                        if (parse_kex_value(value, cfg) < 0)
                                return -EINVAL;
                } else if (strcmp(key, "cipher") == 0) {
                        SET_KEX_CIPHER(cfg, value);
                        if (cfg->c.nid == NID_undef)
                                return -EINVAL;
                } else if (strcmp(key, "kdf") == 0) {
                        SET_KEX_KDF(cfg, value);
                        if (cfg->k.nid == NID_undef)
                                return -EINVAL;
                } else if (strcmp(key, "digest") == 0) {
                        SET_KEX_DIGEST(cfg, value);
                        if (cfg->d.nid == NID_undef)
                                return -EINVAL;
                } else if (strcmp(key, "kem_mode") == 0) {
                        if (strcmp(value, "server") == 0) {
                                cfg->x.mode = KEM_MODE_SERVER_ENCAP;
                        } else if (strcmp(value, "client") == 0) {
                                cfg->x.mode = KEM_MODE_CLIENT_ENCAP;
                        } else {
                                return -EINVAL;
                        }
                } else if (strcmp(key, "auth") == 0) {
                        if (strcmp(value, "required") == 0) {
                                cfg->a.req = true;
                        } else if (strcmp(value, "optional") == 0) {
                                cfg->a.req = false;
                        } else {
                                return -EINVAL;
                        }
                } else if (strcmp(key, "cacert") == 0) {
                        if (strlen(value) >= sizeof(cfg->a.cacert))
                                return -EINVAL;
                        strcpy(cfg->a.cacert, value);
                } else if (strcmp(key, "encryption") == 0) {
                        if (strcmp(value, "none") != 0)
                                return -EINVAL;
                        no_enc = true;
                } else {
                        return -EINVAL;
                }
        }

        if (no_enc) {
                /* Digest stays: it belongs to the auth axis */
                CLEAR_KEX_ALGO(cfg);
                CLEAR_KEX_KDF(cfg);
                CLEAR_KEX_CIPHER(cfg);
        }

        return 0;
}

/*
 * Not in header, but non-static for unit testing. Without a crypto
 * backend a present security config is refused.
 */
int crypt_load_sec_config(struct sec_config * cfg,
                          FILE *              fp)
{
        assert(cfg != NULL);
        assert(fp != NULL);

#ifndef HAVE_OPENSSL
        return -ENOTSUP;
#endif

        return parse_sec_config(cfg, fp);
}

/* Parse key exchange config from file */
int load_sec_config_file(struct sec_config * cfg,
                         const char *        path)
{
        FILE * fp;
        int    ret;

        assert(cfg != NULL);
        assert(path != NULL);

        fp = fopen(path, "r");
        if (fp == NULL) {
                /* Absent config is encryption=none; other errors fail */
                if (errno == ENOENT) {
                        CLEAR_KEX_ALGO(cfg);
                        SET_KEX_DIGEST_NID(cfg, DEFAULT_DIGEST);
                        return 0;
                }
                return -errno;
        }

        pthread_cleanup_push(__cleanup_fclose, fp);

        ret = crypt_load_sec_config(cfg, fp);

        pthread_cleanup_pop(0);

        fclose(fp);

        return ret;
}

int kex_pkp_create(struct sec_config * cfg,
                   void **             pkp,
                   uint8_t *           pk)
{
#ifdef HAVE_OPENSSL
        assert(cfg != NULL);
        assert(pkp != NULL);

        *pkp = NULL;

        if (cfg->x.str == NULL || kex_validate_nid(cfg->x.nid) < 0)
                return -ENOTSUP;

        return openssl_pkp_create(cfg->x.str, (EVP_PKEY **) pkp, pk);
#else
        (void) cfg;
        (void) pkp;
        (void) pk;

        *pkp = NULL;

        return 0;
#endif
}

void kex_pkp_destroy(void * pkp)
{
        if (pkp == NULL)
                return;
#ifdef HAVE_OPENSSL
        openssl_pkp_destroy((EVP_PKEY *) pkp);
#else
        (void) pkp;

        return;
#endif
}

int kex_dhe_derive(struct sec_config * cfg,
                   void *              pkp,
                   buffer_t            pk,
                   uint8_t *           s)
{
        assert(cfg != NULL);

        if (kex_validate_nid(cfg->x.nid) < 0)
                return -ENOTSUP;

#ifdef HAVE_OPENSSL
        return openssl_dhe_derive((EVP_PKEY *) pkp, pk, cfg->k.nid, s);
#else
        (void) pkp;
        (void) pk;

        memset(s, 0, SYMMKEYSZ);

        return -ECRYPT;
#endif
}

ssize_t kex_kem_encap(buffer_t  pk,
                      uint8_t * ct,
                      int       kdf,
                      uint8_t * s)
{
#ifdef HAVE_OPENSSL
        return openssl_kem_encap(pk, ct, kdf, s);
#else
        (void) pk;
        (void) ct;
        (void) kdf;

        memset(s, 0, SYMMKEYSZ);

        return -ECRYPT;
#endif
}

ssize_t kex_kem_encap_raw(const char * algo,
                          buffer_t     pk,
                          uint8_t *    ct,
                          int          kdf,
                          uint8_t *    s)
{
#ifdef HAVE_OPENSSL
        return openssl_kem_encap_raw(algo, pk, ct, kdf, s);
#else
        (void) algo;
        (void) pk;
        (void) ct;
        (void) kdf;

        memset(s, 0, SYMMKEYSZ);

        return -ECRYPT;
#endif
}

int kex_kem_decap(void *    pkp,
                  buffer_t  ct,
                  int       kdf,
                  uint8_t * s)
{
#ifdef HAVE_OPENSSL
        return openssl_kem_decap((EVP_PKEY *) pkp, ct, kdf, s);
#else
        (void) pkp;
        (void) ct;
        (void) kdf;

        memset(s, 0, SYMMKEYSZ);

        return -ECRYPT;
#endif
}

int kex_get_algo_from_pk_der(buffer_t pk,
                             char *   algo)
{
#ifdef HAVE_OPENSSL
        return openssl_get_algo_from_pk_der(pk, algo);
#else
        (void) pk;
        algo[0] = '\0';

        return -ECRYPT;
#endif
}

int kex_validate_algo(const char * algo)
{
        if (algo == NULL)
                return -EINVAL;

        /* Use NID validation instead of string array */
        return kex_validate_nid(kex_str_to_nid(algo));
}

int crypt_validate_nid(int nid)
{
        const struct nid_map * p;

        if (nid == NID_undef)
                return -EINVAL;

        for (p = cipher_nid_map; p->name != NULL; p++) {
                if (p->nid == nid)
                        return 0;
        }

        return -ENOTSUP;
}


const char * crypt_nid_to_str(uint16_t nid)
{
        const struct nid_map * p;

        for (p = cipher_nid_map; p->name != NULL; p++) {
                if (p->nid == nid)
                        return p->name;
        }

        return NULL;
}

uint16_t crypt_str_to_nid(const char * cipher)
{
        const struct nid_map * p;

        if (cipher == NULL)
                return NID_undef;

        /* fast, check if cipher pointer is in the map */
        for (p = cipher_nid_map; p->name != NULL; p++) {
                if (cipher == p->name)
                        return p->nid;
        }

        for (p = cipher_nid_map; p->name != NULL; p++) {
                if (strcmp(p->name, cipher) == 0)
                        return p->nid;
        }

        return NID_undef;
}

const char * kex_nid_to_str(uint16_t nid)
{
        const struct nid_map * p;

        for (p = kex_nid_map; p->name != NULL; p++) {
                if (p->nid == nid)
                        return p->name;
        }

        return NULL;
}

uint16_t kex_str_to_nid(const char * algo)
{
        const struct nid_map * p;

        if (algo == NULL)
                return NID_undef;

        /* Fast path: check if algo pointer is in the map */
        for (p = kex_nid_map; p->name != NULL; p++) {
                if (algo == p->name)
                        return p->nid;
        }

        /* Slow path: string comparison */
        for (p = kex_nid_map; p->name != NULL; p++) {
                if (strcmp(p->name, algo) == 0)
                        return p->nid;
        }

        return NID_undef;
}

int kex_validate_nid(int nid)
{
        const struct nid_map * p;

        if (nid == NID_undef)
                return -EINVAL;

        for (p = kex_nid_map; p->name != NULL; p++) {
                if (p->nid == nid)
                        return 0;
        }

        return -ENOTSUP;
}

bool kex_nid_is_hybrid(uint16_t nid)
{
        return nid >= NID_HYBRID_KEM_MIN && nid <= NID_HYBRID_KEM_MAX;
}

const char * md_nid_to_str(uint16_t nid)
{
        const struct nid_map * p;

        for (p = md_nid_map; p->name != NULL; p++) {
                if (p->nid == nid)
                        return p->name;
        }

        return NULL;
}

uint16_t md_str_to_nid(const char * kdf)
{
        const struct nid_map * p;

        if (kdf == NULL)
                return NID_undef;

        /* Fast path: check if kdf pointer is in the map */
        for (p = md_nid_map; p->name != NULL; p++) {
                if (kdf == p->name)
                        return p->nid;
        }

        /* Slow path: string comparison */
        for (p = md_nid_map; p->name != NULL; p++) {
                if (strcmp(p->name, kdf) == 0)
                        return p->nid;
        }

        return NID_undef;
}

int md_validate_nid(int nid)
{
        const struct nid_map * p;

        if (nid == NID_undef)
                return -EINVAL;

        for (p = md_nid_map; p->name != NULL; p++) {
                if (p->nid == nid)
                        return 0;
        }

        return -ENOTSUP;
}

int crypt_cipher_rank(int nid)
{
        int i;

        if (nid == NID_undef)
                return 0;

        for (i = 0; crypt_supported_nids[i] != NID_undef; i++) {
                if ((int) crypt_supported_nids[i] == nid)
                        return i + 1;
        }

        return -1;
}

int crypt_kdf_rank(int nid)
{
        int i;

        if (nid == NID_undef)
                return 0;

        for (i = 0; md_supported_nids[i] != NID_undef; i++) {
                if ((int) md_supported_nids[i] == nid)
                        return i + 1;
        }

        return -1;
}

int crypt_kex_rank(int nid)
{
        int i;

        if (nid == NID_undef)
                return 0;

        for (i = 0; kex_supported_nids[i] != NID_undef; i++) {
                if ((int) kex_supported_nids[i] == nid)
                        return i + 1;
        }

        return -1;
}

/* AEAD primitive: 1:1 backend wrappers used by the data path below. */
static int crypt_seal(void *          cipher,
                      const uint8_t * key,
                      const uint8_t * nonce,
                      buffer_t        aad,
                      buffer_t        in,
                      uint8_t *       out,
                      uint8_t *       tag)
{
#ifdef HAVE_OPENSSL
        return openssl_seal(cipher, key, nonce, aad, in, out, tag);
#else
        (void) cipher;
        (void) key;
        (void) nonce;
        (void) aad;
        (void) in;
        (void) out;
        (void) tag;

        return -ECRYPT;
#endif
}

static int crypt_open(void *          cipher,
                      const uint8_t * key,
                      const uint8_t * nonce,
                      buffer_t        aad,
                      buffer_t        in,
                      const uint8_t * tag,
                      buffer_t *      out)
{
#ifdef HAVE_OPENSSL
        return openssl_open(cipher, key, nonce, aad, in, tag, out);
#else
        (void) cipher;
        (void) key;
        (void) nonce;
        (void) aad;
        (void) in;
        (void) tag;
        (void) out;

        return -ECRYPT;
#endif
}

int crypt_oneshot_seal(int             nid,
                       const uint8_t * key,
                       const uint8_t * nonce,
                       buffer_t        aad,
                       buffer_t        in,
                       buffer_t *      out)
{
        assert(key != NULL);
        assert(nonce != NULL);
        assert(out != NULL);

#ifdef HAVE_OPENSSL
        return openssl_oneshot_seal(nid, key, nonce, aad, in, out);
#else
        (void) nid;
        (void) key;
        (void) nonce;
        (void) aad;
        (void) in;
        (void) out;

        return -ECRYPT;
#endif
}

int crypt_oneshot_open(int             nid,
                       const uint8_t * key,
                       const uint8_t * nonce,
                       buffer_t        aad,
                       buffer_t        in,
                       buffer_t *      out)
{
        assert(key != NULL);
        assert(nonce != NULL);
        assert(out != NULL);

#ifdef HAVE_OPENSSL
        return openssl_oneshot_open(nid, key, nonce, aad, in, out);
#else
        (void) nid;
        (void) key;
        (void) nonce;
        (void) aad;
        (void) in;
        (void) out;

        return -ECRYPT;
#endif
}

/*
 * Data-path encrypt: rotate the key, frame selector ‖ ct ‖ tag, seal.
 * Backend-agnostic: composed from keyrot_*, crypt_seal and crypt_get_tagsz.
 */
int crypt_encrypt(struct crypt_ctx * ctx,
                  buffer_t           in,
                  buffer_t *         out)
{
        uint8_t         nonce[KR_NONCE_LEN];
        const uint8_t * key;
        uint8_t *       ct;
        buffer_t        aad;
        int             tagsz;
        int             out_sz;

        assert(ctx != NULL);
        assert(ctx->kr != NULL);

        tagsz = crypt_get_tagsz(ctx);
        if (tagsz < 0)
                return -ECRYPT;

        out->data = malloc(KR_SELECTOR_LEN + in.len + (size_t) tagsz);
        if (out->data == NULL)
                goto fail_malloc;

        ct = out->data + KR_SELECTOR_LEN;

        /* keyrot writes the selector into the wire header (== AAD). */
        if (keyrot_tx_next(ctx->kr, out->data, &key, nonce) != 0)
                goto fail_encrypt;

        aad.data = out->data;
        aad.len  = KR_SELECTOR_LEN;

        out_sz = crypt_seal(ctx->cipher, key, nonce, aad, in, ct, ct + in.len);
        if (out_sz < 0)
                goto fail_encrypt;

        out->len = KR_SELECTOR_LEN + (size_t) out_sz + (size_t) tagsz;

        return 0;
 fail_encrypt:
        free(out->data);
 fail_malloc:
        clrbuf(*out);
        return -ECRYPT;
}

/*
 * Data-path decrypt: look up the rotated key from the selector, open, and
 * commit the replay window only after the tag verifies.
 */
int crypt_decrypt(struct crypt_ctx * ctx,
                  buffer_t           in,
                  buffer_t *         out)
{
        uint8_t         nonce[KR_NONCE_LEN];
        const uint8_t * key;
        const uint8_t * tag;
        struct kr_rx    rx;
        buffer_t        aad;
        buffer_t        ct;
        int             tagsz;
        int             in_sz;

        assert(ctx != NULL);
        assert(ctx->kr != NULL);

        tagsz = crypt_get_tagsz(ctx);
        if (tagsz < 0)
                return -ECRYPT;

        if (in.len < (size_t) (KR_SELECTOR_LEN + tagsz))
                return -ECRYPT;

        if (keyrot_rx_lookup(ctx->kr, in.data, &key, nonce, &rx) != 0)
                return -ECRYPT;

        in_sz = (int) in.len - KR_SELECTOR_LEN - tagsz;

        /* +1 keeps malloc(0) defined for an empty (zero-length) frame. */
        out->data = malloc((size_t) in_sz + 1);
        if (out->data == NULL)
                goto fail_malloc;

        aad.data = in.data;
        aad.len  = KR_SELECTOR_LEN;

        ct.data = in.data + KR_SELECTOR_LEN;
        ct.len  = (size_t) in_sz;

        tag = in.data + KR_SELECTOR_LEN + in_sz;

        if (crypt_open(ctx->cipher, key, nonce, aad, ct, tag, out) < 0)
                goto fail_decrypt;

        /* Commit replay state only after the tag verifies. */
        if (keyrot_rx_commit(ctx->kr, &rx) != 0)
                goto fail_decrypt;

        return 0;
 fail_decrypt:
        free(out->data);
 fail_malloc:
        clrbuf(*out);
        return -ECRYPT;
}

struct crypt_ctx * crypt_create_ctx(struct crypt_sk * sk)
{
#ifndef HAVE_OPENSSL
        (void) sk;

        return NULL; /* nothing to seal with */
#else
        struct crypt_ctx * crypt;

        if (crypt_validate_nid(sk->nid) != 0)
                return NULL;

        crypt = malloc(sizeof(*crypt));
        if (crypt == NULL)
                goto fail_crypt;

        memset(crypt, 0, sizeof(*crypt));

        crypt->kr = keyrot_create(sk->key, sk->epoch, sk->role);
        if (crypt->kr == NULL)
                goto fail_kr;

        crypt->cipher = openssl_crypt_create_ctx(sk);
        if (crypt->cipher == NULL)
                goto fail_cipher;

        return crypt;

 fail_cipher:
        keyrot_destroy(crypt->kr);
 fail_kr:
        free(crypt);
 fail_crypt:
        return NULL;
#endif
}

void crypt_destroy_ctx(struct crypt_ctx * crypt)
{
        if (crypt == NULL)
                return;

        keyrot_destroy(crypt->kr);
#ifdef HAVE_OPENSSL
        openssl_crypt_destroy_ctx(crypt->cipher);
#endif
        free(crypt);
}

int crypt_get_headsz(struct crypt_ctx * ctx)
{
        assert(ctx != NULL);
        assert(ctx->kr != NULL);

        (void) ctx; /* validated only; header size is a constant */

        return KR_SELECTOR_LEN;
}

int crypt_rekey(struct crypt_ctx * ctx,
                struct crypt_sk *  sk)
{
        int ret;

        assert(ctx != NULL);
        assert(sk != NULL);
        assert(ctx->kr != NULL);

        ret = keyrot_rekey(ctx->kr, sk->key, sk->epoch);
        if (ret == -EREPLAY)
                return -EREPLAY;

        return ret == 0 ? 0 : -ECRYPT;
}

int crypt_get_tagsz(struct crypt_ctx * ctx)
{
        assert(ctx != NULL);
        assert(ctx->cipher != NULL);

#ifdef HAVE_OPENSSL
        return openssl_crypt_get_tagsz(ctx->cipher);
#else
        (void) ctx;
        return -ENOTSUP;
#endif
}

int crypt_nodes_left(struct crypt_ctx * ctx)
{
        assert(ctx != NULL);
        assert(ctx->kr != NULL);

        return (int) keyrot_tx_nodes_left(ctx->kr);
}

int crypt_peer_synced(struct crypt_ctx * ctx)
{
        assert(ctx != NULL);
        assert(ctx->kr != NULL);

        return keyrot_peer_switched(ctx->kr) ? 1 : 0;
}

void crypt_tx_promote(struct crypt_ctx * ctx)
{
        assert(ctx != NULL);
        assert(ctx->kr != NULL);

        keyrot_tx_promote(ctx->kr);
}

int crypt_load_privkey_file(const char * path,
                            void **      key)
{
        *key = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_privkey_file(path, key);
#else
        (void) path;

        return -ENOTSUP;
#endif
}

int crypt_load_privkey_str(const char * str,
                           void **      key)
{
        *key = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_privkey_str(str, key);
#else
        (void) str;

        return -ENOTSUP;
#endif
}

int crypt_load_pubkey_str(const char * str,
                          void **      key)
{
        *key = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_pubkey_str(str, key);
#else
        (void) str;

        return -ENOTSUP;
#endif
}

int crypt_load_pubkey_file(const char * path,
                           void **      key)
{
        *key = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_pubkey_file(path, key);
#else
        (void) path;

        return -ENOTSUP;
#endif
}

int crypt_load_pubkey_file_to_der(const char * path,
                                  buffer_t *   buf)
{
        assert(buf != NULL);

#ifdef HAVE_OPENSSL
        return openssl_load_pubkey_file_to_der(path, buf);
#else
        (void) path;

        buf->data = NULL;
        buf->len  = 0;
        return 0;
#endif
}

int crypt_load_pubkey_raw_file(const char * path,
                               const char * algo,
                               buffer_t *   buf)
{
        assert(buf != NULL);

#ifdef HAVE_OPENSSL
        return openssl_load_pubkey_raw_file(path, algo, buf);
#else
        (void) path;
        (void) algo;

        buf->data = NULL;
        buf->len  = 0;
        return 0;
#endif
}

int crypt_load_privkey_raw_file(const char * path,
                                const char * algo,
                                void **      key)
{
        *key = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_privkey_raw_file(path, algo, key);
#else
        (void) path;
        (void) algo;

        return 0;
#endif
}

int crypt_ct_cmp(const void * a,
                 const void * b,
                 size_t       len)
{
#ifdef HAVE_OPENSSL
        return CRYPTO_memcmp(a, b, len);
#else
        const volatile uint8_t * pa = a;
        const volatile uint8_t * pb = b;
        uint8_t                  d  = 0;
        size_t                   i;

        for (i = 0; i < len; i++)
                d |= pa[i] ^ pb[i];

        return d != 0;
#endif
}

int crypt_cmp_key(const void * key1,
                  const void * key2)
{
#ifdef HAVE_OPENSSL
        return openssl_cmp_key((const EVP_PKEY *) key1,
                               (const EVP_PKEY *) key2);
#else
        (void) key1;
        (void) key2;

        return 0;
#endif
}

void crypt_free_key(void * key)
{
        if (key == NULL)
                return;

#ifdef HAVE_OPENSSL
        openssl_free_key((EVP_PKEY *) key);
#endif
}

int crypt_load_crt_file(const char * path,
                        void **      crt)
{
        assert(crt != NULL);

        *crt = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_crt_file(path, crt);
#else
        (void) path;

        return 0;
#endif
}

int crypt_load_crt_str(const char * str,
                       void **      crt)
{
        assert(crt != NULL);

        *crt = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_crt_str(str, crt);
#else
        (void) str;

        return 0;
#endif
}

int crypt_load_crt_der(const buffer_t buf,
                       void **        crt)
{
        assert(crt != NULL);
#ifdef HAVE_OPENSSL
        return openssl_load_crt_der(buf, crt);
#else
        *crt = NULL;

        (void) buf;

        return 0;
#endif
}

int crypt_get_pubkey_crt(void *  crt,
                         void ** pk)
{
        assert(crt != NULL);
        assert(pk != NULL);

#ifdef HAVE_OPENSSL
        return openssl_get_pubkey_crt(crt, pk);
#else
        (void) crt;

        clrbuf(*pk);

        return 0;
#endif
}

void crypt_free_crt(void * crt)
{
        if (crt == NULL)
                return;
#ifdef HAVE_OPENSSL
        openssl_free_crt(crt);
#endif
}

int crypt_crt_str(const void * crt,
                  char *       buf)
{
#ifdef HAVE_OPENSSL
        return openssl_crt_str(crt, buf);
#else
        (void) crt;
        (void) buf;

        return 0;
#endif
}

int crypt_crt_der(const void * crt,
                  buffer_t *   buf)
{
        assert(crt != NULL);
        assert(buf != NULL);

#ifdef HAVE_OPENSSL
        return openssl_crt_der(crt, buf);
#else
        (void) crt;

        clrbuf(*buf);

        return 0;
#endif
}

int crypt_check_crt_name(void *       crt,
                         const char * name)
{
#ifdef HAVE_OPENSSL
        return openssl_check_crt_name(crt, name);
#else
        (void) crt;
        (void) name;

        return -ENOTSUP;
#endif
}

int crypt_get_crt_name(void * crt,
                       char * name)
{
#ifdef HAVE_OPENSSL
        return openssl_get_crt_name(crt, name);
#else
        (void) crt;
        (void) name;

        return 0;
#endif
}

struct auth_ctx * auth_create_ctx(void)
{
        struct auth_ctx * ctx;

        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL)
                goto fail_malloc;

        memset(ctx, 0, sizeof(*ctx));
#ifdef HAVE_OPENSSL
        ctx->store = openssl_auth_create_store();
        if (ctx->store == NULL)
                goto fail_store;

        ctx->chain = openssl_auth_create_chain();
        if (ctx->chain == NULL)
                goto fail_chain;
#endif
        return ctx;
#ifdef HAVE_OPENSSL
 fail_chain:
        openssl_auth_destroy_store(ctx->store);
 fail_store:
        free(ctx);
#endif
 fail_malloc:
        return NULL;
}

void auth_destroy_ctx(struct auth_ctx * ctx)
{
        if (ctx == NULL)
                return;
#ifdef HAVE_OPENSSL
        openssl_auth_destroy_chain(ctx->chain);
        openssl_auth_destroy_store(ctx->store);
#endif
        free(ctx);
}

int auth_add_crt_to_store(struct auth_ctx * ctx,
                          void *            crt)
{
        assert(ctx != NULL);
        assert(crt != NULL);

#ifdef HAVE_OPENSSL
        return openssl_auth_add_crt_to_store(ctx->store, crt);
#else
        (void) ctx;
        (void) crt;

        return 0;
#endif
}

int auth_add_crt_to_chain(struct auth_ctx * ctx,
                          void *            crt)
{
        assert(ctx != NULL);
        assert(crt != NULL);

#ifdef HAVE_OPENSSL
        return openssl_auth_add_crt_to_chain(ctx->chain, crt);
#else
        (void) ctx;
        (void) crt;

        return 0;
#endif
}

int auth_verify_crt(struct auth_ctx * ctx,
                    void *            crt)
{
#ifdef HAVE_OPENSSL
        return openssl_verify_crt(ctx->store, ctx->chain, crt);
#else
        (void) ctx;
        (void) crt;

        return -ENOTSUP;
#endif
}

int auth_verify_crt_pin(struct auth_ctx * ctx,
                        void *            crt,
                        void *            pin)
{
#ifdef HAVE_OPENSSL
        return openssl_verify_crt_pin(ctx->store, ctx->chain, crt, pin);
#else
        (void) ctx;
        (void) crt;
        (void) pin;

        return -ENOTSUP;
#endif
}

bool crypt_pk_requires_md(const void * pk)
{
#ifdef HAVE_OPENSSL
        return openssl_pk_requires_md((const EVP_PKEY *) pk);
#else
        (void) pk;

        return false;
#endif
}

int auth_sign(void *     pkp,
              int        md_nid,
              buffer_t   msg,
              buffer_t * sig)
{
#ifdef HAVE_OPENSSL
        return openssl_sign((EVP_PKEY *) pkp, md_nid, msg, sig);
#else
        (void) pkp;
        (void) md_nid;
        (void) msg;
        (void) sig;

        clrbuf(*sig);

        return 0;
#endif
}

int auth_verify_sig(void *   pk,
                    int      md_nid,
                    buffer_t msg,
                    buffer_t sig)
{
#ifdef HAVE_OPENSSL
        return openssl_verify_sig((EVP_PKEY *) pk, md_nid, msg, sig);
#else
        (void) pk;
        (void) md_nid;
        (void) msg;
        (void) sig;

        return -ENOTSUP;
#endif
}

ssize_t md_digest(int       md_nid,
                  buffer_t  in,
                  uint8_t * out)
{
#ifdef HAVE_OPENSSL
        return openssl_md_digest(md_nid, in, out);
#else
        (void) md_nid;
        (void) in;
        (void) out;

        return -1;
#endif
}

ssize_t md_len(int md_nid)
{
#ifdef HAVE_OPENSSL
        return openssl_md_len(md_nid);
#else
        (void) md_nid;
        return -1;
#endif
}

int crypt_hkdf_expand(buffer_t key,
                      buffer_t info,
                      buffer_t out)
{
#ifdef HAVE_OPENSSL
        return openssl_hkdf_expand(key, info, out) == 0 ? 0 : -ECRYPT;
#else
        (void) key;
        (void) info;
        (void) out;

        return -ECRYPT;
#endif
}

int crypt_secure_malloc_init(size_t max)
{
#ifdef HAVE_OPENSSL
        return openssl_secure_malloc_init(max, SECMEM_MINSIZE);
#else
        (void) max;
        return 0;
#endif
}

void crypt_secure_malloc_fini(void)
{
#ifdef HAVE_OPENSSL
        openssl_secure_malloc_fini();
#endif
}

void crypt_cleanup(void)
{
#ifdef HAVE_OPENSSL
        openssl_cleanup();
#endif
}

void * crypt_secure_malloc(size_t size)
{
#ifdef HAVE_OPENSSL
        return openssl_secure_malloc(size);
#else
        return malloc(size);
#endif
}

void crypt_secure_free(void * ptr,
                       size_t size)
{
        if (ptr == NULL)
                return;

#ifdef HAVE_OPENSSL
        openssl_secure_free(ptr, size);
#else
        memset(ptr, 0, size);
        free(ptr);
#endif
}

void crypt_secure_clear(void * ptr,
                        size_t size)
{
        volatile uint8_t * p;

        if (ptr == NULL)
                return;

#ifdef HAVE_OPENSSL
        (void) p;
        openssl_secure_clear(ptr, size);
#elif defined(HAVE_EXPLICIT_BZERO)
        (void) p;
        explicit_bzero(ptr, size);
#else /* best effort to avoid optimizing out */
        p = ptr;
        while (size-- > 0)
                *p++ = 0;
#endif
}
