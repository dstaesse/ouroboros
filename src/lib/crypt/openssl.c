/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OpenSSL based cryptographic operations
 * Elliptic curve Diffie-Hellman key exchange
 * AES encryption
 # Authentication
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

#define _POSIX_C_SOURCE 200809L

#include <config.h>

#include <ouroboros/errno.h>
#include <ouroboros/crypt.h>
#include <ouroboros/hash.h>
#include <ouroboros/name.h>
#include <ouroboros/pthread.h>
#include <ouroboros/random.h>
#include <ouroboros/utils.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <assert.h>
#include <limits.h>
#include <stdio.h>

#define IS_EC_GROUP(str) (strcmp(str, "EC") == 0)
#define IS_DH_GROUP(str) (strcmp(str, "DH") == 0)

#define HKDF_INFO_DHE      "o7s-ossl-dhe"
#define HKDF_INFO_ENCAP    "o7s-ossl-encap"
#define HKDF_SALT_LEN      32 /* SHA-256 output size */
#define AEAD_NONCE_LEN     12 /* 96-bit deterministic IV (SP 800-38D) */
#define AEAD_TAG_LEN       16 /* 128-bit AEAD authentication tag */

/*
 * Holds only the cipher identity, which is fixed at creation. A flow's
 * context is sealed and opened by several threads at once, so nothing
 * here may carry per-packet state.
 */
struct ossl_crypt_ctx {
        const EVP_CIPHER * cipher;
        int                tagsz;
};

/*
 * Per-thread AEAD context. A key covers 2^KEY_LEAF_BITS packets, so
 * the key schedule is worth keeping between them; only the nonce
 * changes. Thread-local, so concurrent sealers share nothing, and a
 * miss costs no more than a full install.
 */
struct ossl_aead {
        EVP_CIPHER_CTX *   evp;
        const EVP_CIPHER * cipher; /* NULL when the state is unusable */
        uint8_t            key[SYMMKEYSZ];
        size_t             keylen;
};

struct ossl_aead_tls {
        struct ossl_aead seal;
        struct ossl_aead open;
};

static struct {
        pthread_key_t  key;
        pthread_once_t once;
} aead_g = { 0, PTHREAD_ONCE_INIT };

struct kdf_info {
        buffer_t secret;
        int      nid;
        buffer_t salt;
        buffer_t info;
        buffer_t key;
};

/* Convert hash NID to OpenSSL digest name string for HKDF */
static const char * hash_nid_to_digest_name(int nid)
{
        const EVP_MD * md;
        const char *   name;

        md = EVP_get_digestbynid(nid);
        if (md == NULL)
                return NULL;

        name = EVP_MD_get0_name(md);
        if (name == NULL)
                return NULL;

        return name;
}

/* Extract public key bytes from a key pair for salt derivation */
static int get_pk_bytes_from_key(EVP_PKEY * key,
                                 buffer_t * pk)
{
        const char * name;
        int          ret;

        assert(key != NULL);
        assert(pk != NULL);

        name = EVP_PKEY_get0_type_name(key);
        if (name == NULL)
                goto fail_name;

        if (IS_HYBRID_KEM(name)) {
                pk->len = EVP_PKEY_get1_encoded_public_key(key, &pk->data);
                if (pk->len == 0)
                        goto fail_name;
        } else {
                /* Pure ML-KEM: use DER encoding to match encap */
                pk->data = NULL;
                ret = i2d_PUBKEY(key, &pk->data);
                if (ret <= 0)
                        goto fail_name;
                pk->len = (size_t) ret;
        }

        return 0;
 fail_name:
        return -ECRYPT;
}

/* Derive salt from public key bytes by hashing them */
static int derive_salt_from_pk_bytes(buffer_t pk,
                                     buffer_t salt)
{
        uint8_t  hash[EVP_MAX_MD_SIZE];
        unsigned hash_len;

        assert(pk.data != NULL);
        assert(salt.data != NULL);

        if (EVP_Digest(pk.data, pk.len, hash, &hash_len,
                       EVP_sha256(), NULL) != 1)
                goto fail_digest;

        memcpy(salt.data, hash, salt.len < hash_len ? salt.len : hash_len);

        return 0;
 fail_digest:
        return -ECRYPT;
}

/* Derive salt from two public key byte buffers (DHE) in canonical order */
static int derive_salt_from_pk_bytes_dhe(buffer_t local,
                                         buffer_t remote,
                                         buffer_t salt)
{
        uint8_t * concat;
        size_t    concat_len;
        uint8_t   hash[EVP_MAX_MD_SIZE];
        unsigned  hash_len;
        size_t    min_len;
        int       cmp;

        assert(local.data != NULL);
        assert(remote.data != NULL);
        assert(salt.data != NULL);

        concat_len = local.len + remote.len;
        concat = OPENSSL_malloc(concat_len);
        if (concat == NULL)
                goto fail_malloc;

        /* Canonical order: compare and concatenate smaller first */
        min_len = local.len < remote.len ? local.len : remote.len;
        cmp = memcmp(local.data, remote.data, min_len);
        if (cmp < 0 || (cmp == 0 && local.len < remote.len)) {
                memcpy(concat, local.data, local.len);
                memcpy(concat + local.len, remote.data, remote.len);
        } else {
                memcpy(concat, remote.data, remote.len);
                memcpy(concat + remote.len, local.data, local.len);
        }

        if (EVP_Digest(concat, concat_len, hash, &hash_len,
                       EVP_sha256(), NULL) != 1)
                goto fail_digest;

        OPENSSL_free(concat);

        memcpy(salt.data, hash, salt.len < hash_len ? salt.len : hash_len);

        return 0;
 fail_digest:
        OPENSSL_free(concat);
 fail_malloc:
        return -ECRYPT;
}

/* Derive key using HKDF */
#define OPc_u_str  OSSL_PARAM_construct_utf8_string
#define OPc_o_str  OSSL_PARAM_construct_octet_string
static int derive_key_hkdf(struct kdf_info * ki)
{
        EVP_KDF *     kdf;
        EVP_KDF_CTX * kctx;
        OSSL_PARAM    params[5];
        const char *  digest;
        int           idx;

        digest = hash_nid_to_digest_name(ki->nid);
        if (digest == NULL)
                goto fail_fetch;

        kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        if (kdf == NULL)
                goto fail_fetch;

        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL)
                goto fail_ctx;

        idx = 0;
        params[idx++] = OPc_u_str("digest", (char *) digest, 0);
        params[idx++] = OPc_o_str("key", ki->secret.data, ki->secret.len);
        params[idx++] = OPc_o_str("salt", ki->salt.data, ki->salt.len);
        params[idx++] = OPc_o_str("info", ki->info.data, ki->info.len);

        params[idx] = OSSL_PARAM_construct_end();

        if (EVP_KDF_derive(kctx, ki->key.data, ki->key.len, params) != 1)
                goto fail_derive;

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);

        return 0;

 fail_derive:
        EVP_KDF_CTX_free(kctx);
 fail_ctx:
        EVP_KDF_free(kdf);
 fail_fetch:
        return -ECRYPT;
}

int openssl_hkdf_expand(buffer_t key,
                        buffer_t info,
                        buffer_t out)
{
        EVP_KDF *     kdf;
        EVP_KDF_CTX * kctx;
        OSSL_PARAM    params[5];
        int           mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
        int           idx  = 0;
        int           ret  = -1;

        kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        if (kdf == NULL)
                goto fail_fetch;

        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL)
                goto fail_ctx;

        params[idx++] = OSSL_PARAM_construct_utf8_string(
                "digest", (char *) "SHA256", 0);
        params[idx++] = OSSL_PARAM_construct_int("mode", &mode);
        params[idx++] = OSSL_PARAM_construct_octet_string(
                "key", key.data, key.len);
        params[idx++] = OSSL_PARAM_construct_octet_string(
                "info", info.data, info.len);
        params[idx]   = OSSL_PARAM_construct_end();

        if (EVP_KDF_derive(kctx, out.data, out.len, params) == 1)
                ret = 0;

        EVP_KDF_CTX_free(kctx);
 fail_ctx:
        EVP_KDF_free(kdf);
 fail_fetch:
        return ret;
}

static void aead_tls_free(void * p)
{
        struct ossl_aead_tls * t = p;
        if (t == NULL)
                return;

        EVP_CIPHER_CTX_free(t->seal.evp);
        EVP_CIPHER_CTX_free(t->open.evp);

        crypt_secure_clear(t->seal.key, SYMMKEYSZ);
        crypt_secure_clear(t->open.key, SYMMKEYSZ);

        free(t);
}

static void aead_tls_init(void)
{
        pthread_key_create(&aead_g.key, aead_tls_free);
}

static struct ossl_aead_tls * aead_tls_get(void)
{
        struct ossl_aead_tls * t;

        pthread_once(&aead_g.once, aead_tls_init);

        t = pthread_getspecific(aead_g.key);
        if (t != NULL)
                return t;

        t = malloc(sizeof(*t));
        if (t == NULL)
                return NULL;

        memset(t, 0, sizeof(*t));

        if (pthread_setspecific(aead_g.key, t) != 0) {
                free(t);
                return NULL;
        }

        return t;
}

/* Install cipher and key; the nonce is set per packet by the caller. */
static int aead_install(EVP_CIPHER_CTX *   evp,
                        const EVP_CIPHER * cipher,
                        const uint8_t *    key,
                        bool               enc)
{
        EVP_CIPHER_CTX_reset(evp);

        if (enc) {
                if (EVP_EncryptInit_ex(evp, cipher, NULL, NULL, NULL) != 1)
                        return -1;
        } else {
                if (EVP_DecryptInit_ex(evp, cipher, NULL, NULL, NULL) != 1)
                        return -1;
        }

        /* Pin the AEAD nonce to 96 bits (SP 800-38D deterministic IV). */
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_IVLEN,
                                AEAD_NONCE_LEN, NULL) != 1)
                return -1;

        if (enc) {
                if (EVP_EncryptInit_ex(evp, NULL, NULL, key, NULL) != 1)
                        return -1;
        } else {
                if (EVP_DecryptInit_ex(evp, NULL, NULL, key, NULL) != 1)
                        return -1;
        }

        return 0;
}

/* This thread's context for cipher/key, ready to take a nonce. */
static EVP_CIPHER_CTX * aead_ctx(struct ossl_aead * a,
                                 const EVP_CIPHER * cipher,
                                 const uint8_t *    key,
                                 bool               enc)
{
        int keylen;

        keylen = EVP_CIPHER_get_key_length(cipher);
        if (keylen <= 0 || (size_t) keylen > SYMMKEYSZ)
                return NULL;

        /* Compare the bytes: a cache slot can be reused for a new key. */
        if (a->cipher == cipher && a->keylen == (size_t) keylen
            && CRYPTO_memcmp(a->key, key, a->keylen) == 0)
                return a->evp;

        if (a->evp == NULL) {
                a->evp = EVP_CIPHER_CTX_new();
                if (a->evp == NULL)
                        return NULL;
        }

        a->cipher = NULL;
        if (aead_install(a->evp, cipher, key, enc) < 0)
                return NULL;

        memcpy(a->key, key, (size_t) keylen);

        a->keylen = (size_t) keylen;
        a->cipher = cipher;

        return a->evp;
}

/* AEAD seal: encrypt in with key/nonce, bind aad, append tag */
int openssl_seal(struct ossl_crypt_ctx * ctx,
                 const uint8_t *         key,
                 const uint8_t *         nonce,
                 buffer_t                aad,
                 buffer_t                in,
                 uint8_t *               out,
                 uint8_t *               tag)
{
        struct ossl_aead_tls * tls;
        EVP_CIPHER_CTX *       evp;
        int                    out_sz;
        int                    tmp_sz;

        assert(ctx != NULL);
        assert(ctx->tagsz > 0); /* AEAD mandated at ctx creation */

        tls = aead_tls_get();
        if (tls == NULL)
                goto fail;

        evp = aead_ctx(&tls->seal, ctx->cipher, key, true);
        if (evp == NULL)
                goto fail;

        if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1)
                goto fail_evp;

        if (EVP_EncryptUpdate(evp, NULL, &tmp_sz, aad.data, (int) aad.len) != 1)
                goto fail_evp;

        if (EVP_EncryptUpdate(evp, out, &out_sz, in.data, (int) in.len) != 1)
                goto fail_evp;

        if (EVP_EncryptFinal_ex(evp, out + out_sz, &tmp_sz) != 1)
                goto fail_evp;

        out_sz += tmp_sz;

        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_GET_TAG,
                                ctx->tagsz, tag) != 1)
                goto fail_evp;

        return out_sz;
 fail_evp:
        tls->seal.cipher = NULL; /* state unknown; install afresh */
 fail:
        return -1;
}

/* AEAD open: decrypt in with key/nonce, verify aad and tag */
int openssl_open(struct ossl_crypt_ctx * ctx,
                 const uint8_t *         key,
                 const uint8_t *         nonce,
                 buffer_t                aad,
                 buffer_t                in,
                 const uint8_t *         tag,
                 buffer_t *              out)
{
        struct ossl_aead_tls * tls;
        EVP_CIPHER_CTX *       evp;
        int                    out_sz;
        int                    tmp_sz;

        assert(ctx != NULL);
        assert(ctx->tagsz > 0); /* AEAD mandated at ctx creation */

        tls = aead_tls_get();
        if (tls == NULL)
                goto fail;

        evp = aead_ctx(&tls->open, ctx->cipher, key, false);
        if (evp == NULL)
                goto fail;

        if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1)
                goto fail_evp;

        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_TAG,
                                ctx->tagsz, (void *) tag) != 1)
                goto fail_evp;

        if (EVP_DecryptUpdate(evp, NULL, &tmp_sz, aad.data, (int) aad.len) != 1)
                goto fail_evp;

        if (EVP_DecryptUpdate(evp, out->data, &out_sz,
                              in.data, (int) in.len) != 1)
                goto fail_evp;

        /* A failed verify leaves defined state; keep the key cached. */
        if (EVP_DecryptFinal_ex(evp, out->data + out_sz, &tmp_sz) != 1)
                goto fail_verify;

        out_sz += tmp_sz;

        out->len = (size_t) out_sz;

        return out_sz;
 fail_evp:
        tls->open.cipher = NULL; /* state unknown; install afresh */
 fail_verify:
 fail:
        return -1;
}

/*
 * Derive the common secret from
 * - your public key pair (pkp)
 * - the remote public key bytes (remote_pk).
 * Store it in a preallocated buffer (s).
 */
static int __openssl_dhe_derive(EVP_PKEY * pkp,
                                EVP_PKEY * pub,
                                buffer_t   remote_pk,
                                int        kdf,
                                uint8_t *  s)
{
        EVP_PKEY_CTX *  ctx;
        struct kdf_info ki;
        buffer_t        local_pk;
        int             ret;
        uint8_t *       secret;
        size_t          secret_len;
        uint8_t         salt_buf[HKDF_SALT_LEN];

        /* Extract local public key bytes */
        local_pk.data = NULL;
        ret = i2d_PUBKEY(pkp, &local_pk.data);
        if (ret <= 0)
                goto fail_local;

        local_pk.len = (size_t) ret;

        ki.salt.len  = HKDF_SALT_LEN;
        ki.salt.data = salt_buf;

        /* Derive salt from both public keys */
        if (derive_salt_from_pk_bytes_dhe(local_pk, remote_pk, ki.salt) < 0)
                goto fail_salt;

        ctx = EVP_PKEY_CTX_new(pkp, NULL);
        if (ctx == NULL)
                goto fail_salt;

        ret = EVP_PKEY_derive_init(ctx);
        if (ret != 1)
                goto fail_ctx;

        ret = EVP_PKEY_derive_set_peer(ctx, pub);
        if (ret != 1)
                goto fail_ctx;

        ret = EVP_PKEY_derive(ctx, NULL, &secret_len);
        if (ret != 1)
                goto fail_ctx;

        if (secret_len < SYMMKEYSZ)
                goto fail_ctx;

        secret = OPENSSL_malloc(secret_len);
        if (secret == NULL)
                goto fail_ctx;

        ret = EVP_PKEY_derive(ctx, secret, &secret_len);
        if (ret != 1)
                goto fail_derive;

        ki.nid         = kdf;
        ki.secret.len  = secret_len;
        ki.secret.data = secret;
        ki.info.len    = strlen(HKDF_INFO_DHE);
        ki.info.data   = (uint8_t *) HKDF_INFO_DHE;
        ki.key.len     = SYMMKEYSZ;
        ki.key.data    = s;

        /* Derive symmetric key from shared secret using HKDF */
        ret = derive_key_hkdf(&ki);

        OPENSSL_clear_free(secret, secret_len);
        EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(local_pk.data);

        if (ret != 0)
                return ret;

        return 0;
 fail_derive:
        OPENSSL_clear_free(secret, secret_len);
 fail_ctx:
        EVP_PKEY_CTX_free(ctx);
 fail_salt:
        OPENSSL_free(local_pk.data);
 fail_local:
        return -ECRYPT;
}

static int __openssl_dhe_gen_key(const char * algo,
                                 EVP_PKEY **  kp)
{
        EVP_PKEY_CTX * ctx    = NULL;
        EVP_PKEY_CTX * kctx   = NULL;
        EVP_PKEY *     params = NULL;
        int            nid;
        int            type;
        int            ret;

        assert(algo != NULL);
        assert(kp != NULL);

        nid = OBJ_txt2nid(algo);
        if (nid == NID_undef)
                return -ECRYPT;

        /* X25519 and X448: direct keygen context */
        if (nid == EVP_PKEY_X25519 || nid == EVP_PKEY_X448) {
                kctx = EVP_PKEY_CTX_new_id(nid, NULL);
                if (kctx == NULL)
                        goto fail_kctx;

                goto keygen;
        }
        /* EC and FFDHE: parameter generation first */
        type = (strncmp(algo, "ffdhe", 5) == 0) ? EVP_PKEY_DH : EVP_PKEY_EC;

        ctx = EVP_PKEY_CTX_new_id(type, NULL);
        if (ctx == NULL)
                goto fail_ctx;

        ret = EVP_PKEY_paramgen_init(ctx);
        if (ret != 1)
                goto fail_paramgen;

        if (type == EVP_PKEY_EC)
                ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
        else /* EVP_PKEY_DH */
                ret = EVP_PKEY_CTX_set_dh_nid(ctx, nid);

        if (ret != 1)
                goto fail_paramgen;

        ret = EVP_PKEY_paramgen(ctx, &params);
        if (ret != 1)
                goto fail_paramgen;

        kctx = EVP_PKEY_CTX_new(params, NULL);
        if (kctx == NULL)
                goto fail_kctx;

        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(ctx);
 keygen:
        ret = EVP_PKEY_keygen_init(kctx);
        if (ret != 1)
                goto fail_keygen;

        ret = EVP_PKEY_keygen(kctx, kp);
        if (ret != 1)
                goto fail_keygen;

        EVP_PKEY_CTX_free(kctx);

        return 0;

 fail_keygen:
        EVP_PKEY_CTX_free(kctx);
        return -ECRYPT;
 fail_kctx:
        if (params != NULL)
                EVP_PKEY_free(params);
 fail_paramgen:
        if (ctx != NULL)
                EVP_PKEY_CTX_free(ctx);
 fail_ctx:
        return -ECRYPT;
}

static int __openssl_kem_gen_key(const char * algo,
                                 EVP_PKEY **  kp)
{
        EVP_PKEY_CTX * kctx;
        int            ret;

        assert(algo != NULL);
        assert(kp != NULL);

        /* PQC KEM (ML-KEM-512, ML-KEM-768, ML-KEM-1024) or hybrid */
        kctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
        if (kctx == NULL)
                goto fail_kctx;

        ret = EVP_PKEY_keygen_init(kctx);
        if (ret != 1)
                goto fail_keygen;

        ret = EVP_PKEY_keygen(kctx, kp);
        if (ret != 1)
                goto fail_keygen;

        EVP_PKEY_CTX_free(kctx);

        return 0;

 fail_keygen:
        EVP_PKEY_CTX_free(kctx);
 fail_kctx:
        return -ECRYPT;
}

static int __openssl_kex_gen_key(const char *  algo,
                                 EVP_PKEY **   kp)
{
        assert(algo != NULL);
        assert(kp != NULL);

        /* Dispatch based on algorithm name prefix */
        if (IS_KEM_ALGORITHM(algo))
                return __openssl_kem_gen_key(algo, kp);

        return __openssl_dhe_gen_key(algo, kp);
}

ssize_t openssl_pkp_create(const char *  algo,
                           EVP_PKEY **   pkp,
                           uint8_t *     pk)
{
        uint8_t *  pos;
        buffer_t   raw;
        ssize_t    len;

        assert(algo != NULL);
        assert(pkp != NULL);
        assert(*pkp == NULL);
        assert(pk != NULL);

        if (__openssl_kex_gen_key(algo, pkp) < 0)
                goto fail_key;

        if (IS_HYBRID_KEM(algo)) { /* Raw encode hybrid KEM */
                raw.len = EVP_PKEY_get1_encoded_public_key(*pkp, &raw.data);
                if (raw.len == 0)
                        goto fail_pubkey;

                if (raw.len > CRYPT_KEY_BUFSZ) {
                        OPENSSL_free(raw.data);
                        goto fail_pubkey;
                }

                memcpy(pk, raw.data, raw.len);
                OPENSSL_free(raw.data);

                return (ssize_t) raw.len;
        } else { /* DER encode standard algorithms */
                len = i2d_PUBKEY(*pkp, NULL); /* pre-flight length */
                if (len < 0 || len > CRYPT_KEY_BUFSZ)
                        goto fail_pubkey;

                pos = pk; /* i2d_PUBKEY increments the ptr, don't use pk! */
                if (i2d_PUBKEY(*pkp, &pos) < 0)
                        goto fail_pubkey;

                return len;
        }
 fail_pubkey:
        EVP_PKEY_free(*pkp);
 fail_key:
        return -ECRYPT;
}

/* Common KEM encapsulation - pub key and salt already prepared */
static ssize_t __openssl_kem_encap(EVP_PKEY * pub,
                                   uint8_t *  salt,
                                   uint8_t *  ct,
                                   int        kdf,
                                   uint8_t *  s)
{
        EVP_PKEY_CTX *  ctx;
        struct kdf_info ki;
        uint8_t *       secret;
        size_t          secret_len;
        size_t          ct_len;
        int             ret;

        ctx = EVP_PKEY_CTX_new(pub, NULL);
        if (ctx == NULL)
                goto fail_ctx;

        ret = EVP_PKEY_encapsulate_init(ctx, NULL);
        if (ret != 1)
                goto fail_encap;

        /* Get required lengths */
        ret = EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &secret_len);
        if (ret != 1 || ct_len > CRYPT_KEY_BUFSZ)
                goto fail_encap;

        /* Allocate buffer for secret */
        secret = OPENSSL_malloc(secret_len);
        if (secret == NULL)
                goto fail_encap;

        /* Perform encapsulation */
        ret = EVP_PKEY_encapsulate(ctx, ct, &ct_len, secret, &secret_len);
        if (ret != 1)
                goto fail_secret;

        ki.secret.len  = secret_len;
        ki.secret.data = secret;
        ki.nid          = kdf;
        ki.info.len    = strlen(HKDF_INFO_ENCAP);
        ki.info.data   = (uint8_t *) HKDF_INFO_ENCAP;
        ki.key.len     = SYMMKEYSZ;
        ki.key.data    = s;
        ki.salt.len    = HKDF_SALT_LEN;
        ki.salt.data   = salt;

        /* Derive symmetric key from shared secret using HKDF */
        ret = derive_key_hkdf(&ki);

        OPENSSL_clear_free(secret, secret_len);
        EVP_PKEY_CTX_free(ctx);

        if (ret != 0)
                return -ECRYPT;

        return (ssize_t) ct_len;

 fail_secret:
        OPENSSL_clear_free(secret, secret_len);
 fail_encap:
        EVP_PKEY_CTX_free(ctx);
 fail_ctx:
        return -ECRYPT;
}

/* ML-KEM encapsulation - DER-encoded public key */
ssize_t openssl_kem_encap(buffer_t   pk,
                          uint8_t *  ct,
                          int        kdf,
                          uint8_t *  s)
{
        EVP_PKEY * pub;
        uint8_t *  pos;
        uint8_t    salt[HKDF_SALT_LEN];
        buffer_t   salt_b;
        ssize_t    ret;

        assert(pk.data != NULL);
        assert(ct != NULL);
        assert(s != NULL);

        salt_b.len  = HKDF_SALT_LEN;
        salt_b.data = salt;

        if (derive_salt_from_pk_bytes(pk, salt_b) < 0)
                goto fail_salt;

        pos = pk.data;
        pub = d2i_PUBKEY(NULL, (const uint8_t **) &pos, (long) pk.len);
        if (pub == NULL)
                goto fail_salt;

        ret = __openssl_kem_encap(pub, salt, ct, kdf, s);

        EVP_PKEY_free(pub);

        return ret;
 fail_salt:
        return -ECRYPT;
}

/* Hybrid KEM encapsulation: NID-tagged raw-encoded public key */
ssize_t openssl_kem_encap_raw(const char * algo,
                              buffer_t     pk,
                              uint8_t *    ct,
                              int          kdf,
                              uint8_t *    s)
{
        EVP_PKEY * pub;
        uint8_t    salt[HKDF_SALT_LEN];
        buffer_t   salt_b;
        ssize_t    ret;

        assert(algo != NULL);
        assert(pk.data != NULL);
        assert(ct != NULL);
        assert(s != NULL);

        salt_b.len  = HKDF_SALT_LEN;
        salt_b.data = salt;

        if (derive_salt_from_pk_bytes(pk, salt_b) < 0)
                goto fail_salt;

        pub = EVP_PKEY_new_raw_public_key_ex(NULL, algo, NULL,
                                             pk.data, pk.len);
        if (pub == NULL)
                goto fail_salt;

        ret = __openssl_kem_encap(pub, salt, ct, kdf, s);

        EVP_PKEY_free(pub);

        return ret;
 fail_salt:
        return -ECRYPT;
}

/* KEM decapsulation - used by party that generated the keypair */
int openssl_kem_decap(EVP_PKEY * priv,
                      buffer_t   ct,
                      int        kdf,
                      uint8_t *  s)
{
        EVP_PKEY_CTX *  ctx;
        struct kdf_info ki;
        buffer_t        pk;
        uint8_t *       secret;
        size_t          secret_len;
        int             ret;
        uint8_t         salt[HKDF_SALT_LEN];
        buffer_t        salt_b;

        /* Extract public key bytes from private key */
        if (get_pk_bytes_from_key(priv, &pk) < 0)
                goto fail_pk;

        salt_b.len  = HKDF_SALT_LEN;
        salt_b.data = salt;

        if (derive_salt_from_pk_bytes(pk, salt_b) < 0)
                goto fail_salt;

        ctx = EVP_PKEY_CTX_new(priv, NULL);
        if (ctx == NULL)
                goto fail_salt;

        ret = EVP_PKEY_decapsulate_init(ctx, NULL);
        if (ret != 1)
                goto fail_ctx;

        /* Get required secret length */
        ret = EVP_PKEY_decapsulate(ctx, NULL, &secret_len, ct.data, ct.len);
        if (ret != 1)
                goto fail_ctx;

        /* Allocate buffer for secret */
        secret = OPENSSL_malloc(secret_len);
        if (secret == NULL)
                goto fail_ctx;

        /* Perform decapsulation */
        ret = EVP_PKEY_decapsulate(ctx, secret, &secret_len, ct.data, ct.len);
        if (ret != 1)
                goto fail_secret;

        ki.secret.len  = secret_len;
        ki.secret.data = secret;
        ki.nid          = kdf;
        ki.info.len    = strlen(HKDF_INFO_ENCAP);
        ki.info.data   = (uint8_t *) HKDF_INFO_ENCAP;
        ki.key.len     = SYMMKEYSZ;
        ki.key.data    = s;
        ki.salt.len    = HKDF_SALT_LEN;
        ki.salt.data   = salt;

        /* Derive symmetric key from shared secret using HKDF */
        ret = derive_key_hkdf(&ki);

        OPENSSL_clear_free(secret, secret_len);
        EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(pk.data);

        if (ret != 0)
                return ret;

        return 0;

 fail_secret:
        OPENSSL_clear_free(secret, secret_len);
 fail_ctx:
        EVP_PKEY_CTX_free(ctx);
 fail_salt:
        OPENSSL_free(pk.data);
 fail_pk:
        return -ECRYPT;
}

void openssl_pkp_destroy(EVP_PKEY * pkp)
{
        EVP_PKEY_free(pkp);
}

static int openssl_get_curve(EVP_PKEY * pub,
                             char *     algo)
{
        int    ret;
        size_t len = KEX_ALGO_BUFSZ;

        ret = EVP_PKEY_get_utf8_string_param(pub, "group", algo, len, &len);

        return ret == 1 ? 0 : -ECRYPT;
}

int openssl_get_algo_from_pk_der(buffer_t pk,
                                 char *   algo)
{
        uint8_t *  pos;
        EVP_PKEY * pub;
        char *     type_str;

        assert(pk.data != NULL);
        assert(algo != NULL);

        pos = pk.data;
        pub = d2i_PUBKEY(NULL, (const uint8_t **) &pos, (long) pk.len);
        if (pub == NULL)
                goto fail_decode;

        type_str = (char *) EVP_PKEY_get0_type_name(pub);
        if (type_str == NULL)
                goto fail_pub;

        strcpy(algo, type_str);

        if (IS_EC_GROUP(algo) || IS_DH_GROUP(algo)) {
                if (openssl_get_curve(pub, algo) < 0)
                        goto fail_pub;
        }

        EVP_PKEY_free(pub);
        return 0;

 fail_pub:
        EVP_PKEY_free(pub);
 fail_decode:
        return -ECRYPT;
}

int openssl_dhe_derive(EVP_PKEY * pkp,
                       buffer_t   pk,
                       int        kdf,
                       uint8_t *  s)
{
        uint8_t *    pos;
        EVP_PKEY *   pub;
        const char * name;

        assert(pkp != NULL);
        assert(pk.data != NULL);
        assert(s != NULL);

        /* X.509 DER decoding for DHE */
        pos = pk.data; /* d2i_PUBKEY increments pos, don't use key ptr! */
        pub = d2i_PUBKEY(NULL, (const uint8_t **) &pos, (long) pk.len);
        if (pub == NULL)
                goto fail_decode;

        /* A peer key of another type must not reach the derivation */
        name = EVP_PKEY_get0_type_name(pkp);
        if (name == NULL || EVP_PKEY_is_a(pub, name) != 1)
                goto fail_derive;

        if (__openssl_dhe_derive(pkp, pub, pk, kdf, s) < 0)
                goto fail_derive;

        EVP_PKEY_free(pub);

        return 0;
 fail_derive:
        EVP_PKEY_free(pub);
 fail_decode:
        return -ECRYPT;
}

/* Set up a fresh AEAD cipher ctx for nid: reject non-AEAD / oversized IV. */
static int ossl_cipher_ctx_init(struct ossl_crypt_ctx * ctx,
                                int                     nid)
{
        ctx->cipher = EVP_get_cipherbynid(nid);
        if (ctx->cipher == NULL)
                return -1;

        /* IV must fit the NONCESZ nonce buffer. */
        if (EVP_CIPHER_get_iv_length(ctx->cipher) > NONCESZ)
                return -1;

        /* Authenticated encryption is mandatory; reject non-AEAD ciphers. */
        if ((EVP_CIPHER_flags(ctx->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) == 0)
                return -1;

        ctx->tagsz = AEAD_TAG_LEN;

        return 0;
}

/* One-shot AEAD seal over an explicit key/nonce (no keyrot). out = ct ‖ tag. */
int openssl_oneshot_seal(int             nid,
                         const uint8_t * key,
                         const uint8_t * nonce,
                         buffer_t        aad,
                         buffer_t        in,
                         buffer_t *      out)
{
        struct ossl_crypt_ctx ctx;
        int                   out_sz;

        assert(key != NULL);
        assert(nonce != NULL);
        assert(out != NULL);

        memset(&ctx, 0, sizeof(ctx));

        if (ossl_cipher_ctx_init(&ctx, nid) < 0)
                goto fail_cipher;

        out->data = malloc(in.len + EVP_MAX_BLOCK_LENGTH + ctx.tagsz);
        if (out->data == NULL)
                goto fail_cipher;

        out_sz = openssl_seal(&ctx, key, nonce, aad, in,
                              out->data, out->data + in.len);
        if (out_sz < 0)
                goto fail_seal;

        out->len = (size_t) out_sz + ctx.tagsz;

        return 0;

 fail_seal:
        free(out->data);
 fail_cipher:
        clrbuf(*out);
        return -ECRYPT;
}

/* One-shot AEAD open; in = ct ‖ tag, verifies aad and tag. */
int openssl_oneshot_open(int             nid,
                         const uint8_t * key,
                         const uint8_t * nonce,
                         buffer_t        aad,
                         buffer_t        in,
                         buffer_t *      out)
{
        struct ossl_crypt_ctx ctx;
        buffer_t              ct;
        const uint8_t *       tag;
        int                   in_sz;

        assert(key != NULL);
        assert(nonce != NULL);
        assert(out != NULL);

        memset(&ctx, 0, sizeof(ctx));

        if (ossl_cipher_ctx_init(&ctx, nid) < 0)
                goto fail_cipher;

        if (in.len < (size_t) ctx.tagsz)
                goto fail_cipher;

        in_sz = (int) in.len - ctx.tagsz;

        out->data = malloc((size_t) in_sz + EVP_MAX_BLOCK_LENGTH);
        if (out->data == NULL)
                goto fail_cipher;

        ct.data = in.data;
        ct.len  = (size_t) in_sz;
        tag     = in.data + in_sz;

        if (openssl_open(&ctx, key, nonce, aad, ct, tag, out) < 0)
                goto fail_open;

        return 0;

 fail_open:
        free(out->data);
 fail_cipher:
        clrbuf(*out);
        return -ECRYPT;
}

struct ossl_crypt_ctx * openssl_crypt_create_ctx(struct crypt_sk * sk)
{
        struct ossl_crypt_ctx * ctx;

        assert(sk != NULL);
        assert(sk->key != NULL);

        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL)
                goto fail_malloc;

        memset(ctx, 0, sizeof(*ctx));

        if (ossl_cipher_ctx_init(ctx, sk->nid) < 0)
                goto fail_cipher;

        return ctx;

 fail_cipher:
        free(ctx);
 fail_malloc:
        return NULL;
}

void openssl_crypt_destroy_ctx(struct ossl_crypt_ctx * ctx)
{
        if (ctx == NULL)
                return;

        free(ctx);
}

int openssl_crypt_get_tagsz(struct ossl_crypt_ctx * ctx)
{
        assert(ctx != NULL);

        return ctx->tagsz;
}

/* AUTHENTICATION */

int openssl_load_crt_file(const char * path,
                          void **      crt)
{
        FILE * fp;
        X509 * xcrt;

        fp = fopen(path, "r");
        if (fp == NULL)
                goto fail_file;

        pthread_cleanup_push(__cleanup_fclose, fp);

        xcrt = PEM_read_X509(fp, NULL, NULL, NULL);

        pthread_cleanup_pop(false);

        if (xcrt == NULL)
                goto fail_crt;

        fclose(fp);

        *crt = (void *) xcrt;

        return 0;
 fail_crt:
        fclose(fp);
 fail_file:
        *crt = NULL;
        return -1;
}

static void * rd_crt_bio(BIO * bio)
{
        return PEM_read_bio_X509(bio, NULL, NULL, NULL);
}

static void * rd_privkey_bio(BIO * bio)
{
        return PEM_read_bio_PrivateKey(bio, NULL, NULL, "");
}

static void * rd_pubkey_bio(BIO * bio)
{
        return PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
}

/* Decode a PEM object from an in-memory string via rd. */
static int load_pem_str(const char * str,
                        void *    (* rd)(BIO *),
                        void **      out)
{
        BIO *  bio;
        void * obj;

        bio = BIO_new(BIO_s_mem());
        if (bio == NULL)
                goto fail_bio;

        if (BIO_write(bio, str, strlen(str)) < 0)
                goto fail_obj;

        obj = rd(bio);
        if (obj == NULL)
                goto fail_obj;

        BIO_free(bio);

        *out = obj;

        return 0;
 fail_obj:
        BIO_free(bio);
 fail_bio:
        *out = NULL;
        return -1;
}

int openssl_load_crt_str(const char * str,
                         void **      crt)
{
        return load_pem_str(str, rd_crt_bio, crt);
}

int openssl_load_crt_der(buffer_t buf,
                         void **  crt)
{
        const uint8_t * p;
        X509 *          xcrt;

        assert(crt != NULL);

        p = buf.data;

        xcrt = d2i_X509(NULL, &p, buf.len);
        if (xcrt == NULL)
                goto fail_crt;

        *crt = (void *) xcrt;

        return 0;
 fail_crt:
        *crt = NULL;
        return -1;
}

int openssl_get_pubkey_crt(void *  crt,
                           void ** key)
{
        EVP_PKEY * pk;
        X509 *     xcrt;

        assert(crt != NULL);
        assert(key != NULL);

        xcrt = (X509 *) crt;

        pk = X509_get_pubkey(xcrt);
        if (pk == NULL)
                goto fail_key;

        *key = (void *) pk;

        return 0;
 fail_key:
        return -1;
}

void openssl_free_crt(void * crt)
{
        X509_free((X509 *) crt);
}

int openssl_load_privkey_file(const char * path,
                              void **      key)
{
        FILE *     fp;
        EVP_PKEY * pkey;

        fp = fopen(path, "r");
        if (fp == NULL)
                goto fail_file;

        pthread_cleanup_push(__cleanup_fclose, fp);

        pkey = PEM_read_PrivateKey(fp, NULL, NULL, "");

        pthread_cleanup_pop(false);

        if (pkey == NULL)
                goto fail_key;

        fclose(fp);

        *key = (void *) pkey;

        return 0;
 fail_key:
        fclose(fp);
 fail_file:
        *key = NULL;
        return -1;
}

int openssl_load_privkey_str(const char * str,
                             void **      key)
{
        return load_pem_str(str, rd_privkey_bio, key);
}

int openssl_load_pubkey_file(const char * path,
                             void **      key)
{
        FILE *     fp;
        EVP_PKEY * pkey;

        fp = fopen(path, "r");
        if (fp == NULL)
                goto fail_file;

        pthread_cleanup_push(__cleanup_fclose, fp);

        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

        pthread_cleanup_pop(false);

        if (pkey == NULL)
                goto fail_key;

        fclose(fp);

        *key = (void *) pkey;

        return 0;
 fail_key:
        fclose(fp);
 fail_file:
        *key = NULL;
        return -1;
}

int openssl_load_pubkey_file_to_der(const char * path,
                                    buffer_t *   buf)
{
        FILE *     fp;
        EVP_PKEY * pkey;
        int        ret;

        assert(path != NULL);
        assert(buf != NULL);

        memset(buf, 0, sizeof(*buf));

        fp = fopen(path, "r");
        if (fp == NULL)
                goto fail_file;

        pthread_cleanup_push(__cleanup_fclose, fp);

        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

        pthread_cleanup_pop(false);

        if (pkey == NULL)
                goto fail_key;

        /* Extract public key bytes in DER format */
        ret = get_pk_bytes_from_key(pkey, buf);
        if (ret < 0)
                goto fail_extract;

        EVP_PKEY_free(pkey);

        fclose(fp);

        return 0;

 fail_extract:
        EVP_PKEY_free(pkey);
 fail_key:
        fclose(fp);
 fail_file:
        clrbuf(*buf);
        return -1;
}

int openssl_load_pubkey_str(const char * str,
                            void **      key)
{
        return load_pem_str(str, rd_pubkey_bio, key);
}

int openssl_load_pubkey_raw_file(const char * path,
                                 const char * algo,
                                 buffer_t *   buf)
{
        FILE *     fp;
        uint8_t    tmp_buf[CRYPT_KEY_BUFSZ];
        size_t     bytes_read;
        EVP_PKEY * chk;

        assert(path != NULL);
        assert(algo != NULL);
        assert(buf != NULL);

        fp = fopen(path, "rb");
        if (fp == NULL)
                goto fail_file;

        pthread_cleanup_push(__cleanup_fclose, fp);

        bytes_read = fread(tmp_buf, 1, CRYPT_KEY_BUFSZ, fp);

        pthread_cleanup_pop(false);

        /* A full buffer means the file was truncated */
        if (bytes_read == 0 || bytes_read == CRYPT_KEY_BUFSZ)
                goto fail_read;

        /* Trial import: reject bad keys at load time */
        chk = EVP_PKEY_new_raw_public_key_ex(NULL, algo, NULL,
                                             tmp_buf, bytes_read);

        if (chk == NULL)
                goto fail_read;

        EVP_PKEY_free(chk);

        buf->data = malloc(bytes_read);
        if (buf->data == NULL)
                goto fail_malloc;

        memcpy(buf->data, tmp_buf, bytes_read);
        buf->len = bytes_read;

        fclose(fp);
        return 0;

 fail_malloc:
 fail_read:
        fclose(fp);
 fail_file:
        clrbuf(*buf);
        return -1;
}

/* Wipe the raw-key staging buffer if a cancel aborts the read. */
static void __cleanse_key_buf(void * o)
{
        OPENSSL_cleanse(o, CRYPT_KEY_BUFSZ);
}

int openssl_load_privkey_raw_file(const char * path,
                                  const char * algo,
                                  void **      key)
{
        FILE *     fp;
        uint8_t    tmp_buf[CRYPT_KEY_BUFSZ];
        size_t     bytes_read;
        EVP_PKEY * pkey;

        assert(path != NULL);
        assert(algo != NULL);
        assert(key != NULL);

        fp = fopen(path, "rb");
        if (fp == NULL)
                goto fail_file;

        pthread_cleanup_push(__cleanup_fclose, fp);
        pthread_cleanup_push(__cleanse_key_buf, tmp_buf);

        bytes_read = fread(tmp_buf, 1, sizeof(tmp_buf), fp);

        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);

        if (bytes_read == 0)
                goto fail_read;

        pkey = EVP_PKEY_new_raw_private_key_ex(NULL, algo, NULL,
                                               tmp_buf, bytes_read);
        /* Clear sensitive data from stack */
        OPENSSL_cleanse(tmp_buf, bytes_read);

        if (pkey == NULL)
                goto fail_read;

        fclose(fp);

        *key = (void *) pkey;

        return 0;

 fail_read:
        fclose(fp);
 fail_file:
        *key = NULL;
        return -1;
}

int openssl_cmp_key(const EVP_PKEY * key1,
                    const EVP_PKEY * key2)
{
        assert(key1 != NULL);
        assert(key2 != NULL);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        return EVP_PKEY_eq(key1, key2) == 1 ? 0 : -1;
#else
        return EVP_PKEY_cmp(key1, key2) == 1 ? 0 : -1;
#endif
}

void openssl_free_key(EVP_PKEY * key)
{
        EVP_PKEY_free(key);
}

/* ASN1_STRING_length is deprecated in OpenSSL 4.1, and returns size_t */
static int ossl_asn1_str_len(const ASN1_STRING * val)
{
#ifdef HAVE_OPENSSL_4_1
        size_t len;

        len = ASN1_STRING_get_length(val);

        return len > INT_MAX ? -1 : (int) len;
#else
        return ASN1_STRING_length(val);
#endif
}

int openssl_check_crt_name(void *       crt,
                           const char * name)
{
        const unsigned char * cn;
        const ASN1_STRING *   val;
        const X509_NAME *     nm;
        int                   idx;
        int                   len;

        nm = X509_get_subject_name((X509 *) crt);
        if (nm == NULL)
                return -1;

        idx = X509_NAME_get_index_by_NID(nm, NID_commonName, -1);
        if (idx < 0)
                return -1;

        val = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(nm, idx));
        cn  = ASN1_STRING_get0_data(val);
        len = ossl_asn1_str_len(val);

        if (len < 0 || (size_t) len != strlen(name))
                return -1;

        if (memchr(cn, '\0', (size_t) len) != NULL)
                return -1;

        if (memcmp(cn, name, (size_t) len) != 0)
                return -1;

        return 0;
}

int openssl_get_crt_name(void * crt,
                         char * name)
{
        const unsigned char * cn;
        const ASN1_STRING *   val;
        const X509_NAME *     nm;
        int                   idx;
        int                   len;

        nm = X509_get_subject_name((X509 *) crt);
        if (nm == NULL)
                return -1;

        idx = X509_NAME_get_index_by_NID(nm, NID_commonName, -1);
        if (idx < 0)
                return -1;

        val = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(nm, idx));
        cn  = ASN1_STRING_get0_data(val);
        len = ossl_asn1_str_len(val);

        if (len < 0)
                return -1;

        if ((size_t) len > NAME_SIZE)
                return -ENAME;

        /* Reject an embedded NUL that would truncate the parsed name. */
        if (memchr(cn, '\0', (size_t) len) != NULL)
                return -1;

        memcpy(name, cn, (size_t) len);
        name[len] = '\0';

        return 0;
}

int openssl_crt_str(const void * crt,
                    char *       str)
{
        BIO *   bio;
        X509 *  xcrt;
        char *  p;
        ssize_t len;

        xcrt = (X509 *) crt;

        bio = BIO_new(BIO_s_mem());
        if (bio == NULL)
                goto fail_bio;

        X509_print(bio, xcrt);

        len = (ssize_t) BIO_get_mem_data(bio, &p);
        if (len <= 0 || p == NULL)
                goto fail_p;

        memcpy(str, p, len);
        str[len] = '\0';

        BIO_free(bio);

        return 0;
 fail_p:
        BIO_free(bio);
 fail_bio:
        return -1;
}

int openssl_crt_der(const void * crt,
                    buffer_t *   buf)
{
        uint8_t * p;
        int       len;

        assert(crt != NULL);
        assert(buf != NULL);

        /* Get the size by encoding to NULL */
        len = i2d_X509((X509 *) crt, NULL);
        if (len < 0)
                goto fail_len;

        buf->data = malloc((size_t) len);
        if (buf->data == NULL)
                goto fail_malloc;

        p = buf->data; /* i2d_X509 increments p */
        i2d_X509((X509 *) crt, &p);
        buf->len = (size_t) len;

        return 0;

 fail_malloc:
 fail_len:
        clrbuf(*buf);
        return -1;
}

void * openssl_auth_create_store(void)
{
        return X509_STORE_new();
}

void openssl_auth_destroy_store(void * ctx)
{
        X509_STORE_free((X509_STORE *) ctx);
}

int openssl_auth_add_crt_to_store(void * store,
                                  void * crt)
{
        int ret;

        ret = X509_STORE_add_cert((X509_STORE *) store, (X509 *) crt);

        return ret == 1 ? 0 : -1;
}

void * openssl_auth_create_chain(void)
{
        return sk_X509_new_null();
}

void openssl_auth_destroy_chain(void * chain)
{
        sk_X509_pop_free((STACK_OF(X509) *) chain, X509_free);
}

int openssl_auth_add_crt_to_chain(void * chain,
                                  void * crt)
{
        if (X509_up_ref((X509 *) crt) != 1)
                goto fail_ref;

        if (sk_X509_push((STACK_OF(X509) *) chain, (X509 *) crt) == 0)
                goto fail_push;

        return 0;
 fail_push:
        X509_free((X509 *) crt);
 fail_ref:
        return -1;
}

int openssl_verify_crt_pin(void * store,
                           void * untrusted,
                           void * crt,
                           void * pin)
{
        X509_STORE_CTX * ctx;
        X509_STORE *     _store;
        X509*            _crt;
        STACK_OF(X509) * chain;
        int              i;
        int              n;
        int              ret;

        _store = (X509_STORE *) store;
        _crt   = (X509 *) crt;

        ctx = X509_STORE_CTX_new();
        if (ctx == NULL)
                goto fail_store_ctx;

        ret = X509_STORE_CTX_init(ctx, _store, _crt,
                                  (STACK_OF(X509) *) untrusted);
        if (ret != 1)
                goto fail_ca;

        ret = X509_verify_cert(ctx);
        if (ret != 1)
                goto fail_ca;

        /* Peer cert only verifies a signature; gate on sig KU, not role. */
        if ((X509_get_key_usage(_crt) & KU_DIGITAL_SIGNATURE) == 0)
                goto fail_ca;

        if (pin != NULL) {
                chain = X509_STORE_CTX_get0_chain(ctx);
                if (chain == NULL)
                        goto fail_ca;
                n = sk_X509_num(chain);
                for (i = 1; i < n; i++) /* Skip the leaf */
                        if (X509_cmp(sk_X509_value(chain, i), pin) == 0)
                                break;
                if (i == n)
                        goto fail_pin;
        }

        X509_STORE_CTX_free(ctx);

        return 0;
 fail_pin:
        X509_STORE_CTX_free(ctx);
        return -ENOENT;
 fail_ca:
        X509_STORE_CTX_free(ctx);
 fail_store_ctx:
        return -EAUTH;
}

int openssl_verify_crt(void * store,
                       void * untrusted,
                       void * crt)
{
        return openssl_verify_crt_pin(store, untrusted, crt, NULL);
}

static const EVP_MD * select_md(EVP_PKEY * pkey,
                                int        nid)
{
        if (EVP_PKEY_get_id(pkey) < 0)
                return NULL; /* Provider-based (PQC) */

        if (nid == NID_undef)
                return NULL; /* Classical requires explicit nid */

        return EVP_get_digestbynid(nid);
}

bool openssl_pk_requires_md(const EVP_PKEY * pk)
{
        /* Provider-based (PQC) signatures have an intrinsic digest */
        return EVP_PKEY_get_id(pk) >= 0;
}

int openssl_sign(EVP_PKEY * pkp,
                 int        nid,
                 buffer_t   msg,
                 buffer_t * sig)
{
        EVP_MD_CTX *   mdctx;
        const EVP_MD * md;
        size_t         required;

        assert(pkp != NULL);
        assert(sig != NULL);

        mdctx = EVP_MD_CTX_new();
        if (!mdctx)
                goto fail_ctx;

        md = select_md(pkp, nid);

        if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkp) != 1)
                goto fail_digest;

        /* Get required signature buffer size */
        if (EVP_DigestSign(mdctx, NULL, &required, msg.data, msg.len) != 1)
                goto fail_digest;

        sig->data = malloc(required);
        if (sig->data == NULL)
                goto fail_digest;

        if (EVP_DigestSign(mdctx, sig->data, &required, msg.data, msg.len) != 1)
                goto fail_sign;

        sig->len = required;

        EVP_MD_CTX_free(mdctx);

        return 0;
 fail_sign:
        freebuf(*sig);
 fail_digest:
        EVP_MD_CTX_free(mdctx);
 fail_ctx:
        clrbuf(*sig);
        return -1;
}

int openssl_verify_sig(EVP_PKEY * pk,
                       int        nid,
                       buffer_t   msg,
                       buffer_t   sig)
{
        EVP_MD_CTX *   mdctx;
        const EVP_MD * md;
        int            ret;

        assert(pk != NULL);

        mdctx = EVP_MD_CTX_new();
        if (!mdctx)
                goto fail_ctx;

        md = select_md(pk, nid);

        if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pk) != 1)
                goto fail_digest;

        ret = EVP_DigestVerify(mdctx, sig.data, sig.len, msg.data, msg.len);
        if (ret != 1)
                goto fail_digest;

        EVP_MD_CTX_free(mdctx);

        return 0;
 fail_digest:
        EVP_MD_CTX_free(mdctx);
 fail_ctx:
        clrbuf(sig);
        return -1;
}

ssize_t openssl_md_digest(int       nid,
                          buffer_t  in,
                          uint8_t * out)
{
        const EVP_MD * md;
        unsigned int   len;

        assert(in.data != NULL);
        assert(out != NULL);

        md = EVP_get_digestbynid(nid);
        if (md == NULL)
                return -1;

        if (EVP_Digest(in.data, in.len, out, &len, md, NULL) != 1)
                return -1;

        return (ssize_t) len;
}

ssize_t openssl_md_len(int nid)
{
        const EVP_MD * md;

        md = EVP_get_digestbynid(nid);
        if (md == NULL)
                return -1;

        return (ssize_t) EVP_MD_get_size(md);
}

int openssl_secure_malloc_init(size_t max,
                               size_t guard)
{
        return CRYPTO_secure_malloc_init(max, guard) == 1 ? 0 : -1;
}

void openssl_secure_malloc_fini(void)
{
        CRYPTO_secure_malloc_done();
}

void * openssl_secure_malloc(size_t size)
{
        return OPENSSL_secure_malloc(size);
}

void openssl_secure_free(void * ptr,
                         size_t size)
{
        OPENSSL_secure_clear_free(ptr, size);
}

void openssl_secure_clear(void * ptr,
                          size_t size)
{
        OPENSSL_cleanse(ptr, size);
}

void openssl_cleanup(void)
{
        OPENSSL_cleanup();
}
