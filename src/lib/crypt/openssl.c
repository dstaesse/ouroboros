/*
 * Ouroboros - Copyright (C) 2016 - 2024
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
#include <ouroboros/random.h>
#include <ouroboros/utils.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <assert.h>
#include <stdio.h>

#define IS_EC_GROUP(str) (strcmp(str, "EC") == 0)
#define IS_DH_GROUP(str) (strcmp(str, "DH") == 0)

#define HKDF_INFO_DHE   "o7s-ossl-dhe"
#define HKDF_INFO_ENCAP "o7s-ossl-encap"
#define HKDF_SALT_LEN   32 /* SHA-256 output size */

struct ossl_crypt_ctx {
        EVP_CIPHER_CTX *   evp_ctx;
        const EVP_CIPHER * cipher;
        uint8_t *          key;
        int                ivsz;
        int                tagsz;
};

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
                return "SHA256"; /* fallback to SHA-256 */

        name = EVP_MD_get0_name(md);
        if (name == NULL)
                return "SHA256"; /* fallback to SHA-256 */

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
static int derive_salt_from_pk_bytes(buffer_t   pk,
                                     uint8_t *  salt,
                                     size_t     salt_len)
{
        uint8_t  hash[EVP_MAX_MD_SIZE];
        unsigned hash_len;

        assert(pk.data != NULL);
        assert(salt != NULL);

        if (EVP_Digest(pk.data, pk.len, hash, &hash_len,
                       EVP_sha256(), NULL) != 1)
                goto fail_digest;

        memcpy(salt, hash, salt_len < hash_len ? salt_len : hash_len);

        return 0;
 fail_digest:
        return -ECRYPT;
}

/* Derive salt from two public key byte buffers (DHE) in canonical order */
static int derive_salt_from_pk_bytes_dhe(buffer_t   local,
                                         buffer_t   remote,
                                         uint8_t *  salt,
                                         size_t     salt_len)
{
        uint8_t * concat;
        size_t    concat_len;
        uint8_t   hash[EVP_MAX_MD_SIZE];
        unsigned  hash_len;
        size_t    min_len;
        int       cmp;

        assert(local.data != NULL);
        assert(remote.data != NULL);
        assert(salt != NULL);

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

        memcpy(salt, hash, salt_len < hash_len ? salt_len : hash_len);

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

        /* Derive salt from both public keys */
        if (derive_salt_from_pk_bytes_dhe(local_pk, remote_pk, salt_buf,
                                          HKDF_SALT_LEN) < 0)
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
        ki.salt.len    = HKDF_SALT_LEN;
        ki.salt.data   = salt_buf;

        /* Derive symmetric key from shared secret using HKDF */
        ret = derive_key_hkdf(&ki);

        OPENSSL_free(secret);
        EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(local_pk.data);

        if (ret != 0)
                return ret;

        return 0;
 fail_derive:
        OPENSSL_free(secret);
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

/* Determine hybrid KEM algorithm from raw key/ciphertext length */
static const char * __openssl_hybrid_algo_from_len(size_t len)
{
        switch(len) {
        case X25519MLKEM768_PKSZ:
                return "X25519MLKEM768";
        case X25519MLKEM768_CTSZ:
                return "X25519MLKEM768";
        case X448MLKEM1024_PKSZ:
                return "X448MLKEM1024";
        default:
                break;
        }

        return NULL;
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

                memcpy(pk, raw.data, raw.len);
                OPENSSL_free(raw.data);

                return (ssize_t) raw.len;
        } else { /* DER encode standard algorithms */
                pos = pk; /* i2d_PUBKEY increments the pointer, don't use pk! */
                len = i2d_PUBKEY(*pkp, &pos);
                if (len < 0)
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
        if (ret != 1 || ct_len > MSGBUFSZ)
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

        OPENSSL_free(secret);
        EVP_PKEY_CTX_free(ctx);

        if (ret != 0)
                return -ECRYPT;

        return (ssize_t) ct_len;

 fail_secret:
        OPENSSL_free(secret);
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
        ssize_t    ret;

        assert(pk.data != NULL);
        assert(ct != NULL);
        assert(s != NULL);

        if (derive_salt_from_pk_bytes(pk, salt, HKDF_SALT_LEN) < 0)
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

/* Hybrid KEM encapsulation: raw-encoded public key */
ssize_t openssl_kem_encap_raw(buffer_t   pk,
                              uint8_t *  ct,
                              int        kdf,
                              uint8_t *  s)
{
        EVP_PKEY *   pub;
        const char * algo;
        uint8_t      salt[HKDF_SALT_LEN];
        ssize_t      ret;

        assert(pk.data != NULL);
        assert(ct != NULL);
        assert(s != NULL);

        if (derive_salt_from_pk_bytes(pk, salt, HKDF_SALT_LEN) < 0)
                goto fail_salt;

        algo = __openssl_hybrid_algo_from_len(pk.len);
        if (algo == NULL)
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

        /* Extract public key bytes from private key */
        if (get_pk_bytes_from_key(priv, &pk) < 0)
                goto fail_pk;

        if (derive_salt_from_pk_bytes(pk, salt, HKDF_SALT_LEN) < 0)
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

        OPENSSL_free(secret);
        EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(pk.data);

        if (ret != 0)
                return ret;

        return 0;

 fail_secret:
        OPENSSL_free(secret);
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

int __openssl_get_curve(EVP_PKEY * pub,
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

        if ((IS_EC_GROUP(algo) || IS_DH_GROUP(algo)) &&
            __openssl_get_curve(pub, algo) < 0)
                goto fail_pub;

        EVP_PKEY_free(pub);
        return 0;

 fail_pub:
        EVP_PKEY_free(pub);
 fail_decode:
        return -ECRYPT;
}

int openssl_get_algo_from_pk_raw(buffer_t pk,
                                 char *   algo)
{
        const char * hybrid_algo;

        assert(pk.data != NULL);
        assert(algo != NULL);

        hybrid_algo = __openssl_hybrid_algo_from_len(pk.len);
        if (hybrid_algo == NULL)
                return -ECRYPT;

        strcpy(algo, hybrid_algo);

        return 0;
}

int openssl_dhe_derive(EVP_PKEY * pkp,
                       buffer_t   pk,
                       int        kdf,
                       uint8_t *  s)
{
        uint8_t *  pos;
        EVP_PKEY * pub;

        assert(pkp != NULL);
        assert(pk.data != NULL);
        assert(s != NULL);

        /* X.509 DER decoding for DHE */
        pos = pk.data; /* d2i_PUBKEY increments pos, don't use key ptr! */
        pub = d2i_PUBKEY(NULL, (const uint8_t **) &pos, (long) pk.len);
        if (pub == NULL)
                goto fail_decode;

        if (__openssl_dhe_derive(pkp, pub, pk, kdf, s) < 0)
                goto fail_derive;

        EVP_PKEY_free(pub);

        return 0;
 fail_derive:
        EVP_PKEY_free(pub);
 fail_decode:
        return -ECRYPT;
}

int openssl_encrypt(struct ossl_crypt_ctx * ctx,
                    buffer_t                in,
                    buffer_t *              out)
{
        uint8_t *  ptr;
        uint8_t *  iv;
        int        in_sz;
        int        out_sz;
        int        tmp_sz;
        int        ret;

        assert(ctx != NULL);

        in_sz = (int) in.len;

        out->data = malloc(in.len + EVP_MAX_BLOCK_LENGTH + \
                           ctx->ivsz + ctx->tagsz);
        if (out->data == NULL)
                goto fail_malloc;

        iv  = out->data;
        ptr = out->data + ctx->ivsz;

        if (random_buffer(iv, ctx->ivsz) < 0)
                goto fail_encrypt;

        EVP_CIPHER_CTX_reset(ctx->evp_ctx);

        ret = EVP_EncryptInit_ex(ctx->evp_ctx, ctx->cipher, NULL, ctx->key, iv);
        if (ret != 1)
                goto fail_encrypt;

        ret = EVP_EncryptUpdate(ctx->evp_ctx, ptr, &tmp_sz, in.data, in_sz);
        if (ret != 1)
                goto fail_encrypt;

        out_sz = tmp_sz;
        ret =  EVP_EncryptFinal_ex(ctx->evp_ctx, ptr + tmp_sz, &tmp_sz);
        if (ret != 1)
                goto fail_encrypt;

        out_sz += tmp_sz;

        /* For AEAD ciphers, get and append the authentication tag */
        if (ctx->tagsz > 0) {
                ret = EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_AEAD_GET_TAG,
                                          ctx->tagsz, ptr + out_sz);
                if (ret != 1)
                        goto fail_encrypt;
                out_sz += ctx->tagsz;
        }

        assert(out_sz >= in_sz);

        out->len = (size_t) out_sz + ctx->ivsz;

        return 0;
 fail_encrypt:
        free(out->data);
 fail_malloc:
        clrbuf(*out);
        return -ECRYPT;
}

int openssl_decrypt(struct ossl_crypt_ctx * ctx,
                    buffer_t                in,
                    buffer_t *              out)
{
        uint8_t *               ptr;
        uint8_t *               iv;
        uint8_t *               input;
        int                     ret;
        int                     out_sz;
        int                     in_sz;
        int                     tmp_sz;

        assert(ctx != NULL);

        in_sz = (int) in.len - ctx->ivsz;
        if (in_sz < ctx->tagsz)
                return -ECRYPT;

        in_sz -= ctx->tagsz;

        out->data = malloc(in_sz + EVP_MAX_BLOCK_LENGTH);
        if (out->data == NULL)
                goto fail_malloc;

        iv    = in.data;
        ptr   = out->data;
        input = in.data + ctx->ivsz;

        EVP_CIPHER_CTX_reset(ctx->evp_ctx);

        ret = EVP_DecryptInit_ex(ctx->evp_ctx, ctx->cipher, NULL, ctx->key, iv);
        if (ret != 1)
                goto fail_decrypt;

        /* For AEAD ciphers, set the expected authentication tag */
        if (ctx->tagsz > 0) {
                uint8_t * tag = input + in_sz;
                ret = EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_AEAD_SET_TAG,
                                          ctx->tagsz, tag);
                if (ret != 1)
                        goto fail_decrypt;
        }

        ret = EVP_DecryptUpdate(ctx->evp_ctx, ptr, &tmp_sz, input, in_sz);
        if (ret != 1)
                goto fail_decrypt;

        out_sz = tmp_sz;
        ret = EVP_DecryptFinal_ex(ctx->evp_ctx, ptr + tmp_sz, &tmp_sz);
        if (ret != 1)
                goto fail_decrypt;

        out_sz += tmp_sz;

        assert(out_sz <= in_sz);

        out->len = (size_t) out_sz;

        return 0;
 fail_decrypt:
        free(out->data);
 fail_malloc:
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

        ctx->key = OPENSSL_secure_malloc(SYMMKEYSZ);
        if (ctx->key == NULL)
                goto fail_key;

        memcpy(ctx->key, sk->key, SYMMKEYSZ);

        ctx->cipher = EVP_get_cipherbynid(sk->nid);
        if (ctx->cipher == NULL)
                goto fail_cipher;

        ctx->ivsz = EVP_CIPHER_iv_length(ctx->cipher);

        /* Set tag size for AEAD ciphers (GCM, CCM, OCB, ChaCha20-Poly1305) */
        if (EVP_CIPHER_flags(ctx->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER)
                ctx->tagsz = 16;  /* Standard AEAD tag length (128 bits) */

        ctx->evp_ctx = EVP_CIPHER_CTX_new();
        if (ctx->evp_ctx == NULL)
                goto fail_cipher;

        return ctx;

 fail_cipher:
        OPENSSL_secure_clear_free(ctx->key, SYMMKEYSZ);
 fail_key:
        free(ctx);
 fail_malloc:
        return NULL;
}

void openssl_crypt_destroy_ctx(struct ossl_crypt_ctx * ctx)
{
        if (ctx == NULL)
                return;

        if (ctx->key != NULL)
                OPENSSL_secure_clear_free(ctx->key, SYMMKEYSZ);

        EVP_CIPHER_CTX_free(ctx->evp_ctx);
        free(ctx);
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

        xcrt = PEM_read_X509(fp, NULL, NULL, NULL);
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

int openssl_load_crt_str(const char * str,
                         void **      crt)
{
        BIO *  bio;
        X509 * xcrt;

        bio = BIO_new(BIO_s_mem());
        if (bio == NULL)
                goto fail_bio;

        if (BIO_write(bio, str, strlen(str)) < 0)
                goto fail_crt;

        xcrt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (xcrt == NULL)
                goto fail_crt;

        BIO_free(bio);

        *crt = (void *) xcrt;

        return 0;
 fail_crt:
        BIO_free(bio);
 fail_bio:
        *crt = NULL;
        return -1;
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
        unsigned long err;
        char       errbuf[256];

        fp = fopen(path, "r");
        if (fp == NULL) {
                fprintf(stderr, "Failed to open %s\n", path);
                goto fail_file;
        }

        pkey = PEM_read_PrivateKey(fp, NULL, NULL, "");
        if (pkey == NULL) {
                err = ERR_get_error();
                ERR_error_string_n(err, errbuf, sizeof(errbuf));
                fprintf(stderr,
                        "OpenSSL error loading privkey from %s: %s\n",
                        path, errbuf);
                goto fail_key;
        }

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
        BIO *      bio;
        EVP_PKEY * pkey;

        bio = BIO_new(BIO_s_mem());
        if (bio == NULL)
                goto fail_bio;

        if (BIO_write(bio, str, strlen(str)) < 0)
                goto fail_key;

        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (pkey == NULL)
                goto fail_key;

        BIO_free(bio);

        *key = (void *) pkey;

        return 0;
 fail_key:
        BIO_free(bio);
 fail_bio:
        *key = NULL;
        return -1;
}

int openssl_load_pubkey_file(const char * path,
                             void **      key)
{
        FILE *     fp;
        EVP_PKEY * pkey;

        fp = fopen(path, "r");
        if (fp == NULL)
                goto fail_file;

        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
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

        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        if (pkey == NULL)
                goto fail_key;

        fclose(fp);

        /* Extract public key bytes in DER format */
        ret = get_pk_bytes_from_key(pkey, buf);

        EVP_PKEY_free(pkey);

        if (ret < 0)
                goto fail_extract;

        return 0;

 fail_extract:
        clrbuf(*buf);
        return -1;
 fail_key:
        fclose(fp);
 fail_file:
        clrbuf(*buf);
        return -1;
}

int openssl_load_pubkey_str(const char * str,
                            void **      key)
{
        BIO *      bio;
        EVP_PKEY * pkey;

        bio = BIO_new(BIO_s_mem());
        if (bio == NULL)
                goto fail_bio;

        if (BIO_write(bio, str, strlen(str)) < 0)
                goto fail_key;

        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (pkey == NULL)
                goto fail_key;

        BIO_free(bio);

        *key = (void *) pkey;

        return 0;
 fail_key:
        BIO_free(bio);
 fail_bio:
        *key = NULL;
        return -1;
}

int openssl_load_pubkey_raw_file(const char * path,
                                 buffer_t *   buf)
{
        FILE *        fp;
        uint8_t       tmp_buf[MSGBUFSZ];
        size_t        bytes_read;
        const char *  algo;

        assert(path != NULL);
        assert(buf != NULL);

        fp = fopen(path, "rb");
        if (fp == NULL)
                goto fail_file;

        bytes_read = fread(tmp_buf, 1, MSGBUFSZ, fp);
        if (bytes_read == 0)
                goto fail_read;

        /* Validate that this is a known hybrid KEM format */
        algo = __openssl_hybrid_algo_from_len(bytes_read);
        if (algo == NULL)
                goto fail_read;

        buf->data = malloc(bytes_read);
        if (buf->data == NULL)
                goto fail_malloc;

        memcpy(buf->data, tmp_buf, bytes_read);
        buf->len = bytes_read;

        return 0;

 fail_malloc:
 fail_read:
        fclose(fp);
 fail_file:
        clrbuf(*buf);
        return -1;
}

/* Determine hybrid KEM algorithm from raw private key length */
static const char * __openssl_hybrid_algo_from_sk_len(size_t len)
{
        switch(len) {
        case X25519MLKEM768_SKSZ:
                return "X25519MLKEM768";
        case X448MLKEM1024_SKSZ:
                return "X448MLKEM1024";
        default:
                break;
        }

        return NULL;
}

int openssl_load_privkey_raw_file(const char * path,
                                  void **      key)
{
        FILE *       fp;
        uint8_t      tmp_buf[4096];
        size_t       bytes_read;
        const char * algo;
        EVP_PKEY *   pkey;

        assert(path != NULL);
        assert(key != NULL);

        fp = fopen(path, "rb");
        if (fp == NULL)
                goto fail_file;

        bytes_read = fread(tmp_buf, 1, sizeof(tmp_buf), fp);
        fclose(fp);

        if (bytes_read == 0)
                goto fail_read;

        /* Determine algorithm from key size */
        algo = __openssl_hybrid_algo_from_sk_len(bytes_read);
        if (algo == NULL)
                goto fail_read;

        pkey = EVP_PKEY_new_raw_private_key_ex(NULL, algo, NULL,
                                               tmp_buf, bytes_read);
        /* Clear sensitive data from stack */
        OPENSSL_cleanse(tmp_buf, bytes_read);

        if (pkey == NULL)
                goto fail_read;

        *key = (void *) pkey;

        return 0;

 fail_read:
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

int openssl_check_crt_name(void *       crt,
                           const char * name)
{
        char * subj;
        char * cn;
        X509 * xcrt;

        xcrt = (X509 *) crt;

        subj = X509_NAME_oneline(X509_get_subject_name(xcrt), NULL, 0);
        if (subj == NULL)
                goto fail_subj;

        cn = strstr(subj, "CN=");
        if (cn == NULL)
                goto fail_cn;

        if (strcmp(cn + 3, name) != 0)
                goto fail_cn;

        free(subj);

        return 0;
 fail_cn:
        free(subj);
 fail_subj:
        return -1;
}

int openssl_get_crt_name(void * crt,
                         char * name)
{
        char * subj;
        char * cn;
        char * end;
        X509 * xcrt;

        xcrt = (X509 *) crt;

        subj = X509_NAME_oneline(X509_get_subject_name(xcrt), NULL, 0);
        if (subj == NULL)
                goto fail_subj;

        cn = strstr(subj, "CN=");
        if (cn == NULL)
                goto fail_cn;

        cn += 3; /* Skip "CN=" */

        /* Find end of CN (comma or slash for next field) */
        end = strpbrk(cn, ",/");
        if (end != NULL)
                *end = '\0';

        strcpy(name, cn);
        free(subj);

        return 0;
 fail_cn:
        free(subj);
 fail_subj:
        return -1;
}

int openssl_crt_str(const void * crt,
                    char *       str)
{
        BIO *  bio;
        X509 * xcrt;
        char * p;

        xcrt = (X509 *) crt;

        bio = BIO_new(BIO_s_mem());
        if (bio == NULL)
                goto fail_bio;

        X509_print(bio, xcrt);

        BIO_get_mem_data(bio, &p);
        if (p == NULL)
                goto fail_p;

        sprintf(str, "%s", p);

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
        int len;

        assert(crt != NULL);
        assert(buf != NULL);

        len = i2d_X509((X509 *) crt, &buf->data);
        if (len < 0)
                goto fail_der;

        buf->len = (size_t) len;

        return 0;

 fail_der:
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

int openssl_verify_crt(void * store,
                       void * crt)
{
        X509_STORE_CTX * ctx;
        X509_STORE *     _store;
        X509*            _crt;
        int              ret;

        _store = (X509_STORE *) store;
        _crt   = (X509 *) crt;

        ctx = X509_STORE_CTX_new();
        if (ctx == NULL)
                goto fail_store_ctx;

        ret = X509_STORE_CTX_init(ctx, _store, _crt, NULL);
        if (ret != 1)
                goto fail_ca;

        ret = X509_verify_cert(ctx);
        if (ret != 1)
                goto fail_ca;

        X509_STORE_CTX_free(ctx);

        return 0;
 fail_ca:
        X509_STORE_CTX_free(ctx);
 fail_store_ctx:
        return -1;
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

void openssl_secure_free(void * ptr)
{
        OPENSSL_secure_free(ptr);
}
