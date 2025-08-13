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

#include <ouroboros/errno.h>
#include <ouroboros/crypt.h>
#include <ouroboros/hash.h>
#include <ouroboros/random.h>
#include <ouroboros/utils.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <assert.h>

/*
 * Derive the common secret from
 * - your public key pair (kp)
 * - the remote public key (pub).
 * Store it in a preallocated buffer (s).
 */
static int __openssl_ecdh_derive_secret(EVP_PKEY * kp,
                                        EVP_PKEY * pub,
                                        uint8_t *  s)
{
        EVP_PKEY_CTX * ctx;
        int            ret;
        uint8_t *      secret;
        size_t         secret_len;

        ctx = EVP_PKEY_CTX_new(kp, NULL);
        if (ctx == NULL)
                goto fail_new;

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

        /* Hash the secret for use as AES key. */
        mem_hash(HASH_SHA3_256, s, secret, secret_len);

        OPENSSL_free(secret);
        EVP_PKEY_CTX_free(ctx);

        return 0;
 fail_derive:
        OPENSSL_free(secret);
 fail_ctx:
        EVP_PKEY_CTX_free(ctx);
 fail_new:
        return -ECRYPT;
}

static int __openssl_ecdh_gen_key(void ** kp)
{
        EVP_PKEY_CTX * ctx    = NULL;
        EVP_PKEY_CTX * kctx   = NULL;
        EVP_PKEY *     params = NULL;
        int            ret;

        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (ctx == NULL)
                goto fail_new_id;

        ret = EVP_PKEY_paramgen_init(ctx);
        if (ret != 1)
                goto fail_paramgen;

        ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
        if (ret != 1)
                goto fail_paramgen;

        ret = EVP_PKEY_paramgen(ctx, &params);
        if (ret != 1)
                goto fail_paramgen;

        kctx = EVP_PKEY_CTX_new(params, NULL);
        if (kctx == NULL)
                goto fail_keygen_init;

        ret = EVP_PKEY_keygen_init(kctx);
        if (ret != 1)
                goto fail_keygen;

        ret = EVP_PKEY_keygen(kctx, (EVP_PKEY **) kp);
        if (ret != 1)
                goto fail_keygen;

        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_CTX_free(ctx);

        return 0;
 fail_keygen:
        EVP_PKEY_CTX_free(kctx);
 fail_keygen_init:
        EVP_PKEY_free(params);
 fail_paramgen:
        EVP_PKEY_CTX_free(ctx);
 fail_new_id:
        return -ECRYPT;
}

ssize_t openssl_ecdh_pkp_create(void **   pkp,
                                uint8_t * pk)
{
        uint8_t * pos;
        ssize_t   len;

        assert(pkp != NULL);
        assert(*pkp == NULL);
        assert(pk != NULL);

        if (__openssl_ecdh_gen_key(pkp) < 0)
                goto fail_key;

        pos = pk; /* i2d_PUBKEY increments the pointer, don't use pk! */
        len = i2d_PUBKEY(*pkp, &pos);
        if (len < 0)
                goto fail_pubkey;

        return len;
 fail_pubkey:
        EVP_PKEY_free(*pkp);
 fail_key:
        return -ECRYPT;
}

void openssl_ecdh_pkp_destroy(void * pkp)
{
        EVP_PKEY_free((EVP_PKEY *) pkp);
}

int openssl_ecdh_derive(void *    pkp,
                        buffer_t  pk,
                        uint8_t * s)
{
        uint8_t *  pos;
        EVP_PKEY * pub;

        pos = pk.data; /* d2i_PUBKEY increments pos, don't use key ptr! */
        pub = d2i_PUBKEY(NULL, (const uint8_t **) &pos, (long) pk.len);
        if (pub == NULL)
                goto fail_pubkey;

        if (__openssl_ecdh_derive_secret(pkp, pub, s) < 0)
                goto fail_key;

        EVP_PKEY_free(pub);

        return 0;
 fail_pubkey:
        EVP_PKEY_free(pub);
 fail_key:
        return -ECRYPT;
}

/*
 * AES encryption calls. If FRCT is disabled, we should generate a
 * 128-bit random IV and append it to the packet.  If the flow is
 * reliable, we could initialize the context once, and consider the
 * stream a single encrypted message to avoid initializing the
 * encryption context for each packet.
 */

int openssl_encrypt(void *     ctx,
                    uint8_t *  key,
                    buffer_t   in,
                    buffer_t * out)
{
        uint8_t * ptr;
        uint8_t * iv;
        int       in_sz;
        int       out_sz;
        int       tmp_sz;
        int       ret;

        in_sz = (int) in.len;

        out->data = malloc(in.len + EVP_MAX_BLOCK_LENGTH + IVSZ);
        if (out->data == NULL)
                goto fail_malloc;

        iv  = out->data;
        ptr = out->data + IVSZ;

        if (random_buffer(iv, IVSZ) < 0)
                goto fail_iv;

        EVP_CIPHER_CTX_reset(ctx);

        ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        if (ret != 1)
                goto fail_iv;

        ret = EVP_EncryptUpdate(ctx, ptr, &tmp_sz, in.data, in_sz);
        if (ret != 1)
                goto fail_encrypt;

        out_sz = tmp_sz;
        ret =  EVP_EncryptFinal_ex(ctx, ptr + tmp_sz, &tmp_sz);
        if (ret != 1)
                goto fail_encrypt;

        out_sz += tmp_sz;

        EVP_CIPHER_CTX_cleanup(ctx);

        assert(out_sz >= in_sz);

        out->len = (size_t) out_sz + IVSZ;

        return 0;
 fail_encrypt:
        EVP_CIPHER_CTX_cleanup(ctx);
 fail_iv:
        free(out->data);
 fail_malloc:
        clrbuf(*out);
        return -ECRYPT;
}

int openssl_decrypt(void *     ctx,
                    uint8_t *  key,
                    buffer_t   in,
                    buffer_t * out)
{
        uint8_t * ptr;
        uint8_t * iv;
        uint8_t * input;
        int       ret;
        int       out_sz;
        int       in_sz;
        int       tmp_sz;

        in_sz = (int) in.len - IVSZ;
        if (in_sz < 0)
                return -ECRYPT;

        out->data = malloc(in_sz);
        if (out->data == NULL)
                goto fail_malloc;

        iv    = in.data;
        ptr   = out->data;
        input = in.data + IVSZ;

        EVP_CIPHER_CTX_reset(ctx);

        ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        if (ret != 1)
                goto fail_decrypt_init;

        ret = EVP_DecryptUpdate(ctx, ptr, &tmp_sz, input, in_sz);
        if (ret != 1)
                goto fail_decrypt;

        out_sz = tmp_sz;
        ret = EVP_DecryptFinal_ex(ctx, ptr + tmp_sz, &tmp_sz);
        if (ret != 1)
                goto fail_decrypt;

        out_sz += tmp_sz;

        assert(out_sz <= in_sz);

        out->len = (size_t) out_sz;

        return 0;
 fail_decrypt:
        EVP_CIPHER_CTX_cleanup(ctx);
 fail_decrypt_init:
        free(out->data);
 fail_malloc:
        clrbuf(*out);
        return -ECRYPT;
}

void * openssl_crypt_create_ctx(void)
{
        return (void *) EVP_CIPHER_CTX_new();
}

void openssl_crypt_destroy_ctx(void * ctx)
{
         EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *) ctx);
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

        fp = fopen(path, "r");
        if (fp == NULL)
                goto fail_file;

        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
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

int openssl_cmp_key(const void * key1,
                    const void * key2)
{
        EVP_PKEY * pkey1;
        EVP_PKEY * pkey2;

        assert(key1 != NULL);
        assert(key2 != NULL);

        pkey1 = (EVP_PKEY *) key1;
        pkey2 = (EVP_PKEY *) key2;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        return EVP_PKEY_eq(pkey1, pkey2) == 1 ? 0 : -1;
#else
        return EVP_PKEY_cmp(pkey1, pkey2) == 1 ? 0 : -1;
#endif
}

void openssl_free_key(void * key)
{
        EVP_PKEY_free((EVP_PKEY *) key);
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

int openssl_sign(void *     pkp,
                 buffer_t   msg,
                 buffer_t * sig)
{
        EVP_PKEY *   pkey;
        EVP_MD_CTX * mdctx;
        size_t       required;

        assert(pkp != NULL);
        assert(sig != NULL);

        pkey = (EVP_PKEY *) pkp;

        mdctx = EVP_MD_CTX_new();
        if (!mdctx)
                goto fail_ctx;

        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)
                goto fail_digest;

        if (EVP_DigestSignUpdate(mdctx, msg.data, msg.len) != 1)
                goto fail_digest;

        if (EVP_DigestSignFinal(mdctx, NULL, &required) != 1)
                goto fail_digest;

        sig->data = malloc(required);
        if (sig->data == NULL)
                goto fail_digest;

        if (EVP_DigestSignFinal(mdctx, sig->data, &required) != 1)
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

int openssl_verify_sig(void *   pk,
                       buffer_t msg,
                       buffer_t sig)
{
        EVP_PKEY *   pkey;
        EVP_MD_CTX * mdctx;
        int          ret;

        assert(pk != NULL);

        pkey = (EVP_PKEY *) pk;

        mdctx = EVP_MD_CTX_new();
        if (!mdctx)
                goto fail_ctx;

        if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)
                goto fail_digest;

        if (EVP_DigestVerifyUpdate(mdctx, msg.data, msg.len) != 1)
                goto fail_digest;

        ret = EVP_DigestVerifyFinal(mdctx, sig.data, sig.len);
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
