/*
 * Ouroboros - Copyright (C) 2016 - 2024
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

#include <config.h>

#include <ouroboros/errno.h>
#include <ouroboros/random.h>
#include <ouroboros/crypt.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include "crypt/openssl.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

struct nid_map {
        uint16_t     nid;
        const char * name;
};

static const struct nid_map cipher_nid_map[] = {
        {NID_aes_128_gcm,       "aes-128-gcm"},
        {NID_aes_192_gcm,       "aes-192-gcm"},
        {NID_aes_256_gcm,       "aes-256-gcm"},
        {NID_chacha20_poly1305, "chacha20-poly1305"},
        {NID_aes_128_ctr,       "aes-128-ctr"},
        {NID_aes_192_ctr,       "aes-192-ctr"},
        {NID_aes_256_ctr,       "aes-256-ctr"},
        {NID_undef,             NULL}
};

const uint16_t crypt_supported_nids[] = {
#ifdef HAVE_OPENSSL
        NID_aes_128_gcm,
        NID_aes_192_gcm,
        NID_aes_256_gcm,
        NID_chacha20_poly1305,
        NID_aes_128_ctr,
        NID_aes_192_ctr,
        NID_aes_256_ctr,
#endif
        NID_undef
};

static const struct nid_map kex_nid_map[] = {
        {NID_X9_62_prime256v1, "prime256v1"},
        {NID_secp384r1,        "secp384r1"},
        {NID_secp521r1,        "secp521r1"},
        {NID_X25519,           "X25519"},
        {NID_X448,             "X448"},
        {NID_ffdhe2048,        "ffdhe2048"},
        {NID_ffdhe3072,        "ffdhe3072"},
        {NID_ffdhe4096,        "ffdhe4096"},
        {NID_MLKEM512,         "ML-KEM-512"},
        {NID_MLKEM768,         "ML-KEM-768"},
        {NID_MLKEM1024,        "ML-KEM-1024"},
        {NID_X25519MLKEM768,   "X25519MLKEM768"},
        {NID_X448MLKEM1024,    "X448MLKEM1024"},
        {NID_undef,            NULL}
};

const uint16_t kex_supported_nids[] = {
#ifdef HAVE_OPENSSL
        NID_X9_62_prime256v1,
        NID_secp384r1,
        NID_secp521r1,
        NID_X25519,
        NID_X448,
        NID_ffdhe2048,
        NID_ffdhe3072,
        NID_ffdhe4096,
#ifdef HAVE_OPENSSL_PQC
        NID_MLKEM512,
        NID_MLKEM768,
        NID_MLKEM1024,
        NID_X25519MLKEM768,
        NID_X448MLKEM1024,
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

const uint16_t md_supported_nids[] = {
#ifdef HAVE_OPENSSL
        NID_sha256,
        NID_sha384,
        NID_sha512,
        NID_sha3_256,
        NID_sha3_384,
        NID_sha3_512,
        NID_blake2b512,
        NID_blake2s256,
#endif
        NID_undef
};

struct crypt_ctx {
        void * ctx;  /* Encryption context */
};

struct auth_ctx {
        void * store;
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

        assert(cfg != NULL);
        assert(fp != NULL);

        /* Set defaults */
        SET_KEX_ALGO_NID(cfg, NID_X9_62_prime256v1);
        cfg->x.mode = KEM_MODE_SERVER_ENCAP;
        SET_KEX_KDF_NID(cfg, NID_sha256);
        SET_KEX_CIPHER_NID(cfg, NID_aes_256_gcm);
        SET_KEX_DIGEST_NID(cfg, NID_sha256);

        while (fgets(line, sizeof(line), fp) != NULL) {
                char * trimmed;

                /* Skip comments and empty lines */
                if (line[0] == '#' || line[0] == '\n')
                        continue;

                /* Check for 'none' keyword */
                trimmed = trim_whitespace(line);
                if (strcmp(trimmed, "none") == 0) {
                        memset(cfg, 0, sizeof(*cfg));
                        return 0;
                }

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
                }
        }

        return 0;
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
                /* File doesn't exist - disable encryption */
                CLEAR_KEX_ALGO(cfg);
                return 0;
        }

        ret = parse_sec_config(cfg, fp);

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

ssize_t kex_kem_encap_raw(buffer_t  pk,
                          uint8_t * ct,
                          int       kdf,
                          uint8_t * s)
{
#ifdef HAVE_OPENSSL
        return openssl_kem_encap_raw(pk, ct, kdf, s);
#else
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

int kex_get_algo_from_pk_raw(buffer_t pk,
                             char *   algo)
{
#ifdef HAVE_OPENSSL
        return openssl_get_algo_from_pk_raw(pk, algo);
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

/* Hash length now returned by md_digest() */

int crypt_encrypt(struct crypt_ctx * ctx,
                  buffer_t           in,
                  buffer_t *         out)
{
        assert(ctx != NULL);
        assert(ctx->ctx != NULL);

#ifdef HAVE_OPENSSL
        return openssl_encrypt(ctx->ctx, in, out);
#else
        (void) ctx;
        (void) in;
        (void) out;

        return -ECRYPT;
#endif
}

int crypt_decrypt(struct crypt_ctx * ctx,
                  buffer_t           in,
                  buffer_t *         out)
{
        assert(ctx != NULL);
        assert(ctx->ctx != NULL);

#ifdef HAVE_OPENSSL
        return openssl_decrypt(ctx->ctx, in, out);
#else
        (void) ctx;
        (void) in;
        (void) out;

        return -ECRYPT;
#endif
}

struct crypt_ctx * crypt_create_ctx(struct crypt_sk * sk)
{
        struct crypt_ctx * crypt;

        if (crypt_validate_nid(sk->nid) != 0)
                return NULL;

        crypt = malloc(sizeof(*crypt));
        if (crypt == NULL)
                goto fail_crypt;

        memset(crypt, 0, sizeof(*crypt));

#ifdef HAVE_OPENSSL
        crypt->ctx = openssl_crypt_create_ctx(sk);
        if (crypt->ctx == NULL)
                goto fail_ctx;
#endif
        return crypt;
#ifdef HAVE_OPENSSL
 fail_ctx:
        free(crypt);
#endif
 fail_crypt:
        return NULL;
}

void crypt_destroy_ctx(struct crypt_ctx * crypt)
{
        if (crypt == NULL)
                return;

#ifdef HAVE_OPENSSL
        assert(crypt->ctx != NULL);
        openssl_crypt_destroy_ctx(crypt->ctx);
#else
        assert(crypt->ctx == NULL);
#endif
        free(crypt);
}

int crypt_get_ivsz(struct crypt_ctx * ctx)
{
        if (ctx == NULL)
                return -EINVAL;

#ifdef HAVE_OPENSSL
        assert(ctx->ctx != NULL);
        return openssl_crypt_get_ivsz(ctx->ctx);
#else
        assert(ctx->ctx == NULL);
        return -ENOTSUP;
#endif
}

int crypt_get_tagsz(struct crypt_ctx * ctx)
{
        if (ctx == NULL)
                return -EINVAL;

#ifdef HAVE_OPENSSL
        assert(ctx->ctx != NULL);
        return openssl_crypt_get_tagsz(ctx->ctx);
#else
        assert(ctx->ctx == NULL);
        return -ENOTSUP;
#endif
}

int crypt_load_privkey_file(const char * path,
                            void **      key)
{
        *key = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_privkey_file(path, key);
#else
        (void) path;

        return 0;
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

        return 0;
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

        return 0;
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

        return 0;
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
                               buffer_t *   buf)
{
        assert(buf != NULL);

#ifdef HAVE_OPENSSL
        return openssl_load_pubkey_raw_file(path, buf);
#else
        (void) path;

        buf->data = NULL;
        buf->len  = 0;
        return 0;
#endif
}

int crypt_load_privkey_raw_file(const char * path,
                                void **      key)
{
        *key = NULL;

#ifdef HAVE_OPENSSL
        return openssl_load_privkey_raw_file(path, key);
#else
        (void) path;

        return 0;
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

        return 0;
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
#endif
        return ctx;
#ifdef HAVE_OPENSSL
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

int auth_verify_crt(struct auth_ctx * ctx,
                    void *            crt)
{
#ifdef HAVE_OPENSSL
        return openssl_verify_crt(ctx->store, crt);
#else
        (void) ctx;
        (void) crt;

        return 0;
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

        return 0;
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

int crypt_secure_malloc_init(size_t max)
{
#ifdef HAVE_OPENSSL
        return openssl_secure_malloc_init(max, SECMEM_GUARD);
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
