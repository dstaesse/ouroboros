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

#include <ouroboros/crypt.h>
#include <ouroboros/errno.h>
#ifdef HAVE_OPENSSL
 #include "crypt/openssl.h"
#endif /* HAVE_OPENSSL */

#include <assert.h>
#include <string.h>

struct crypt_ctx {
    uint16_t flags;
    void *   ctx;
    uint8_t  key[SYMMKEYSZ];
};

struct auth_ctx {
        void * store;
};

int crypt_dh_pkp_create(void **   pkp,
                        uint8_t * pk)
{
#ifdef HAVE_OPENSSL
        assert(pkp != NULL);
        *pkp = NULL;
        return openssl_ecdh_pkp_create(pkp, pk);
#else
        (void) pkp;
        (void) pk;

        *pkp = NULL;

        return 0;
#endif
}

void crypt_dh_pkp_destroy(void * pkp)
{
        if (pkp == NULL)
                return;
#ifdef HAVE_OPENSSL
        openssl_ecdh_pkp_destroy(pkp);
#else
        (void) pkp;

        return;
#endif
}

int crypt_dh_derive(void *    pkp,
                    buffer_t  pk,
                    uint8_t * s)
{
#ifdef HAVE_OPENSSL
        return openssl_ecdh_derive(pkp, pk, s);
#else
        (void) pkp;
        (void) pk;

        memset(s, 0, SYMMKEYSZ);

        return -ECRYPT;
#endif
}

int crypt_encrypt(struct crypt_ctx * ctx,
                  buffer_t           in,
                  buffer_t *         out)
{
        if (ctx->flags == 0) {
                clrbuf(*out);
                return 0;
        }

#ifdef HAVE_OPENSSL
        return openssl_encrypt(ctx->ctx, ctx->key, in, out);
#else
        (void) in;
        (void) out;

        return -ECRYPT;
#endif
}

int crypt_decrypt(struct crypt_ctx * ctx,
                  buffer_t           in,
                  buffer_t *         out)
{
        if (ctx->flags == 0) {
                clrbuf(*out);
                return 0;
        }

#ifdef HAVE_OPENSSL
        return openssl_decrypt(ctx->ctx, ctx->key, in, out);
#else
        (void) in;
        (void) out;

        return -ECRYPT;
#endif
}

struct crypt_ctx * crypt_create_ctx(uint16_t        flags,
                                    const uint8_t * key)
{
        struct crypt_ctx * crypt;

        crypt = malloc(sizeof(*crypt));
        if (crypt == NULL)
                goto fail_crypt;

        memset(crypt, 0, sizeof(*crypt));

        crypt->flags = flags;
        if (key != NULL)
                memcpy(crypt->key, key, SYMMKEYSZ);
#ifdef HAVE_OPENSSL
        crypt->ctx=openssl_crypt_create_ctx();
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

int crypt_cmp_key(const void * key1,
                  const void * key2)
{
#ifdef HAVE_OPENSSL
        return openssl_cmp_key(key1, key2);
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
        openssl_free_key(key);
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
              buffer_t   msg,
              buffer_t * sig)
{
#ifdef HAVE_OPENSSL
        return openssl_sign(pkp, msg, sig);
#else
        (void) pkp;
        (void) msg;
        (void) sig;

        clrbuf(*sig);

        return 0;
#endif
}

int auth_verify_sig(void *   pk,
                    buffer_t msg,
                    buffer_t sig)
{
#ifdef HAVE_OPENSSL
        return openssl_verify_sig(pk, msg, sig);
#else
        (void) pk;
        (void) msg;
        (void) sig;

        return 0;
#endif
}
