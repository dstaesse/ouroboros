/*
 * Ouroboros - Copyright (C) 2016 - 2019
 *
 * Elliptic curve Diffie-Hellman key exchange and
 * AES encryption for flows using OpenSSL
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

#ifdef HAVE_OPENSSL

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#define MSGBUFSZ 2048
#define IVSZ     16
#define DH_TIMEO 2 /* seconds */
/* SYMMKEYSZ defined in dev.c */

/*
 * Derive the common secret from
 *  your public key pair (kp)
 *  the remote public key (pub).
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

static int __openssl_ecdh_gen_key(EVP_PKEY ** kp)
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

        ret = EVP_PKEY_keygen(kctx, kp);
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

/* ECDH from the server side. */
static int openssl_ecdh_srv(int       fd,
                            uint8_t * s)
{
        EVP_PKEY *      kp    = NULL;
        EVP_PKEY *      pub   = NULL;
        uint8_t         buf[MSGBUFSZ];
        ssize_t         len;
        int             buf_sz;
        uint8_t *       pos;
        struct timespec timeo = {DH_TIMEO,0};

        assert(s != NULL);

        (void) fd;
        (void) s;

        if (__openssl_ecdh_gen_key(&kp) < 0)
                goto fail_gen_key;

        fccntl(fd, FLOWSRCVTIMEO, &timeo);

        len = flow_read(fd, buf, MSGBUFSZ);
        if (len < 0) {
                fccntl(fd, FLOWSRCVTIMEO, NULL);
                goto fail_get_key;
        }

        fccntl(fd, FLOWSRCVTIMEO, NULL);

        pos = buf; /* i2d_PUBKEY increments the pointer, don't use buf! */
        pub = d2i_PUBKEY(NULL, (const uint8_t **) &pos, (long) len);

        pos = buf; /* i2d_PUBKEY increments the pointer, don't use buf! */
        buf_sz = i2d_PUBKEY(kp, &pos);
        if (buf_sz < 0)
                goto fail_get_key;

        if (flow_write(fd, buf, (size_t) buf_sz) < 0)
                goto fail_get_key;

        if (__openssl_ecdh_derive_secret(kp, pub, s) < 0)
                goto fail_get_key;

        EVP_PKEY_free(kp);
        EVP_PKEY_free(pub);

        return 0;

 fail_get_key:
        EVP_PKEY_free(kp);
 fail_gen_key:
        return -ECRYPT;
}

/* ECDH from the client side. */
static int openssl_ecdh_clt(int       fd,
                            uint8_t * s)
{
        EVP_PKEY *      kp    = NULL;
        EVP_PKEY *      pub   = NULL;
        uint8_t         buf[MSGBUFSZ];
        int             buf_sz;
        uint8_t *       pos;
        ssize_t         len;
        struct timespec timeo = {DH_TIMEO,0};

        assert(s != NULL);

        (void) fd;
        (void) s;

        if (__openssl_ecdh_gen_key(&kp) < 0)
                goto fail_gen_key;

        pos = buf; /* i2d_PUBKEY increments the pointer, don't use buf! */
        buf_sz = i2d_PUBKEY(kp, &pos);
        if (buf_sz < 0)
                goto fail_get_key;

        if (flow_write(fd, buf, (size_t) buf_sz) < 0)
                goto fail_get_key;

        fccntl(fd, FLOWSRCVTIMEO, &timeo);

        len = flow_read(fd, buf, MSGBUFSZ);
        if (len < 0) {
                fccntl(fd, FLOWSRCVTIMEO, NULL);
                goto fail_get_key;
        }

        fccntl(fd, FLOWSRCVTIMEO, NULL);

        pos = buf; /* i2d_PUBKEY increments the pointer, don't use buf! */
        pub = d2i_PUBKEY(NULL, (const uint8_t **) &pos, (long) len);

        if (__openssl_ecdh_derive_secret(kp, pub, s) < 0)
                goto fail_get_key;

        EVP_PKEY_free(kp);
        EVP_PKEY_free(pub);

        return 0;

 fail_get_key:
        EVP_PKEY_free(kp);
 fail_gen_key:
        return -ECRYPT;
}

/*
 * AES encryption calls. If FRCT is disabled, we should generate a
 * 128-bit random IV and append it to the packet.  If the flow is
 * reliable, we could initialize the context once, and consider the
 * stream a single encrypted message to avoid initializing the
 * encryption context for each packet.
 */

static int openssl_encrypt(struct flow *        f,
                           struct shm_du_buff * sdb)
{
        uint8_t * out;
        uint8_t * in;
        uint8_t * head;
        uint8_t   iv[IVSZ];
        int       in_sz;
        int       out_sz;
        int       tmp_sz;
        int       ret;

        in = shm_du_buff_head(sdb);
        in_sz = shm_du_buff_tail(sdb) - in;

        if (random_buffer(iv, IVSZ) < 0)
                goto fail_iv;

        out = malloc(in_sz + EVP_MAX_BLOCK_LENGTH);
        if (out == NULL)
                goto fail_iv;

        EVP_CIPHER_CTX_reset(f->ctx);

        ret = EVP_EncryptInit_ex(f->ctx,
                                 EVP_aes_256_cbc(),
                                 NULL,
                                 f->key,
                                 iv);
        if (ret != 1)
                goto fail_encrypt_init;

        ret = EVP_EncryptUpdate(f->ctx, out, &tmp_sz, in, in_sz);
        if (ret != 1)
                goto fail_encrypt;

        out_sz = tmp_sz;
        ret =  EVP_EncryptFinal_ex(f->ctx, out + tmp_sz, &tmp_sz);
        if (ret != 1)
                goto fail_encrypt;

        out_sz += tmp_sz;

        EVP_CIPHER_CTX_cleanup(f->ctx);

        assert(out_sz >= in_sz);

        head = shm_du_buff_head_alloc(sdb, IVSZ);
        if (head == NULL)
                goto fail_encrypt;

        if (shm_du_buff_tail_alloc(sdb, out_sz - in_sz) == NULL)
                goto fail_tail_alloc;

        memcpy(head, iv, IVSZ);
        memcpy(in, out, out_sz);

        free(out);

        return 0;

 fail_tail_alloc:
        shm_du_buff_head_release(sdb, IVSZ);
 fail_encrypt:
        EVP_CIPHER_CTX_cleanup(f->ctx);
 fail_encrypt_init:
        free(out);
 fail_iv:
        return -ECRYPT;
}

static int openssl_decrypt(struct flow *        f,
                           struct shm_du_buff * sdb)
{
        uint8_t * in;
        uint8_t * out;
        uint8_t   iv[IVSZ];
        int       ret;
        int       out_sz;
        int       in_sz;
        int       tmp_sz;

        in = shm_du_buff_head_release(sdb, IVSZ);

        memcpy(iv, in, IVSZ);

        in = shm_du_buff_head(sdb);

        in_sz = shm_du_buff_tail(sdb) - shm_du_buff_head(sdb);

        out = malloc(in_sz);
        if (out == NULL)
                goto fail_malloc;

        EVP_CIPHER_CTX_reset(f->ctx);

        ret = EVP_DecryptInit_ex(f->ctx,
                                 EVP_aes_256_cbc(),
                                 NULL,
                                 f->key,
                                 iv);
        if (ret != 1)
                goto fail_decrypt_init;

        ret = EVP_DecryptUpdate(f->ctx, out, &tmp_sz, in, in_sz);
        if (ret != 1)
                goto fail_decrypt;

        out_sz = tmp_sz;

        ret = EVP_DecryptFinal_ex(f->ctx, out + tmp_sz, &tmp_sz);
        if (ret != 1)
                goto fail_decrypt;

        out_sz += tmp_sz;

        assert(out_sz <= in_sz);

        shm_du_buff_tail_release(sdb, in_sz - out_sz);

        memcpy(in, out, out_sz);

        free(out);

        return 0;

 fail_decrypt:
        EVP_CIPHER_CTX_cleanup(f->ctx);
 fail_decrypt_init:
        free(out);
 fail_malloc:
        return -ECRYPT;

}

static int openssl_crypt_init(struct flow * f)
{
        f->ctx = EVP_CIPHER_CTX_new();
        if (f->ctx == NULL)
                goto fail_new;

        return 0;

 fail_new:
        return -ECRYPT;
}

static void openssl_crypt_fini(struct flow * f)
{
        EVP_CIPHER_CTX_free(f->ctx);
        f->ctx = NULL;
}

#endif /* HAVE_OPENSSL */

static int crypt_dh_srv(int       fd,
                        uint8_t * s)
{
#ifdef HAVE_OPENSSL
        return openssl_ecdh_clt(fd, s);
#else
        (void) fd;

        memset(s, 0, SYMMKEYSZ);

        return -ECRYPT;
#endif
}

static int crypt_dh_clt(int       fd,
                        uint8_t * s)
{
#ifdef HAVE_OPENSSL
        return openssl_ecdh_srv(fd, s);
#else
        (void) fd;

        memset(s, 0, SYMMKEYSZ);

        return 0;
#endif
}

static int crypt_encrypt(struct flow *        f,
                         struct shm_du_buff * sdb)
{
#ifdef HAVE_OPENSSL
        return openssl_encrypt(f, sdb);
#else
        (void) f;
        (void) sdb;

        return 0;
#endif
}

static int crypt_decrypt(struct flow *        f,
                         struct shm_du_buff * sdb)
{
#ifdef HAVE_OPENSSL
        return openssl_decrypt(f, sdb);
#else
        (void) f;
        (void) sdb;

        return 0;
#endif
}


static int crypt_init(struct flow * f)
{
#ifdef HAVE_OPENSSL
        return openssl_crypt_init(f);
#else
        (void) f;

        return 0;
#endif
}

static void crypt_fini(struct flow * f)
{
#ifdef HAVE_OPENSSL
        openssl_crypt_fini(f);
#else
        (void) f;
#endif
}
