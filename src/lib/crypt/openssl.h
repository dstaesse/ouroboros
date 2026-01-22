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

#ifndef OUROBOROS_LIB_CRYPT_OPENSSL_H
#define OUROBOROS_LIB_CRYPT_OPENSSL_H

struct ossl_crypt_ctx;

ssize_t openssl_pkp_create(const char * algo,
                           EVP_PKEY **  pkp,
                           uint8_t *    pk);

void    openssl_pkp_destroy(EVP_PKEY * pkp);

int     openssl_dhe_derive(EVP_PKEY * pkp,
                           buffer_t   pk,
                           int        kdf_nid,
                           uint8_t *  s);

ssize_t openssl_kem_encap(buffer_t  pk,
                          uint8_t * ct,
                          int       kdf_nid,
                          uint8_t * s);

/* no X509 DER support yet for DHKEM public keys */
ssize_t openssl_kem_encap_raw(buffer_t  pk,
                              uint8_t * ct,
                              int       kdf_nid,
                              uint8_t * s);

int     openssl_kem_decap(EVP_PKEY * priv,
                          buffer_t   ct,
                          int        kdf_nid,
                          uint8_t *  s);

int     openssl_get_algo_from_pk_der(buffer_t pk,
                                     char *   algo);

int     openssl_get_algo_from_pk_raw(buffer_t pk,
                                     char *   algo);

int     openssl_encrypt(struct ossl_crypt_ctx * ctx,
                        buffer_t                in,
                        buffer_t *              out);

int     openssl_decrypt(struct ossl_crypt_ctx * ctx,
                        buffer_t                in,
                        buffer_t *              out);

struct ossl_crypt_ctx * openssl_crypt_create_ctx(struct crypt_sk * sk);

void                    openssl_crypt_destroy_ctx(struct ossl_crypt_ctx * ctx);

int                     openssl_crypt_get_ivsz(struct ossl_crypt_ctx * ctx);

int                     openssl_crypt_get_tagsz(struct ossl_crypt_ctx * ctx);

/* AUTHENTICATION */

int     openssl_load_crt_file(const char * path,
                              void **      crt);

int     openssl_load_crt_str(const char * str,
                             void **      crt);

int     openssl_load_crt_der(buffer_t buf,
                             void **  crt);

int     openssl_get_pubkey_crt(void *  crt,
                               void ** pk);

void    openssl_free_crt(void * crt);

int     openssl_load_privkey_file(const char * path,
                                  void **      key);

int     openssl_load_privkey_str(const char * str,
                                 void **      key);

int     openssl_load_pubkey_file(const char * path,
                                 void **      key);

int     openssl_load_pubkey_str(const char * str,
                                void **      key);
int     openssl_load_pubkey_file_to_der(const char * path,
                                        buffer_t *   buf);
int     openssl_load_pubkey_raw_file(const char * path,
                                     buffer_t *   buf);

int     openssl_load_privkey_raw_file(const char * path,
                                      void **      key);

int     openssl_cmp_key(const EVP_PKEY * key1,
                        const EVP_PKEY * key2);

void    openssl_free_key(EVP_PKEY * key);

int     openssl_check_crt_name(void *       crt,
                               const char * name);

int     openssl_get_crt_name(void * crt,
                             char * name);

int     openssl_crt_str(const void * crt,
                        char *       str);

int     openssl_crt_der(const void * crt,
                        buffer_t *   buf);

void *  openssl_auth_create_store(void);

void    openssl_auth_destroy_store(void * store);

int     openssl_auth_add_crt_to_store(void * store,
                                      void * crt);

int     openssl_verify_crt(void * store,
                           void * crt);

int     openssl_sign(EVP_PKEY * pkp,
                     int        md_nid,
                     buffer_t   msg,
                     buffer_t * sig);

int     openssl_verify_sig(EVP_PKEY * pk,
                           int        md_nid,
                           buffer_t   msg,
                           buffer_t   sig);

ssize_t openssl_md_digest(int        md_nid,
                          buffer_t   in,
                          uint8_t *  out);

ssize_t openssl_md_len(int md_nid);

/* Secure memory allocation */
int     openssl_secure_malloc_init(size_t max,
                                   size_t guard);

void    openssl_secure_malloc_fini(void);

void *  openssl_secure_malloc(size_t size);

void    openssl_secure_free(void * ptr,
                            size_t size);

#endif /* OUROBOROS_LIB_CRYPT_OPENSSL_H */
