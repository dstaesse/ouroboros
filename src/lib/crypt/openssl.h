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

ssize_t openssl_ecdh_pkp_create(void **   pkp,
                                uint8_t * pk);

void    openssl_ecdh_pkp_destroy(void * pkp);

int     openssl_ecdh_derive(void *    pkp,
                            buffer_t  pk,
                            uint8_t * s);

int     openssl_encrypt(void *     ctx,
                        uint8_t *  key,
                        buffer_t   in,
                        buffer_t * out);

int     openssl_decrypt(void *     ctx,
                        uint8_t *  key,
                        buffer_t   in,
                        buffer_t * out);

void *  openssl_crypt_create_ctx(void);

void    openssl_crypt_destroy_ctx(void * ctx);

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

int     openssl_cmp_key(const void * key1,
                        const void * key2);

void    openssl_free_key(void * key);

int     openssl_check_crt_name(void *       crt,
                               const char * name);

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

int     openssl_sign(void *     pkp,
                     buffer_t   msg,
                     buffer_t * sig);

int     openssl_verify_sig(void *   pk,
                           buffer_t msg,
                           buffer_t sig);

#endif /* OUROBOROS_LIB_CRYPT_OPENSSL_H */
