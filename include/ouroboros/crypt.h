/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Cryptography
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

#ifndef OUROBOROS_LIB_CRYPT_H
#define OUROBOROS_LIB_CRYPT_H

#include <ouroboros/shm_du_buff.h>
#include <ouroboros/utils.h>

#define IVSZ      16
#define SYMMKEYSZ 32
#define MSGBUFSZ  2048

struct auth_ctx;
struct crypt_ctx;

struct crypt_ctx * crypt_create_ctx(uint16_t        flags,
                                    const uint8_t * key);

void               crypt_destroy_ctx(struct crypt_ctx * ctx);

int                crypt_dh_pkp_create(void **   pkp,
                                       uint8_t * pk);

void               crypt_dh_pkp_destroy(void * pkp);

int                crypt_dh_derive(void *    pkp,
                                   buffer_t  pk,
                                   uint8_t * s);

int                crypt_encrypt(struct crypt_ctx * ctx,
                                 buffer_t           in,
                                 buffer_t *         out);

int                crypt_decrypt(struct crypt_ctx * ctx,
                                 buffer_t           in,
                                 buffer_t *         out);

int                crypt_load_crt_file(const char * path,
                                       void **      crt);

int                crypt_load_crt_str(const char * str,
                                      void **      crt);

int                crypt_get_pubkey_crt(void *  crt,
                                        void ** pk);

void               crypt_free_crt(void * crt);

int                crypt_load_privkey_file(const char * path,
                                           void **      key);

int                crypt_load_privkey_str(const char * str,
                                          void **      key);

int                crypt_load_pubkey_str(const char * str,
                                         void **      key);

int                crypt_cmp_key(const void * key1,
                                 const void * key2);

void               crypt_free_key(void * key);

int                crypt_crt_str(void * crt,
                                 char * buf);

int                crypt_check_crt_name(void *       crt,
                                        const char * name);

struct auth_ctx *  auth_create_ctx(void);

void               auth_destroy_ctx(struct auth_ctx * ctx);

int                auth_add_crt_to_store(struct auth_ctx * ctx,
                                         void *            crt);

void               auth_destroy_ctx(struct auth_ctx * ctx);

int                auth_verify_crt(struct auth_ctx * ctx,
                                   void *            crt);

int                auth_sign(void *     pkp,
                             buffer_t   msg,
                             buffer_t * sig);

int                auth_verify_sig(void *   pk,
                                   buffer_t msg,
                                   buffer_t sig);

#endif /* OUROBOROS_LIB_CRYPT_H */
