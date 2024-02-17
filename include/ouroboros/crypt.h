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

#define SYMMKEYSZ 32

struct crypt_info {
    uint16_t flags;
    void *   ctx;
    uint8_t  key[SYMMKEYSZ];
};

int  crypt_dh_pkp_create(void **   pkp,
                         uint8_t * pk);

void crypt_dh_pkp_destroy(void * pkp);

int  crypt_dh_derive(void *    pkp,
                     buffer_t  pk,
                     uint8_t * s);

int  crypt_encrypt(struct crypt_info *  info,
                   struct shm_du_buff * sdb);

int  crypt_decrypt(struct crypt_info *  info,
                   struct shm_du_buff * sdb);

int  crypt_init(struct crypt_info * info);

void crypt_fini(struct crypt_info * info);

#endif /* OUROBOROS_LIB_CRYPT_H */