/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OAP internal definitions
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_IRMD_OAP_INTERNAL_H
#define OUROBOROS_IRMD_OAP_INTERNAL_H

#include <ouroboros/crypt.h>
#include <ouroboros/list.h>
#include <ouroboros/name.h>
#include <ouroboros/pthread.h>
#include <ouroboros/utils.h>

#include "hdr.h"

#include <stdbool.h>
#include <stdint.h>

int  oap_check_hdr(const struct oap_hdr * hdr);

int  oap_auth_peer(char *                 name,
                   const struct oap_hdr * local_hdr,
                   const struct oap_hdr * peer_hdr);

int  oap_negotiate_cipher(const struct oap_hdr * peer_hdr,
                          struct sec_config *    kcfg);

#ifndef OAP_TEST_MODE
int  load_credentials(const char *                  name,
                      const struct name_sec_paths * paths,
                      void **                       pkp,
                      void **                       crt);

int  load_kex_config(const char *        name,
                     const char *        path,
                     struct sec_config * cfg);
#endif

#ifndef OAP_TEST_MODE
int  load_srv_credentials(const struct name_info * info,
                          void **                  pkp,
                          void **                  crt);

int  load_srv_kex_config(const struct name_info * info,
                         struct sec_config *      cfg);

int  load_server_kem_keypair(const char *        name,
                             struct sec_config * cfg,
                             void **             pkp);
#else
extern int load_srv_credentials(const struct name_info * info,
                                void **                  pkp,
                                void **                  crt);
extern int load_srv_kex_config(const struct name_info * info,
                               struct sec_config *      cfg);
extern int load_server_kem_keypair(const char *        name,
                                   struct sec_config * cfg,
                                   void **             pkp);
#endif

int  do_server_kex(const struct name_info * info,
                   struct oap_hdr *         peer_hdr,
                   struct sec_config *      kcfg,
                   buffer_t *               kex,
                   struct crypt_sk *        sk);

#ifndef OAP_TEST_MODE
int  load_cli_credentials(const struct name_info * info,
                          void **                  pkp,
                          void **                  crt);

int  load_cli_kex_config(const struct name_info * info,
                         struct sec_config *      cfg);

int  load_server_kem_pk(const char *        name,
                        struct sec_config * cfg,
                        buffer_t *          pk);
#else
extern int load_cli_credentials(const struct name_info * info,
                                void **                  pkp,
                                void **                  crt);
extern int load_cli_kex_config(const struct name_info * info,
                               struct sec_config *      cfg);
extern int load_server_kem_pk(const char *        name,
                              struct sec_config * cfg,
                              buffer_t *          pk);
#endif

int  oap_client_kex_prepare(struct sec_config * kcfg,
                            buffer_t            server_pk,
                            buffer_t *          kex,
                            uint8_t *           key,
                            void **             ephemeral_pkp);

int  oap_client_kex_complete(const struct oap_hdr * peer_hdr,
                             struct sec_config *    kcfg,
                             void *                 pkp,
                             uint8_t *              key);

#endif /* OUROBOROS_IRMD_OAP_INTERNAL_H */
