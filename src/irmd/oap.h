/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Ouroboros Allocation Protocol (OAP) Component
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

#ifndef OUROBOROS_IRMD_OAP_H
#define OUROBOROS_IRMD_OAP_H

#include <ouroboros/crypt.h>
#include <ouroboros/flow.h>
#include <ouroboros/name.h>
#include <ouroboros/utils.h>

#include <stdbool.h>

/* OAP authentication state (in oap/auth.c) */
int  oap_auth_init(void);

void oap_auth_fini(void);

int  oap_auth_add_ca_crt(void * crt);

int  oap_auth_add_chain_crt(void * crt);

/*
* Prepare OAP request header for server, returns context
* Passes client data for srv, returns srv data for client
* rekey forces ephemeral server-encap KEX (no client-encap; preserves FS/PCS)
*/
int  oap_cli_prepare(void **                  ctx,
                     const struct name_info * info,
                     buffer_t *               req_buf,
                     buffer_t                 data,
                     bool                     rekey);

/*
 * Server processes header, creates response header, returns secret key.
 * data is in/out: input=srv data to send, output=cli data received.
 * rekey drops the cert and verifies against cached_crt; peer_crt (or NULL)
 * receives a copy of the peer cert to cache at the initial handshake.
 */
int  oap_srv_process(const struct name_info * info,
                     buffer_t                 req_buf,
                     buffer_t *               rsp_buf,
                     buffer_t *               data,
                     struct crypt_sk *        sk,
                     bool                     rekey,
                     const buffer_t *         cached_crt,
                     buffer_t *               peer_crt);

/*
 * Complete OAP, returns secret key and server data, frees ctx.
 * cached_crt verifies a cert-less re-key; peer_crt (or NULL) receives a
 * copy of the peer cert to cache at the initial handshake.
 */
int  oap_cli_complete(void *                   ctx,
                      const struct name_info * info,
                      buffer_t                 rsp_buf,
                      buffer_t *               data,
                      struct crypt_sk *        sk,
                      const buffer_t *         cached_crt,
                      buffer_t *               peer_crt);

/* Free OAP state (on failure before complete) */
void oap_ctx_free(void * ctx);

#endif /* OUROBOROS_IRMD_OAP_H */
