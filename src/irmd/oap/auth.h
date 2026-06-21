/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OAP - Authentication functions
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

#ifndef OUROBOROS_IRMD_OAP_AUTH_H
#define OUROBOROS_IRMD_OAP_AUTH_H

#include <ouroboros/crypt.h>

#include "hdr.h"

int  oap_check_hdr(const struct oap_hdr * hdr);

/*
 * name is set to the peer crt CN, "" if no crt was presented.
 * cached_crt (or NULL) is the peer cert from the initial handshake, used
 * to verify a cert-less re-key.
 */
int  oap_auth_peer(char *                    name,
                   const struct sec_config * cfg,
                   const struct oap_hdr *    local_hdr,
                   const struct oap_hdr *    peer_hdr,
                   const buffer_t *          cached_crt);

/* Derive the handshake key that seals the response identity block. */
int  oap_derive_hs_key(const struct crypt_sk * sk,
                       buffer_t                req_hash,
                       uint8_t *               out);

/* resp_hash = H(kex || data || crt): binds the server response transcript. */
int  oap_resp_hash(int        md_nid,
                   buffer_t   kex,
                   buffer_t   data,
                   buffer_t   crt,
                   buffer_t * out);

/* Fold request + response transcript + negotiated suite into the key. */
int  oap_bind_session_key(struct crypt_sk * sk,
                          buffer_t          req_hash,
                          buffer_t          resp_hash,
                          int               kdf_nid);

/* Server->client key-confirmation tag derived from the bound key. */
int  oap_key_confirm_tag(const struct crypt_sk * sk,
                         buffer_t                req_hash,
                         buffer_t                resp_hash,
                         uint8_t *               out,
                         size_t                  outlen);

#endif /* OUROBOROS_IRMD_OAP_AUTH_H */
