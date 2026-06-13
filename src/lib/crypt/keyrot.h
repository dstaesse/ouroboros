/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Data-plane key-rotation schedule (node/leaf keys, selector)
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

#ifndef OUROBOROS_LIB_CRYPT_KEYROT_H
#define OUROBOROS_LIB_CRYPT_KEYROT_H

#include <ouroboros/crypt.h>   /* SYMMKEYSZ, NONCESZ */

#include <stdbool.h>
#include <stdint.h>

#define KR_SELECTOR_LEN 6
#define KR_NONCE_LEN    NONCESZ

struct keyrot;

struct kr_rx {
        uint64_t id;   /* batch id of the matched epoch */
        uint64_t ctr;  /* packet counter for replay check */
};

struct keyrot * keyrot_create(const uint8_t * root,
                              uint8_t         epoch,
                              uint8_t         role);

void            keyrot_destroy(struct keyrot * kr);

int             keyrot_rekey(struct keyrot * kr,
                             const uint8_t * root,
                             uint8_t         epoch);

/* Promote TX to the installed (new) batch once the peer is on it. */
void            keyrot_tx_promote(struct keyrot * kr);

int             keyrot_tx_next(struct keyrot *  kr,
                               uint8_t          sel[KR_SELECTOR_LEN],
                               const uint8_t ** key,
                               uint8_t          nonce[KR_NONCE_LEN]);

int             keyrot_rx_lookup(struct keyrot *  kr,
                                 const uint8_t    sel[KR_SELECTOR_LEN],
                                 const uint8_t ** key,
                                 uint8_t          nonce[KR_NONCE_LEN],
                                 struct kr_rx *   rx);

/* Commit an authenticated packet: replay window + peer-switched. */
int             keyrot_rx_commit(struct keyrot *      kr,
                                 const struct kr_rx * rx);

/* True once an RX packet under the current batch has been observed. */
bool            keyrot_peer_switched(const struct keyrot * kr);

unsigned        keyrot_tx_nodes_left(struct keyrot * kr);

#endif /* OUROBOROS_LIB_CRYPT_KEYROT_H */
