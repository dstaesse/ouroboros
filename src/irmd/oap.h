/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Ouroboros flow allocation protocol header
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

#include <ouroboros/utils.h>

#define OAP_ID_SIZE      (16)
#define OAP_HDR_MIN_SIZE (OAP_ID_SIZE + sizeof(uint64_t) + 4 * sizeof(uint16_t))


/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                        id (128 bits)                          |
 * |                                                               |
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                      timestamp (64 bits)                      |
 * |                                                               |
 * +---------------------------------------------------------------+
 * |      crt_len  (16 bits)     |                                 |
 * +-----------+-----------------+                                 |
 * |                        certificate                            |
 * |                                                               |
 * +---------------------------------------------------------------+
 * |      eph_len  (16 bits)     |                                 |
 * +-----------+-----------------+                                 |
 * |                   public key for ECDHE                        |
 * |                                                               |
 * +---------------------------------------------------------------+
 * |     data_len (16 bits)      |                                 |
 * +-----------+-----------------+                                 |
 * |               piggy backed application data                   |
 * |                                                               |
 * +---------------------------------------------------------------+
 * |     sig_len  (16 bits)      |                                 |
 * +-----------+-----------------+                                 |
 * |                         signature                             |
 * |                                                               |
 * +---------------------------------------------------------------+
 */

struct oap_hdr {
        uint64_t timestamp;
        buffer_t id;
        buffer_t crt;
        buffer_t eph;
        buffer_t data;
        buffer_t sig;
        buffer_t hdr;
};

int  oap_hdr_init(buffer_t         id,
                  void *           pkp,
                  void *           pubcrt,
                  buffer_t         ephkey,
                  buffer_t         data,
                  struct oap_hdr * oap_hdr);

void oap_hdr_fini(struct oap_hdr * oap_hdr);

int  oap_hdr_decode(buffer_t         hdr,
                    struct oap_hdr * oap_hdr);

#ifdef DEBUG_PROTO_OAP
void debug_oap_hdr_snd(const struct oap_hdr * hdr);

void debug_oap_hdr_rcv(const struct oap_hdr * hdr);
#endif /* DEBUG_PROTO_OAP */

#endif /* OUROBOROS_IRMD_OAP_H */
