/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OAP - Header definitions and functions
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

#ifndef OUROBOROS_IRMD_OAP_HDR_H
#define OUROBOROS_IRMD_OAP_HDR_H

#include <ouroboros/crypt.h>
#include <ouroboros/utils.h>

#include <stdbool.h>
#include <stdint.h>

#define OAP_ID_SIZE      (16)
#define OAP_HDR_MIN_SIZE (OAP_ID_SIZE + sizeof(uint64_t) + 6 * sizeof(uint16_t))

#define OAP_KEX_FMT_BIT  0x8000 /* bit 15: 0=X.509 DER, 1=Raw               */
#define OAP_KEX_ROLE_BIT 0x4000 /* bit 14: 0=Server encaps, 1=Client encaps */
#define OAP_KEX_LEN_MASK 0x3FFF /* bits 0-13: Length (0-16383 bytes)        */

#define OAP_KEX_ROLE(hdr) (hdr->kex_flags.role)
#define OAP_KEX_FMT(hdr) (hdr->kex_flags.fmt)

#define OAP_KEX_IS_X509_FMT(hdr) (((hdr)->kex_flags.fmt) == 0)
#define OAP_KEX_IS_RAW_FMT(hdr)  (((hdr)->kex_flags.fmt) == 1)

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---+
 * |                                                               |    |
 * +                                                               +    |
 * |                                                               |    |
 * +                      id (128 bits)                            +    |
 * |                  Unique flow allocation ID                    |    |
 * +                                                               +    |
 * |                                                               |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
 * |                                                               |    |
 * +                     timestamp (64 bits)                       +    |
 * |                UTC nanoseconds since epoch                    |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
 * |       cipher_nid (16 bits)    |        kdf_nid (16 bits)      |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
 * |         md_nid (16 bits)      |        crt_len (16 bits)      |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
 * |F|R|      kex_len (14 bits)    |        data_len (16 bits)     |    | Signed
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    | Region
 * |                                                               |    |
 * +                  certificate (variable)                       +    |
 * |               X.509 certificate, DER encoded                  |    |
 * +                                                               +    |
 * |                                                               |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
 * |                                                               |    |
 * +                     kex_data (variable)                       +    |
 * |           public key (DER/raw) or ciphertext (KEM)            |    |
 * +                                                               +    |
 * |                                                               |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
 * |                                                               |    |
 * +                        data (variable)                        +    |
 * |                  Piggybacked application data                 |    |
 * +                                                               +    |
 * |                                                               |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
 * |                                                               |    |
 * +                  req_hash (variable, response only)           +    |
 * |                      H(request) using req md_nid / sha384     |    |
 * |                                                               |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---+
 * |                                                               |
 * +                     signature (variable)                      +
 * |                  DSA signature over signed region             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * cipher_nid: NID value for symmetric cipher (0 = none)
 * kdf_nid:    NID value for KDF function (0 = none)
 * md_nid:     NID value for signature hash (0 = PQC/no signature)
 *
 * kex_len field bit layout:
 *   F (bit 15): Format - 0 = X.509 DER, 1 = Raw/Hybrid
 *   R (bit 14): Role   - 0 = Server encaps, 1 = Client encaps
 *               (R is ignored for non-KEM algorithms)
 *   Bits 0-13:  Length (0-16383 bytes)
 *
 * Request:  sig_len = total - 36 - crt_len - kex_len - data_len
 * Response: sig_len = total - 36 - crt_len - kex_len - data_len - hash_len
 *           where hash_len = md_len(req_md_nid / sha384)
 */

/* Parsed OAP header - buffers pointing to a single memory region */
struct oap_hdr {
        const char * cipher_str;
        const char * kdf_str;
        const char * md_str;
        uint64_t     timestamp;
        uint16_t     nid;
        uint16_t     kdf_nid;
        uint16_t     md_nid;
        struct {
                bool fmt;   /* Format */
                bool role;  /* Role   */
        } kex_flags;
        buffer_t     id;
        buffer_t     crt;
        buffer_t     kex;
        buffer_t     data;
        buffer_t     req_hash; /* H(request) - response only */
        buffer_t     sig;
        buffer_t     hdr;
};


void oap_hdr_init(struct oap_hdr * hdr,
                  buffer_t         id,
                  uint8_t *        kex_buf,
                  buffer_t         data,
                  uint16_t         nid);

void oap_hdr_fini(struct oap_hdr * oap_hdr);

int  oap_hdr_encode(struct oap_hdr *    hdr,
                    void *              pkp,
                    void *              crt,
                    struct sec_config * kcfg,
                    buffer_t            req_hash,
                    int                 req_md_nid);

int  oap_hdr_decode(struct oap_hdr * hdr,
                    buffer_t         buf,
                    int              req_md_nid);

void debug_oap_hdr_rcv(const struct oap_hdr * hdr);

void debug_oap_hdr_snd(const struct oap_hdr * hdr);

int  oap_hdr_copy_data(const struct oap_hdr * hdr,
                       buffer_t *             out);

#endif /* OUROBOROS_IRMD_OAP_HDR_H */
