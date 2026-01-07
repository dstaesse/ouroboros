/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * OAP - Header encoding, decoding, and debugging
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

#if defined(__linux__) || defined(__CYGWIN__)
 #define _DEFAULT_SOURCE
#else
 #define _POSIX_C_SOURCE 200809L
#endif

#define OUROBOROS_PREFIX "irmd/oap"

#include <ouroboros/crypt.h>
#include <ouroboros/endian.h>
#include <ouroboros/hash.h>
#include <ouroboros/logs.h>
#include <ouroboros/rib.h>
#include <ouroboros/time.h>

#include "config.h"

#include "hdr.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int oap_hdr_decode(struct oap_hdr * oap_hdr,
                   buffer_t         hdr,
                   int              req_md_nid)
{
        off_t        offset;
        uint16_t     kex_len;
        uint16_t     ciph_nid;
        size_t       crt_len;
        size_t       data_len;
        size_t       hash_len;
        size_t       sig_len;

        assert(oap_hdr != NULL);
        memset(oap_hdr, 0, sizeof(*oap_hdr));

        if (hdr.len < OAP_HDR_MIN_SIZE)
                goto fail_decode;

        /* Parse fixed header (36 bytes) */
        oap_hdr->id.data = hdr.data;
        oap_hdr->id.len  = OAP_ID_SIZE;

        offset = OAP_ID_SIZE;

        oap_hdr->timestamp = ntoh64(*(uint64_t *)(hdr.data + offset));
        offset += sizeof(uint64_t);

        /* cipher NID */
        ciph_nid = ntoh16(*(uint16_t *)(hdr.data + offset));
        oap_hdr->nid = ciph_nid;
        oap_hdr->cipher_str = crypt_nid_to_str(ciph_nid);
        offset += sizeof(uint16_t);

        /* kdf NID */
        oap_hdr->kdf_nid = ntoh16(*(uint16_t *)(hdr.data + offset));
        oap_hdr->kdf_str = md_nid_to_str(oap_hdr->kdf_nid);
        offset += sizeof(uint16_t);

        /* md NID (signature hash) */
        oap_hdr->md_nid = ntoh16(*(uint16_t *)(hdr.data + offset));
        oap_hdr->md_str = md_nid_to_str(oap_hdr->md_nid);
        offset += sizeof(uint16_t);

        /* Validate NIDs: NID_undef is valid at parse time, else must be known.
         * Note: md_nid=NID_undef only valid for PQC; enforced at sign/verify.
         */
        if (ciph_nid != NID_undef && crypt_validate_nid(ciph_nid) < 0)
                goto fail_decode;
        if (oap_hdr->kdf_nid != NID_undef &&
            md_validate_nid(oap_hdr->kdf_nid) < 0)
                goto fail_decode;
        if (oap_hdr->md_nid != NID_undef &&
            md_validate_nid(oap_hdr->md_nid) < 0)
                goto fail_decode;

        /* crt_len */
        crt_len = (size_t) ntoh16(*(uint16_t *)(hdr.data + offset));
        offset += sizeof(uint16_t);

        /* kex_len + flags */
        kex_len = ntoh16(*(uint16_t *)(hdr.data + offset));
        oap_hdr->kex.len = (size_t) (kex_len & OAP_KEX_LEN_MASK);
        oap_hdr->kex_flags.fmt  = (kex_len & OAP_KEX_FMT_BIT) ? 1 : 0;
        oap_hdr->kex_flags.role = (kex_len & OAP_KEX_ROLE_BIT) ? 1 : 0;
        offset += sizeof(uint16_t);

        /* data_len */
        data_len = (size_t) ntoh16(*(uint16_t *)(hdr.data + offset));
        offset += sizeof(uint16_t);

        /* Response includes req_hash when md_nid is set */
        hash_len = (req_md_nid != NID_undef) ?
                   (size_t) md_len(req_md_nid) : 0;

        /* Validate total length */
        if (hdr.len < (size_t) offset + crt_len + oap_hdr->kex.len +
                      data_len + hash_len)
                goto fail_decode;

        /* Derive sig_len from remaining bytes */
        sig_len = hdr.len - offset - crt_len - oap_hdr->kex.len -
                  data_len - hash_len;

        /* Unsigned packets must not have trailing bytes */
        if (crt_len == 0 && sig_len != 0)
                goto fail_decode;

        /* Parse variable fields */
        oap_hdr->crt.data = hdr.data + offset;
        oap_hdr->crt.len = crt_len;
        offset += crt_len;

        oap_hdr->kex.data = hdr.data + offset;
        offset += oap_hdr->kex.len;

        oap_hdr->data.data = hdr.data + offset;
        oap_hdr->data.len = data_len;
        offset += data_len;

        oap_hdr->req_hash.data = hdr.data + offset;
        oap_hdr->req_hash.len = hash_len;
        offset += hash_len;

        oap_hdr->sig.data = hdr.data + offset;
        oap_hdr->sig.len = sig_len;

        oap_hdr->hdr = hdr;

        return 0;

 fail_decode:
        memset(oap_hdr, 0, sizeof(*oap_hdr));
        return -1;
}

void oap_hdr_fini(struct oap_hdr * oap_hdr)
{
        assert(oap_hdr != NULL);

        freebuf(oap_hdr->hdr);
        memset(oap_hdr, 0, sizeof(*oap_hdr));
}

int oap_hdr_copy_data(const struct oap_hdr * hdr,
                      buffer_t *             out)
{
        assert(hdr != NULL);
        assert(out != NULL);

        if (hdr->data.len == 0) {
                clrbuf(*out);
                return 0;
        }

        out->data = malloc(hdr->data.len);
        if (out->data == NULL)
                return -ENOMEM;

        memcpy(out->data, hdr->data.data, hdr->data.len);
        out->len = hdr->data.len;

        return 0;
}

void oap_hdr_init(struct oap_hdr * hdr,
                  buffer_t         id,
                  uint8_t *        kex_buf,
                  buffer_t         data,
                  uint16_t         nid)
{
        assert(hdr != NULL);
        assert(id.data != NULL && id.len == OAP_ID_SIZE);

        memset(hdr, 0, sizeof(*hdr));

        hdr->id       = id;
        hdr->kex.data = kex_buf;
        hdr->kex.len  = 0;
        hdr->data     = data;
        hdr->nid      = nid;
}

int oap_hdr_encode(struct oap_hdr *    hdr,
                   void *              pkp,
                   void *              crt,
                   struct sec_config * kcfg,
                   buffer_t            req_hash,
                   int                 req_md_nid)
{
        struct timespec now;
        uint64_t        stamp;
        buffer_t        out;
        buffer_t        der = BUF_INIT;
        buffer_t        sig = BUF_INIT;
        buffer_t        sign;
        uint16_t        len;
        uint16_t        ciph_nid;
        uint16_t        kdf_nid;
        uint16_t        md_nid;
        uint16_t        kex_len;
        off_t           offset;

        assert(hdr != NULL);
        assert(hdr->id.data != NULL && hdr->id.len == OAP_ID_SIZE);
        assert(kcfg != NULL);

        clock_gettime(CLOCK_REALTIME, &now);
        stamp = hton64(TS_TO_UINT64(now));

        if (crt != NULL && crypt_crt_der(crt, &der) < 0)
                goto fail_der;

        ciph_nid = hton16(hdr->nid);
        kdf_nid = hton16(kcfg->k.nid);
        md_nid = hton16(kcfg->d.nid);

        /* Build kex_len with flags */
        kex_len = (uint16_t) hdr->kex.len;
        if (hdr->kex.len > 0 && IS_KEM_ALGORITHM(kcfg->x.str)) {
                if (IS_HYBRID_KEM(kcfg->x.str))
                        kex_len |= OAP_KEX_FMT_BIT;
                if (kcfg->x.mode == KEM_MODE_CLIENT_ENCAP)
                        kex_len |= OAP_KEX_ROLE_BIT;
        }
        kex_len = hton16(kex_len);

        /* Fixed header (36 bytes) + variable fields + req_hash (if auth) */
        out.len = OAP_HDR_MIN_SIZE + der.len + hdr->kex.len + hdr->data.len +
                  req_hash.len;

        out.data = malloc(out.len);
        if (out.data == NULL)
                goto fail_out;

        offset = 0;

        /* id (16 bytes) */
        memcpy(out.data + offset, hdr->id.data, hdr->id.len);
        offset += hdr->id.len;

        /* timestamp (8 bytes) */
        memcpy(out.data + offset, &stamp, sizeof(stamp));
        offset += sizeof(stamp);

        /* cipher_nid (2 bytes) */
        memcpy(out.data + offset, &ciph_nid, sizeof(ciph_nid));
        offset += sizeof(ciph_nid);

        /* kdf_nid (2 bytes) */
        memcpy(out.data + offset, &kdf_nid, sizeof(kdf_nid));
        offset += sizeof(kdf_nid);

        /* md_nid (2 bytes) */
        memcpy(out.data + offset, &md_nid, sizeof(md_nid));
        offset += sizeof(md_nid);

        /* crt_len (2 bytes) */
        len = hton16((uint16_t) der.len);
        memcpy(out.data + offset, &len, sizeof(len));
        offset += sizeof(len);

        /* kex_len + flags (2 bytes) */
        memcpy(out.data + offset, &kex_len, sizeof(kex_len));
        offset += sizeof(kex_len);

        /* data_len (2 bytes) */
        len = hton16((uint16_t) hdr->data.len);
        memcpy(out.data + offset, &len, sizeof(len));
        offset += sizeof(len);

        /* Fixed header complete (36 bytes) */
        assert((size_t) offset == OAP_HDR_MIN_SIZE);

        /* certificate (variable) */
        if (der.len != 0)
                memcpy(out.data + offset, der.data, der.len);
        offset += der.len;

        /* kex data (variable) */
        if (hdr->kex.len != 0)
                memcpy(out.data + offset, hdr->kex.data, hdr->kex.len);
        offset += hdr->kex.len;

        /* data (variable) */
        if (hdr->data.len != 0)
                memcpy(out.data + offset, hdr->data.data, hdr->data.len);
        offset += hdr->data.len;

        /* req_hash (variable, only for authenticated responses) */
        if (req_hash.len != 0)
                memcpy(out.data + offset, req_hash.data, req_hash.len);
        offset += req_hash.len;

        assert((size_t) offset == out.len);

        /* Sign the entire header (fixed + variable, excluding signature) */
        sign.data = out.data;
        sign.len  = out.len;

        if (pkp != NULL && auth_sign(pkp, kcfg->d.nid, sign, &sig) < 0)
                goto fail_sig;

        hdr->hdr = out;

        /* Append signature */
        if (sig.len > 0) {
                hdr->hdr.len += sig.len;
                hdr->hdr.data = realloc(out.data, hdr->hdr.len);
                if (hdr->hdr.data == NULL)
                        goto fail_realloc;

                memcpy(hdr->hdr.data + offset, sig.data, sig.len);
                clrbuf(out);
        }

        if (oap_hdr_decode(hdr, hdr->hdr, req_md_nid) < 0)
                goto fail_decode;

        freebuf(der);
        freebuf(sig);

        return 0;

 fail_decode:
        oap_hdr_fini(hdr);
 fail_realloc:
        freebuf(sig);
 fail_sig:
        freebuf(out);
 fail_out:
        freebuf(der);
 fail_der:
        return -1;
}

#ifdef DEBUG_PROTO_OAP
static void debug_oap_hdr(const struct oap_hdr * hdr)
{
        assert(hdr);

        if (hdr->crt.len > 0)
                log_proto("  crt: [%zu bytes]", hdr->crt.len);
        else
                log_proto("  crt: <none>");

        if (hdr->kex.len > 0)
                log_proto("  Key Exchange Data: [%zu bytes] [%s]",
                          hdr->kex.len, hdr->kex_flags.role ?
                                "Client encaps" : "Server encaps");
        else
                log_proto("  Ephemeral Public Key: <none>");

        if (hdr->cipher_str != NULL)
                log_proto("  Cipher: %s", hdr->cipher_str);
        else
                log_proto("  Cipher: <none>");

        if (hdr->kdf_str != NULL)
                log_proto("  KDF: HKDF-%s", hdr->kdf_str);
        else
                log_proto("  KDF: <none>");

        if (hdr->md_str != NULL)
                log_proto("  Digest: %s", hdr->md_str);
        else
                log_proto("  Digest: <none>");

        if (hdr->data.len > 0)
                log_proto("  Data: [%zu bytes]", hdr->data.len);
        else
                log_proto("  Data: <none>");

        if (hdr->req_hash.len > 0)
                log_proto("  Req Hash: [%zu bytes]", hdr->req_hash.len);
        else
                log_proto("  Req Hash: <none>");

        if (hdr->sig.len > 0)
                log_proto("  Signature: [%zu bytes]", hdr->sig.len);
        else
                log_proto("  Signature: <none>");
}
#endif

void debug_oap_hdr_rcv(const struct oap_hdr * hdr)
{
#ifdef DEBUG_PROTO_OAP
        struct tm *     tm;
        char            tmstr[RIB_TM_STRLEN];
        time_t          stamp;

        assert(hdr);

        stamp = (time_t) hdr->timestamp / BILLION;

        tm = gmtime(&stamp);
        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);

        log_proto("OAP_HDR [" HASH_FMT64 " @ %s ] <--",
                  HASH_VAL64(hdr->id.data), tmstr);

        debug_oap_hdr(hdr);
#else
        (void) hdr;
#endif
}

void debug_oap_hdr_snd(const struct oap_hdr * hdr)
{
#ifdef DEBUG_PROTO_OAP
        struct tm *     tm;
        char            tmstr[RIB_TM_STRLEN];
        time_t          stamp;

        assert(hdr);

        stamp = (time_t) hdr->timestamp / BILLION;

        tm = gmtime(&stamp);
        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);

        log_proto("OAP_HDR [" HASH_FMT64 " @ %s ] -->",
                  HASH_VAL64(hdr->id.data), tmstr);

        debug_oap_hdr(hdr);
#else
        (void) hdr;
#endif
}
