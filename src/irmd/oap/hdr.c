/*
 * Ouroboros - Copyright (C) 2016 - 2026
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
#include <ouroboros/errno.h>
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

#define OAP_SEAL_TAGSZ 16 /* AEAD tag on the sealed identity block */
/* Sealed length prefix: data_len ‖ crt_len. */
#define OAP_SEAL_LENSZ (sizeof(uint16_t) + sizeof(uint16_t))

/* hs_key is single-use per handshake, so a fixed nonce is reuse-safe. */
static const uint8_t oap_seal_nonce[12];

int oap_hdr_decode(struct oap_hdr * oap_hdr,
                   buffer_t         hdr,
                   int              req_md_nid,
                   bool             rekey)
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

        /*
         * Validate NIDs: NID_undef is valid at parse time, else must be known.
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

        assert((size_t) offset == OAP_HDR_MIN_SIZE);

        /* Response includes rsp_tag when md_nid is set */
        hash_len = (req_md_nid != NID_undef) ?
                   (size_t) md_len(req_md_nid) : 0;

        /* Encrypted response: sealed block is data_len‖crt_len‖data‖crt‖sig. */
        if (req_md_nid != NID_undef && ciph_nid != NID_undef) {
                if (hdr.len < (size_t) offset + oap_hdr->kex.len + hash_len +
                              OAP_SEAL_TAGSZ + OAP_SEAL_LENSZ)
                        goto fail_decode;

                oap_hdr->kex.data = hdr.data + offset;
                offset += oap_hdr->kex.len;

                oap_hdr->rsp_tag.data = hdr.data + offset;
                oap_hdr->rsp_tag.len  = hash_len;
                offset += hash_len;

                oap_hdr->sealed.data = hdr.data + offset;
                oap_hdr->sealed.len  = hdr.len - offset;

                /* crt/data/sig lengths are sealed; set by oap_hdr_unseal. */
                oap_hdr->crt.len  = crt_len;
                oap_hdr->data.len = data_len;

                oap_hdr->hdr = hdr;

                return 0;
        }

        /* Validate total length */
        if (hdr.len < (size_t) offset + crt_len + oap_hdr->kex.len +
                      data_len + hash_len)
                goto fail_decode;

        /* Derive sig_len from remaining bytes */
        sig_len = hdr.len - offset - crt_len - oap_hdr->kex.len -
                  data_len - hash_len;

        /*
         * Unsigned packets must not have trailing bytes. A re-key request
         * is signed but cert-less (verified against the cached peer cert),
         * so the rekey caller permits crt_len==0 with a signature.
         */
        if (crt_len == 0 && sig_len != 0 && !rekey)
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

        oap_hdr->rsp_tag.data = hdr.data + offset;
        oap_hdr->rsp_tag.len = hash_len;
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

        freebuf(oap_hdr->sealed_pt);
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

/* Write the 36-byte fixed header; stamp is already in network order. */
static void write_oap_fixed(uint8_t *                 buf,
                            const struct oap_hdr *    hdr,
                            const struct sec_config * kcfg,
                            size_t                    crt_len,
                            size_t                    data_len,
                            uint64_t                  stamp)
{
        uint16_t v;
        uint16_t kex_len;
        off_t    offset = 0;

        memcpy(buf + offset, hdr->id.data, hdr->id.len);
        offset += hdr->id.len;

        memcpy(buf + offset, &stamp, sizeof(stamp));
        offset += sizeof(stamp);

        v = hton16(hdr->nid);
        memcpy(buf + offset, &v, sizeof(v));
        offset += sizeof(v);

        v = hton16(kcfg->k.nid);
        memcpy(buf + offset, &v, sizeof(v));
        offset += sizeof(v);

        v = hton16(kcfg->d.nid);
        memcpy(buf + offset, &v, sizeof(v));
        offset += sizeof(v);

        v = hton16((uint16_t) crt_len);
        memcpy(buf + offset, &v, sizeof(v));
        offset += sizeof(v);

        kex_len = (uint16_t) hdr->kex.len;
        if (hdr->kex.len > 0 && IS_KEM_ALGORITHM(kcfg->x.str)) {
                if (IS_HYBRID_KEM(kcfg->x.str))
                        kex_len |= OAP_KEX_FMT_BIT;
                if (kcfg->x.mode == KEM_MODE_CLIENT_ENCAP)
                        kex_len |= OAP_KEX_ROLE_BIT;
        }

        kex_len = hton16(kex_len);
        memcpy(buf + offset, &kex_len, sizeof(kex_len));
        offset += sizeof(kex_len);

        v = hton16((uint16_t) data_len);
        memcpy(buf + offset, &v, sizeof(v));
}

/*
 * Pack lens ‖ data ‖ crt, sign prefix ‖ body, append the signature, then
 * AEAD-seal lens ‖ data ‖ crt ‖ sig under prefix as AAD. The cert, app data
 * and their sizes stay confidential; *out is the opaque sealed block. The
 * signature rides inside the seal so it can't deanonymise the server.
 */
static int oap_seal_body(int             nid,
                         const uint8_t * seal_key,
                         void *          pkp,
                         int             md_nid,
                         buffer_t        prefix,
                         buffer_t        data,
                         buffer_t        crt,
                         buffer_t *      out)
{
        buffer_t  sig = BUF_INIT;
        buffer_t  sign;
        buffer_t  aad;
        buffer_t  plain;
        uint8_t * buf;
        uint8_t * tmp;
        uint16_t  datalen;
        uint16_t  crtlen;
        size_t    body_len;
        off_t     offset;

        datalen = hton16((uint16_t) data.len);
        crtlen  = hton16((uint16_t) crt.len);

        body_len = OAP_SEAL_LENSZ + data.len + crt.len;

        buf = malloc(prefix.len + body_len);
        if (buf == NULL)
                return -1;

        memcpy(buf, prefix.data, prefix.len);
        offset = (off_t) prefix.len;

        memcpy(buf + offset, &datalen, sizeof(datalen));
        offset += sizeof(datalen);

        memcpy(buf + offset, &crtlen, sizeof(crtlen));
        offset += sizeof(crtlen);

        if (data.len != 0)
                memcpy(buf + offset, data.data, data.len);

        offset += data.len;

        if (crt.len != 0)
                memcpy(buf + offset, crt.data, crt.len);

        /* Sign prefix ‖ lens ‖ data ‖ crt (plaintext, before sealing). */
        sign.data = buf;
        sign.len  = prefix.len + body_len;

        if (pkp != NULL && auth_sign(pkp, md_nid, sign, &sig) < 0)
                goto fail_buf;

        /* Append the signature so the seal covers lens ‖ data ‖ crt ‖ sig. */
        if (sig.len != 0) {
                tmp = realloc(buf, prefix.len + body_len + sig.len);
                if (tmp == NULL)
                        goto fail_sig;

                buf = tmp;
                memcpy(buf + prefix.len + body_len, sig.data, sig.len);
        }

        aad.data   = buf;
        aad.len    = prefix.len;
        plain.data = buf + prefix.len;
        plain.len  = body_len + sig.len;

        if (crypt_oneshot_seal(nid, seal_key, oap_seal_nonce,
                               aad, plain, out) < 0)
                goto fail_sig;

        free(buf);
        freebuf(sig);

        return 0;

 fail_sig:
        freebuf(sig);
 fail_buf:
        free(buf);
        return -1;
}

/* Encode an identity-hidden response: wire = prefix ‖ oap_seal_body(...). */
static int oap_hdr_encode_sealed(struct oap_hdr *    hdr,
                                 void *              pkp,
                                 void *              crt,
                                 struct sec_config * kcfg,
                                 buffer_t            rsp_tag,
                                 int                 req_md_nid,
                                 const uint8_t *     seal_key)
{
        struct timespec now;
        uint64_t        stamp;
        buffer_t        der    = BUF_INIT;
        buffer_t        sealed = BUF_INIT;
        buffer_t        prefix;
        off_t           offset;

        clock_gettime(CLOCK_REALTIME, &now);
        stamp = hton64(TS_TO_UINT64(now));

        if (crt != NULL && crypt_crt_der(crt, &der) < 0)
                goto fail_der;

        prefix.len  = OAP_HDR_MIN_SIZE + hdr->kex.len + rsp_tag.len;
        prefix.data = malloc(prefix.len);
        if (prefix.data == NULL)
                goto fail_der;

        /* Cleartext crt_len/data_len are 0; real lengths prefix the seal. */
        write_oap_fixed(prefix.data, hdr, kcfg, 0, 0, stamp);
        offset = OAP_HDR_MIN_SIZE;

        if (hdr->kex.len != 0)
                memcpy(prefix.data + offset, hdr->kex.data, hdr->kex.len);

        offset += hdr->kex.len;

        if (rsp_tag.len != 0)
                memcpy(prefix.data + offset, rsp_tag.data, rsp_tag.len);

        offset += rsp_tag.len;

        assert((size_t) offset == prefix.len);

        if (oap_seal_body(hdr->nid, seal_key, pkp, kcfg->d.nid,
                          prefix, hdr->data, der, &sealed) < 0)
                goto fail_prefix;

        hdr->hdr.len  = prefix.len + sealed.len;
        hdr->hdr.data = malloc(hdr->hdr.len);
        if (hdr->hdr.data == NULL)
                goto fail_sealed;

        memcpy(hdr->hdr.data, prefix.data, prefix.len);
        memcpy(hdr->hdr.data + prefix.len, sealed.data, sealed.len);

        freebuf(sealed);
        free(prefix.data);
        freebuf(der);

        if (oap_hdr_decode(hdr, hdr->hdr, req_md_nid, false) < 0)
                goto fail_decode;

        return 0;

 fail_decode:
        oap_hdr_fini(hdr);
        return -1;
 fail_sealed:
        freebuf(sealed);
 fail_prefix:
        free(prefix.data);
 fail_der:
        freebuf(der);
        return -1;
}

int oap_hdr_encode(struct oap_hdr *    hdr,
                   void *              pkp,
                   void *              crt,
                   struct sec_config * kcfg,
                   buffer_t            rsp_tag,
                   int                 req_md_nid,
                   const uint8_t *     seal_key)
{
        struct timespec now;
        uint64_t        stamp;
        buffer_t        out;
        buffer_t        der = BUF_INIT;
        buffer_t        sig = BUF_INIT;
        buffer_t        sign;
        off_t           offset;

        assert(hdr != NULL);
        assert(hdr->id.data != NULL && hdr->id.len == OAP_ID_SIZE);
        assert(kcfg != NULL);

        if (seal_key != NULL)
                return oap_hdr_encode_sealed(hdr, pkp, crt, kcfg, rsp_tag,
                                             req_md_nid, seal_key);

        clock_gettime(CLOCK_REALTIME, &now);
        stamp = hton64(TS_TO_UINT64(now));

        if (crt != NULL && crypt_crt_der(crt, &der) < 0)
                goto fail_der;

        /* Fixed header (36 bytes) + variable fields + rsp_tag (rsp only) */
        out.len = OAP_HDR_MIN_SIZE + der.len + hdr->kex.len + hdr->data.len +
                  rsp_tag.len;

        out.data = malloc(out.len);
        if (out.data == NULL)
                goto fail_out;

        write_oap_fixed(out.data, hdr, kcfg, der.len, hdr->data.len, stamp);
        offset = OAP_HDR_MIN_SIZE;

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

        /* rsp_tag (variable, response only) */
        if (rsp_tag.len != 0)
                memcpy(out.data + offset, rsp_tag.data, rsp_tag.len);

        offset += rsp_tag.len;

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

        if (oap_hdr_decode(hdr, hdr->hdr, req_md_nid, false) < 0)
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

int oap_hdr_unseal(struct oap_hdr * hdr,
                   const uint8_t *  key)
{
        buffer_t  pt = BUF_INIT;
        buffer_t  prefix;
        uint8_t * recon;
        size_t    body_len;
        size_t    pt_len;
        size_t    data_len;
        size_t    crt_len;

        assert(hdr != NULL);
        assert(key != NULL);

        if (hdr->sealed.data == NULL || hdr->sealed.len == 0)
                return -EINVAL;

        /* AAD prefix is fixed‖kex‖rsp_tag; sealed starts right after. */
        prefix.data = hdr->hdr.data;
        prefix.len  = (size_t) (hdr->sealed.data - hdr->hdr.data);

        if (crypt_oneshot_open(hdr->nid, key, oap_seal_nonce, prefix,
                               hdr->sealed, &pt) < 0)
                return -ECRYPT;

        pt_len = pt.len;

        /* Plaintext = data_len ‖ crt_len ‖ data ‖ crt ‖ sig. */
        if (pt_len < OAP_SEAL_LENSZ)
                goto fail_auth;

        data_len = (size_t) ntoh16(*(uint16_t *) pt.data);
        crt_len  = (size_t) ntoh16(*(uint16_t *)(pt.data + sizeof(uint16_t)));

        body_len = OAP_SEAL_LENSZ + data_len + crt_len;
        if (pt_len < body_len)
                goto fail_auth;

        /* Rebuild prefix ‖ lens ‖ data ‖ crt ‖ sig (whole signed region). */
        recon = malloc(prefix.len + pt_len);
        if (recon == NULL)
                goto fail_mem;

        memcpy(recon, prefix.data, prefix.len);
        memcpy(recon + prefix.len, pt.data, pt_len);

        freebuf(pt);

        hdr->sealed_pt.data = recon;
        hdr->sealed_pt.len  = prefix.len + pt_len;

        hdr->data.data = recon + prefix.len + OAP_SEAL_LENSZ;
        hdr->data.len  = data_len;
        hdr->crt.data  = recon + prefix.len + OAP_SEAL_LENSZ + data_len;
        hdr->crt.len   = crt_len;
        hdr->sig.data  = recon + prefix.len + body_len;
        hdr->sig.len   = pt_len - body_len;

        return 0;

 fail_mem:
        freebuf(pt);
        return -ENOMEM;
 fail_auth:
        freebuf(pt);
        return -EAUTH;
}

#ifdef DEBUG_PROTO_OAP
#define OAP_KEX_IS_KEM(hdr) ((hdr)->kex_flags.role | (hdr)->kex_flags.fmt)
static void debug_oap_hdr(const struct oap_hdr * hdr)
{
        assert(hdr);

        if (hdr->sealed.len > 0)
                log_proto("  Sealed block: [%zu bytes] on wire",
                          hdr->sealed.len);

        if (hdr->crt.len > 0)
                log_proto("  crt: [%zu bytes]", hdr->crt.len);
        else if (hdr->sealed.len > 0)
                log_proto("  crt: <sealed>");
        else
                log_proto("  crt: <none>");

        if (hdr->kex.len > 0) {
                if (OAP_KEX_IS_KEM(hdr))
                        log_proto("  Key Exchange Data: [%zu bytes] [%s]",
                                  hdr->kex.len,
                                  hdr->kex_flags.role ?
                                  "Client encaps" : "Server encaps");
                else
                        log_proto("  Key Exchange Data: [%zu bytes]",
                                  hdr->kex.len);
        } else
                log_proto("  Key Exchange Data: <none>");

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
        else if (hdr->sealed.len > 0)
                log_proto("  Data: <sealed>");
        else
                log_proto("  Data: <none>");

        if (hdr->rsp_tag.len > 0)
                log_proto("  Rsp Tag: [%zu bytes]", hdr->rsp_tag.len);
        else
                log_proto("  Rsp Tag: <none>");

        if (hdr->sig.len > 0)
                log_proto("  Signature: [%zu bytes]", hdr->sig.len);
        else if (hdr->sealed.len > 0)
                log_proto("  Signature: <sealed>");
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

        log_proto("OAP_HDR [" HASH_FMT64 " @ %s ]%s <--",
                  HASH_VAL64(hdr->id.data), tmstr,
                  hdr->sealed.len > 0 ? " [sealed]" : "");

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

        log_proto("OAP_HDR [" HASH_FMT64 " @ %s ]%s -->",
                  HASH_VAL64(hdr->id.data), tmstr,
                  hdr->sealed.len > 0 ? " [sealed]" : "");

        debug_oap_hdr(hdr);
#else
        (void) hdr;
#endif
}
