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

#if defined(__linux__) || defined(__CYGWIN__)
 #define _DEFAULT_SOURCE
#else
 #define _POSIX_C_SOURCE 200809L
#endif

#define OUROBOROS_PREFIX "irmd/oap"

#include <ouroboros/crypt.h>
#include <ouroboros/endian.h>
#include <ouroboros/logs.h>
#include <ouroboros/rib.h>
#include <ouroboros/time.h>

#include "config.h"

#include "oap.h"

#include <assert.h>

int oap_hdr_init(buffer_t         id,
                 void *           pkp,
                 void *           pubcrt,
                 buffer_t         ephkey,
                 buffer_t         data,
                 struct oap_hdr * oap_hdr)
{
        struct timespec now;
        uint64_t        stamp;
        buffer_t        hdr;
        buffer_t        der = BUF_INIT;
        buffer_t        sig = BUF_INIT;
        buffer_t        sign;
        uint16_t        len;
        off_t           offset;

        assert(id.data != NULL && id.len == OAP_ID_SIZE);
        assert(oap_hdr != NULL);
        memset(oap_hdr, 0, sizeof(*oap_hdr));

        clock_gettime(CLOCK_REALTIME, &now);
        stamp = hton64(TS_TO_UINT64(now));

        if (pubcrt != NULL && crypt_crt_der(pubcrt, &der) < 0)
                goto fail_der;

        hdr.len = id.len +
                sizeof(stamp) +
                sizeof(len) + der.len +
                sizeof(len) + ephkey.len +
                sizeof(len) + data.len +
                sizeof(len); /* sig len */

        hdr.data = malloc(hdr.len);
        if (hdr.data == NULL)
                goto fail_hdr;

        offset = 0;

        memcpy(hdr.data, id.data, id.len);
        offset += id.len;

        memcpy(hdr.data + offset, &stamp, sizeof(stamp));
        offset += sizeof(stamp);

        /* pubcrt */
        len = hton16((uint16_t) der.len);
        memcpy(hdr.data + offset, &len, sizeof(len));
        offset += sizeof(len);
        if (der.len != 0)
                memcpy(hdr.data + offset, der.data, der.len);
        offset += der.len;

        /* ephkey */
        len = hton16((uint16_t) ephkey.len);
        memcpy(hdr.data + offset, &len, sizeof(len));
        offset += sizeof(len);
        if (ephkey.len != 0)
                memcpy(hdr.data + offset, ephkey.data, ephkey.len);
        offset += ephkey.len;

        /* data */
        len = hton16((uint16_t) data.len);
        memcpy(hdr.data + offset, &len, sizeof(len));
        offset += sizeof(len);
        if (data.len != 0)
                memcpy(hdr.data + offset, data.data, data.len);
        offset += data.len;

        sign.data = hdr.data;
        sign.len  = hdr.len - sizeof(len);

        if (pkp != NULL && auth_sign(pkp, sign, &sig) < 0)
                goto fail_sig;

        len = hton16((uint16_t) sig.len);
        memcpy(hdr.data + offset, &len, sizeof(len));
        offset += sizeof(len);

        oap_hdr->hdr = hdr;

        assert((size_t) offset == hdr.len);

        if (sig.len > 0) {
                oap_hdr->hdr.len += sig.len;
                oap_hdr->hdr.data = realloc(hdr.data, oap_hdr->hdr.len);
                if (oap_hdr->hdr.data == NULL)
                        goto fail_oap_hdr;

                memcpy(oap_hdr->hdr.data + offset, sig.data, sig.len);
                clrbuf(hdr);
        }

        if (oap_hdr_decode(oap_hdr->hdr, oap_hdr) < 0)
                goto fail_decode;

        freebuf(der);
        freebuf(sig);

        return 0;

 fail_decode:
        oap_hdr_fini(oap_hdr);
 fail_oap_hdr:
        freebuf(sig);
 fail_sig:
        freebuf(hdr);
 fail_hdr:
        freebuf(der);
 fail_der:
        memset(oap_hdr, 0, sizeof(*oap_hdr));
        return -1;
}

void oap_hdr_fini(struct oap_hdr * oap_hdr)
{
        assert(oap_hdr != NULL);

        freebuf(oap_hdr->hdr);
        memset(oap_hdr, 0, sizeof(*oap_hdr));
}

int oap_hdr_decode(buffer_t             hdr,
                   struct oap_hdr * oap_hdr)
{
        off_t offset;

        assert(oap_hdr != NULL);
        memset(oap_hdr, 0, sizeof(*oap_hdr));

        if (hdr.len < OAP_HDR_MIN_SIZE)
                goto fail_decode;

        oap_hdr->id.data = hdr.data;
        oap_hdr->id.len  = OAP_ID_SIZE;

        offset = OAP_ID_SIZE;

        oap_hdr->timestamp = ntoh64(*(uint64_t *)(hdr.data + offset));

        offset += sizeof(uint64_t);

        oap_hdr->crt.len = (size_t) ntoh16(*(uint16_t *)(hdr.data + offset));
        oap_hdr->crt.data = hdr.data + offset + sizeof(uint16_t);

        offset += sizeof(uint16_t) + oap_hdr->crt.len;

        if ((size_t) offset + sizeof(uint16_t) >= hdr.len)
                goto fail_decode;

        oap_hdr->eph.len = (size_t) ntoh16(*(uint16_t *)(hdr.data + offset));
        oap_hdr->eph.data = hdr.data + offset + sizeof(uint16_t);

        offset += sizeof(uint16_t) + oap_hdr->eph.len;

        if ((size_t) offset + sizeof(uint16_t) >= hdr.len)
                goto fail_decode;

        oap_hdr->data.len = (size_t) ntoh16(*(uint16_t *)(hdr.data + offset));
        oap_hdr->data.data = hdr.data + offset + sizeof(uint16_t);

        offset += sizeof(uint16_t) + oap_hdr->data.len;

        if ((size_t) offset + sizeof(uint16_t) > hdr.len)
                goto fail_decode;

        oap_hdr->sig.len = (size_t) ntoh16(*(uint16_t *)(hdr.data + offset));
        oap_hdr->sig.data = hdr.data + offset + sizeof(uint16_t);

        offset += sizeof(uint16_t) + oap_hdr->sig.len;

        if ((size_t) offset != hdr.len)
                goto fail_decode;

        oap_hdr->hdr = hdr;

        return 0;

 fail_decode:
        memset(oap_hdr, 0, sizeof(*oap_hdr));
        return -1;
}

#ifdef DEBUG_PROTO_OAP
static void debug_oap_hdr(const struct oap_hdr * hdr)
{
        assert(hdr);

        if (hdr->crt.len > 0)
                log_proto("  Certificate: [%zu bytes]", hdr->crt.len);
        else
                log_proto("  Certificate: <none>");

        if (hdr->eph.len > 0)
                log_proto("  Ephemeral Public Key: [%zu bytes]", hdr->eph.len);
        else
                log_proto("  Ephemeral Public Key: <none>");
        if (hdr->data.len > 0)
                log_proto("  Data: [%zu bytes]", hdr->data.len);
        else
                log_proto("  Data: <none>");
        if (hdr->sig.len > 0)
                log_proto("  Signature: [%zu bytes]", hdr->sig.len);
        else
                log_proto("  Signature: <none>");
}

void debug_oap_hdr_rcv(const struct oap_hdr *   hdr)
{
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
}

void debug_oap_hdr_snd(const struct oap_hdr * hdr)
{
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
}
#endif

