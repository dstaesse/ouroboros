/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Points of attachment (PoA) - addresses and management messages
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

#if defined(__linux__) || defined(__CYGWIN__)
#ifndef _DEFAULT_SOURCE /* Test include source */
#define _DEFAULT_SOURCE
#endif
#endif

#include "config.h"

#include <ouroboros/endian.h>
#include <ouroboros/errno.h>

#include "poa.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int poa_addr_cmp(const struct poa_addr * a,
                 const struct poa_addr * b)
{
        if (a->type != b->type)
                return 1;

        switch (a->type) {
        case POA_UDP4:
                if (a->udp4.port != b->udp4.port)
                        return 1;
                return memcmp(&a->udp4.ip_addr, &b->udp4.ip_addr,
                              sizeof(a->udp4.ip_addr));
        case POA_UDP6:
                if (a->udp6.port != b->udp6.port)
                        return 1;
                return memcmp(&a->udp6.ip_addr, &b->udp6.ip_addr,
                              sizeof(a->udp6.ip_addr));
        case POA_ETH:
                if (a->eth.dst.ethertype != b->eth.dst.ethertype)
                        return 1;
                return memcmp(a->eth.dst.mac, b->eth.dst.mac, POA_MAC_SIZE);
        default:
                return 1;
        }
}

/* Display/RIB entry name, e.g. "udp4.<ip>.<port>". */
int poa_addr_name(const struct poa_addr * a,
                  char *                  buf,
                  size_t                  len)
{
        char ip[INET6_ADDRSTRLEN];
        int  ret;

        switch (a->type) {
        case POA_UDP4:
                if (inet_ntop(AF_INET, &a->udp4.ip_addr,
                              ip, sizeof(ip)) == NULL)
                        return -EINVAL;
                ret = snprintf(buf, len, "udp4.%s.%u", ip, a->udp4.port);
                break;
        case POA_UDP6:
                if (inet_ntop(AF_INET6, &a->udp6.ip_addr,
                              ip, sizeof(ip)) == NULL)
                        return -EINVAL;
                ret = snprintf(buf, len, "udp6.%s.%u", ip, a->udp6.port);
                break;
        case POA_ETH:
                ret = snprintf(buf, len, "eth.%s.%04X",
                               a->eth.src.dev, a->eth.src.ethertype);
                break;
        default:
                return -EINVAL;
        }

        if (ret < 0 || (size_t) ret >= len)
                return -EMSGSIZE;

        return 0;
}

void poa_mgmt_msg_ser(struct poa_mgmt_msg * msg,
                      uint8_t               code,
                      uint32_t              s_eid,
                      uint32_t              d_eid,
                      qosspec_t             qs,
                      int                   response,
                      size_t                data_len)
{
        memset(msg, 0, sizeof(*msg));

        msg->code         = code;
        msg->s_eid        = hton32(s_eid);
        msg->d_eid        = hton32(d_eid);
        msg->response     = hton32(response);
        msg->data_len     = hton16((uint16_t) data_len);

        if (code != POA_FLOW_REQ)
                return;

        msg->bandwidth    = hton64(qs.bandwidth);
        msg->delay        = hton32(qs.delay);
        msg->loss         = hton32(qs.loss);
        msg->ber          = hton32(qs.ber);
        msg->max_gap      = hton32(qs.max_gap);
        msg->timeout      = hton32(qs.timeout);
        msg->availability = qs.availability;
        msg->service      = qs.service;
}

void poa_mgmt_msg_qos(const struct poa_mgmt_msg * msg,
                      qosspec_t *                 qs)
{
        qs->bandwidth    = ntoh64(msg->bandwidth);
        qs->delay        = ntoh32(msg->delay);
        qs->loss         = ntoh32(msg->loss);
        qs->ber          = ntoh32(msg->ber);
        qs->max_gap      = ntoh32(msg->max_gap);
        qs->timeout      = ntoh32(msg->timeout);
        qs->availability = msg->availability;
        qs->service      = msg->service;
}

