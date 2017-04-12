/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * IPCP definitions and policies
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_IPCP_H
#define OUROBOROS_IPCP_H

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

/*
 * NOTE: the IRMd uses this order to select an IPCP
 * for flow allocation
 */
enum ipcp_type {
        IPCP_LOCAL = 0,
        IPCP_SHIM_ETH_LLC,
        IPCP_SHIM_UDP,
        IPCP_NORMAL
};

/* IPCP policies */
enum pol_addr_auth {
        FLAT_RANDOM = 0
};

enum pol_gam {
        COMPLETE = 0
};

struct ipcp_config {
        char *             dif_name;
        enum ipcp_type     type;
        uint16_t           dir_hash_len;

        /* Normal DIF */
        uint8_t            addr_size;
        uint8_t            cep_id_size;
        uint8_t            pdu_length_size;
        uint8_t            seqno_size;

        bool               has_ttl;
        bool               has_chk;

        uint32_t           min_pdu_size;
        uint32_t           max_pdu_size;

        enum pol_addr_auth addr_auth_type;
        enum pol_gam       dt_gam_type;
        enum pol_gam       rm_gam_type;

        /* Shim UDP */
        uint32_t           ip_addr;
        uint32_t           dns_addr;

        /* Shim Ethernet LLC */
        char *             if_name;
};

#endif /* OUROBOROS_IPCP_H */
