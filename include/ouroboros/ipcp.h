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

/* Normal IPCP policies */
enum pol_addr_auth {
        FLAT_RANDOM = 0
};

enum pol_gam {
        COMPLETE = 0
};

enum pol_routing {
        LINK_STATE = 0
};

enum pol_dir_hash {
        DIR_HASH_SHA3_224 = 0,
        DIR_HASH_SHA3_256,
        DIR_HASH_SHA3_384,
        DIR_HASH_SHA3_512
};

#define DIF_NAME_SIZE 256

/* Info reported back to the IRMd about the DIF on enrollment */
struct dif_info {
        char dif_name[DIF_NAME_SIZE];
        int  dir_hash_algo;
};

/* Structure to configure the first IPCP */
struct ipcp_config {
        struct dif_info    dif_info;

        enum ipcp_type     type;

        /* Normal */
        uint8_t            addr_size;
        uint8_t            fd_size;
        bool               has_ttl;

        enum pol_addr_auth addr_auth_type;
        enum pol_gam       dt_gam_type;
        enum pol_gam       rm_gam_type;
        enum pol_routing   routing_type;

        /* Shim UDP */
        uint32_t           ip_addr;
        uint32_t           dns_addr;

        /* Shim Ethernet LLC */
        char *             if_name;
};

#endif /* OUROBOROS_IPCP_H */
