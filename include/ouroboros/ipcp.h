/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * IPCP definitions and policies
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

#ifndef OUROBOROS_IPCP_H
#define OUROBOROS_IPCP_H

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

#define LAYER_NAME_SIZE 255

/*
 * NOTE: the IRMd uses this order to select an IPCP
 * for flow allocation.
 */
enum ipcp_type {
        IPCP_LOCAL = 0,
        IPCP_UNICAST,
        IPCP_BROADCAST,
        IPCP_ETH_LLC,
        IPCP_ETH_DIX,
        IPCP_UDP,
        IPCP_INVALID
};

/* Unicast IPCP policies */
enum pol_addr_auth {
        ADDR_AUTH_FLAT_RANDOM = 0
};

enum pol_routing {
        ROUTING_LINK_STATE = 0,
        ROUTING_LINK_STATE_LFA,
        ROUTING_LINK_STATE_ECMP
};

enum pol_cong_avoid {
        CA_NONE = 0,
        CA_MB_ECN
};

enum pol_dir_hash {
        DIR_HASH_SHA3_224 = 0,
        DIR_HASH_SHA3_256,
        DIR_HASH_SHA3_384,
        DIR_HASH_SHA3_512
};

/* Info reported back to the IRMd about the layer on enrollment */
struct layer_info {
        char layer_name[LAYER_NAME_SIZE + 1];
        int  dir_hash_algo;
};

/* Structure to configure the first IPCP */
struct ipcp_config {
        struct layer_info   layer_info;

        enum ipcp_type      type;

        /* Unicast */
        uint8_t             addr_size;
        uint8_t             eid_size;
        uint8_t             max_ttl;

        enum pol_addr_auth  addr_auth_type;
        enum pol_routing    routing_type;
        enum pol_cong_avoid cong_avoid;

        /* UDP */
        uint32_t            ip_addr;
        uint32_t            dns_addr;
        uint16_t            port;

        /* Ethernet */
        char *              dev;

        /* Ethernet DIX */
        uint16_t            ethertype;
};

#endif /* OUROBOROS_IPCP_H */
