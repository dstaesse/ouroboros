/*
 * Ouroboros - Copyright (C) 2016 - 2023
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
#define DEV_NAME_SIZE   255

/* Unicast IPCP components. */
#define DT_COMP   "Data Transfer"
#define MGMT_COMP "Management"

/* NOTE: The IRMd uses this order to select an IPCP for flow allocation. */
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
        ADDR_AUTH_FLAT_RANDOM = 0,
        ADDR_AUTH_INVALID
};

enum pol_routing {
        ROUTING_LINK_STATE = 0,
        ROUTING_LINK_STATE_LFA,
        ROUTING_LINK_STATE_ECMP,
        ROUTING_INVALID
};

enum pol_cong_avoid {
        CA_NONE = 0,
        CA_MB_ECN,
        CA_INVALID
};

enum pol_dir_hash {
        DIR_HASH_SHA3_224,
        DIR_HASH_SHA3_256,
        DIR_HASH_SHA3_384,
        DIR_HASH_SHA3_512,
        DIR_HASH_INVALID
};

struct dt_config {
        uint8_t          addr_size;
        uint8_t          eid_size;
        uint8_t          max_ttl;
        enum pol_routing routing_type;
};

/* IPCP configuration */
struct uni_config {
        struct dt_config    dt;
        enum pol_addr_auth  addr_auth_type;
        enum pol_cong_avoid cong_avoid;
};

struct eth_config {
        char     dev[DEV_NAME_SIZE + 1];
        uint16_t ethertype; /* DIX only*/
};

struct udp_config {
        uint32_t ip_addr;
        uint32_t dns_addr;
        uint16_t port;
};

/* Info reported back to the IRMd about the layer on enrollment */
struct layer_info {
        char name[LAYER_NAME_SIZE + 1];
        int  dir_hash_algo;
};

/* Structure to configure the first IPCP */
struct ipcp_config {
        struct layer_info layer_info;
        enum ipcp_type    type;

        union {
                struct uni_config unicast;
                struct udp_config udp;
                struct eth_config eth;
        };
};

/* default configurations */
static const struct ipcp_config local_default_conf = {
        .type = IPCP_LOCAL,
        .layer_info = {
                .dir_hash_algo = DIR_HASH_SHA3_256
        }
};

static const struct ipcp_config eth_dix_default_conf = {
        .type = IPCP_ETH_DIX,
        .layer_info = {
                .dir_hash_algo = DIR_HASH_SHA3_256
        },
        .eth = {
             .ethertype=0xA000,
        }
};

static const struct ipcp_config eth_llc_default_conf = {
        .type = IPCP_ETH_LLC,
        .layer_info = {
                .dir_hash_algo = DIR_HASH_SHA3_256
        }
};

static const struct ipcp_config udp_default_conf = {
        .type = IPCP_UDP,
        .udp = {
                .port = 3435
        }
};

static const struct ipcp_config uni_default_conf = {
        .type = IPCP_UNICAST,
        .layer_info = {
                .dir_hash_algo = DIR_HASH_SHA3_256
        },
        .unicast = {
                .dt = {
                        .addr_size    = 4,
                        .eid_size     = 8,
                        .max_ttl      = 6,
                        .routing_type = ROUTING_LINK_STATE
                },
                .addr_auth_type = ADDR_AUTH_FLAT_RANDOM,
                .cong_avoid     = CA_MB_ECN
        }
};

static const struct ipcp_config bc_default_conf = {
        .type = IPCP_BROADCAST
};

#endif /* OUROBOROS_IPCP_H */
