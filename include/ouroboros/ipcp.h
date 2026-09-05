/*
 * Ouroboros - Copyright (C) 2016 - 2026
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
#include <netinet/in.h>
#include <sys/types.h>

#define IPCP_NAME_SIZE  255
#define LAYER_NAME_SIZE 255
#define DEV_NAME_SIZE   255

/* TODO: Move state to ipcpd/ipcp.h, requires small change to reg/ipcp.c */
enum ipcp_state {
        IPCP_NULL = 0,
        IPCP_INIT,
        IPCP_BOOT,
        IPCP_BOOTSTRAPPED,
        IPCP_ENROLLED,
        IPCP_OPERATIONAL,
        IPCP_SHUTDOWN
};

enum ipcp_type { /* IRMd uses order to select an IPCP for flow allocation. */
        IPCP_LOCAL = 0,
        IPCP_UNICAST,
        IPCP_BROADCAST,
        IPCP_INVALID
};

/* The medium a PoA sits on. */
enum poa_type {
        POA_UDP4 = 0,
        POA_UDP6,
        /* A name to resolve; the family is DNS's pick. Port in udp4. */
        POA_UDP,
        POA_ETH,
        POA_INVALID
};

/* IPCP flags, settable at creation and at runtime. */
#define IPCP_FLAG_TRANSIT 0x00000001 /* Forward for others */
#define IPCP_FLAGS_ALL    (IPCP_FLAG_TRANSIT)

struct ipcp_info {
        enum ipcp_type  type;
        pid_t           pid;
        char            name[IPCP_NAME_SIZE + 1];
        enum ipcp_state state; /* TODO: remove. */
        uint32_t        flags;
};

/* Unicast IPCP components. */
#define DT_COMP   "Data Transfer"
#define MGMT_COMP "Management"

/* Unicast IPCP policies */
enum pol_addr_auth {
        ADDR_AUTH_FLAT_RANDOM = 0,
        ADDR_AUTH_INVALID
};

enum pol_link_state {
        LS_SIMPLE = 0,
        LS_LFA,
        LS_ECMP,
        LS_INVALID
};

struct ls_config {
        enum pol_link_state pol;      /* Link state policy           */
        time_t              t_recalc; /* Time to recalculate PFF (s) */
        time_t              t_update; /* Time between updates (s)    */
        time_t              t_timeo;  /* Link timeout (s)            */
};

static const struct ls_config default_ls_config = {
        .pol      = LS_SIMPLE,
        .t_recalc = 4,
        .t_update = 15,
        .t_timeo  = 60
};

enum pol_routing {
        ROUTING_LINK_STATE = 0,
        ROUTING_INVALID
};

struct routing_config {
        enum pol_routing pol;             /* Routing policy     */
        union {
                struct ls_config ls;      /* Link state config  */
                /* struct pv_config pv */ /* Path vector config */
        };
};

static const struct routing_config default_routing_config = {
        .pol = ROUTING_LINK_STATE,
        .ls = {
                .pol      = LS_SIMPLE,
                .t_recalc = 4,
                .t_update = 15,
                .t_timeo  = 60
        }
};

enum pol_cong_avoid {
        CA_NONE = 0,
        CA_MB_ECN,
        CA_INVALID
};

struct dt_config {
        struct {
                uint8_t  addr_size;
                uint8_t  eid_size;
                uint8_t  max_ttl;
                uint16_t max_rtt; /* Declared max layer RTT (ms)       */
        };
        struct routing_config routing; /* Routing policy */
};

static const struct dt_config default_dt_config = {
        .addr_size = 4,
        .eid_size  = 8,
        .max_ttl   = 60,
        .max_rtt   = 200,
        .routing = {
                .pol = ROUTING_LINK_STATE,
                .ls = {
                        .pol = LS_SIMPLE,
                        .t_recalc = 4,
                        .t_update = 15,
                        .t_timeo  = 60
                }
        }
};

enum pol_dir {
        DIR_DHT = 0,
        DIR_INVALID
};

enum pol_dir_hash {
        DIR_HASH_SHA3_224,
        DIR_HASH_SHA3_256,
        DIR_HASH_SHA3_384,
        DIR_HASH_SHA3_512,
        DIR_HASH_INVALID
};

enum dir_dht_config_limits {
        DHT_ALPHA_MIN       = 1,
        DHT_K_MIN           = 1,
        DHT_T_EXPIRE_MIN    = 10,
        DHT_T_REFRESH_MIN   = 3,
        DHT_T_REPLICATE_MIN = 3,

        DHT_ALPHA_MAX       = 10,
        DHT_K_MAX           = 20,
        DHT_T_EXPIRE_MAX    = 86400,
        DHT_T_REFRESH_MAX   = 3600,
        DHT_T_REPLICATE_MAX = 3600,
};

struct dir_dht_config {
        struct {
                uint32_t alpha;       /* Parallel search factor */
                uint32_t k;           /* Replication factor     */
                uint32_t t_expire;    /* Expire time (s)        */
                uint32_t t_refresh;   /* Refresh time (s)       */
                uint32_t t_replicate; /* Replication time (s)   */
        } params;
        uint64_t peer;                /* Initial peer address   */
};

static const struct dir_dht_config default_dht_config = {
        .params = {
                .alpha       = 3,     /* Proven optimal value   */
                .k           = 8,     /* MDHT value             */
                .t_expire    = 86400, /* Expire after 1 day     */
                .t_refresh   = 900,   /* MDHT value.            */
                .t_replicate = 900    /* MDHT value.            */
        }
};

/* TODO: Move hash algorithm in directory config */
struct dir_config {
        enum pol_dir pol;
        union {
                struct dir_dht_config dht;
        };
};

static const struct dir_config default_dir_config = {
        .pol = DIR_DHT,
        .dht = {
                .params = {
                        .alpha       = 3,
                        .k           = 8,
                        .t_expire    = 86400,
                        .t_refresh   = 900,
                        .t_replicate = 900
                }
        }
};

/* IPCP configuration */
struct uni_config {
        struct dt_config    dt;
        struct dir_config   dir;
        enum pol_addr_auth  addr_auth_type;
        enum pol_cong_avoid cong_avoid;
};

static const struct uni_config default_uni_config = {
        .dt = {
                .addr_size    = 4,
                .eid_size     = 8,
                .max_ttl      = 60,
                .routing = {
                        .pol = ROUTING_LINK_STATE,
                        .ls = {
                                .pol = LS_SIMPLE,
                                .t_recalc = 4,
                                .t_update = 15,
                                .t_timeo  = 60
                        }
                }
        },
        .dir = {
                .pol = DIR_DHT,
                .dht = {
                        .params = {
                                .alpha       = 3,
                                .k           = 8,
                                .t_expire    = 86400,
                                .t_refresh   = 900,
                                .t_replicate = 900
                        }
                }
        },
        .addr_auth_type = ADDR_AUTH_FLAT_RANDOM,
        .cong_avoid     = CA_MB_ECN
};

#define POA_UDP_PORT     3435   /* default UDP PoA port */
#define POA_ETHERTYPE    0xA000 /* default Ethertype        */
#define POA_MAC_SIZE     6
#define POA_HOST_STRLEN  255

struct eth_poa {
        char     dev[DEV_NAME_SIZE + 1];
        uint16_t ethertype;
        uint8_t  mac[POA_MAC_SIZE];
};

struct udp4_poa {
        struct in_addr ip_addr;
        uint16_t       port;
};

struct udp6_poa {
        struct in6_addr ip_addr;
        uint16_t        port;
};

/* PoA a unicast or broadcast IPCP attaches to. */
struct poa_spec {
        enum poa_type type;
        union {
                struct udp4_poa udp4;
                struct udp6_poa udp6;
                struct eth_poa  eth;
        };
};


/* Peer PoA to connect to. */
struct poa_addr {
        enum poa_type type;
        char          hostname[POA_HOST_STRLEN + 1]; /* resolved by IRMd */
        union {
                struct udp4_poa udp4;
                struct udp6_poa udp6;
                struct {
                        struct eth_poa src;
                        struct eth_poa dst;
                } eth;
        };
};

/* Layers */
struct layer_info {
        char              name[LAYER_NAME_SIZE + 1];
        /* TODO: Move this to directory info ? */
        enum pol_dir_hash dir_hash_algo;
};

/* Structure to configure the first IPCP */
struct ipcp_config {
        struct layer_info layer_info;
        enum ipcp_type    type;

        struct uni_config unicast;
};

/* default configurations */
static const struct ipcp_config local_default_conf = {
        .layer_info = {
                .dir_hash_algo = DIR_HASH_SHA3_256
        },
        .type = IPCP_LOCAL
};

static const struct ipcp_config uni_default_conf = {
        .layer_info = {
                .dir_hash_algo = DIR_HASH_SHA3_256
        },
        .type = IPCP_UNICAST,
        .unicast = {
                .dt = {
                        .addr_size = 4,
                        .eid_size  = 8,
                        .max_ttl   = 60,
                        .routing = {
                                .pol = ROUTING_LINK_STATE,
                                .ls = {
                                        .pol      = LS_SIMPLE,
                                        .t_recalc = 4,
                                        .t_update = 15,
                                        .t_timeo  = 60
                                }
                        }
                },
                .dir = {
                        .pol = DIR_DHT,
                        .dht = {
                                .params = {
                                        .alpha       = 3,
                                        .k           = 8,
                                        .t_expire    = 86400,
                                        .t_refresh   = 900,
                                        .t_replicate = 900
                                }
                        }
                },
                .addr_auth_type = ADDR_AUTH_FLAT_RANDOM,
                .cong_avoid     = CA_MB_ECN
        }
};

static const struct ipcp_config bc_default_conf = {
        .type = IPCP_BROADCAST
};

#endif /* OUROBOROS_IPCP_H */
