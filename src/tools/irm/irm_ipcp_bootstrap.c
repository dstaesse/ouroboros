/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Bootstrap IPC Processes
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#endif

#define UNICAST        "unicast"
#define BROADCAST      "broadcast"
#define IP_UDP         "udp"
#define ETH_LLC        "eth-llc"
#define ETH_DIX        "eth-dix"
#define LOCAL          "local"

#define MD5            "MD5"
#define SHA3_224       "SHA3_224"
#define SHA3_256       "SHA3_256"
#define SHA3_384       "SHA3_384"
#define SHA3_512       "SHA3_512"

#define FLAT_RANDOM    "flat"
#define DHT_DIR        "DHT"
#define LINK_STATE     "link_state"
#define LINK_STATE_LFA "lfa"
#define LINK_STATE_ECM "ecmp"
#define NONE_CA        "none"
#define MB_ECN_CA      "mb-ecn"

#define DT(x)  default_dt_config.x
#define DHT(x) default_dht_config.params.x
#define UNI(x) default_uni_config.x
#define DIX(x) eth_dix_default_conf.eth.x
#define LLC(x) eth_llc_default_conf.eth.x
#define UDP(x) udp_default_conf.udp.x

static char * usage_str = \
        "Usage: irm ipcp bootstrap\n"
        "           name <ipcp name>\n"
        "           layer <layer name>\n"
        "           [type [TYPE]]\n"
        "where TYPE in {" UNICAST " " BROADCAST " " LOCAL " "
        IP_UDP " " ETH_LLC " " ETH_DIX "},\n\n"
        "if TYPE == " UNICAST "\n"
        "        [addr_auth <ADDRESS_POLICY> (default: %s)]\n"
        "        [directory <DIRECTORY_POLICY> (default: %s)]\n"
        "        [hash [ALGORITHM] (default: %s)]\n"
        "        [routing <ROUTING_POLICY> (default: %s)]\n"
        "        [congestion <CONG_POLICY> (default: %s)]\n"
        "        [autobind]\n"
        "where ADDRESS_POLICY in {" FLAT_RANDOM "}\n"
        "    DIRECTORY_POLICY in {" DHT_DIR "}\n"
        "    ALGORITHM in {" SHA3_224 " " SHA3_256 " "
        SHA3_384 " " SHA3_512 "}\n\n"
        "    ROUTING_POLICY in {" LINK_STATE " "
        LINK_STATE_LFA " " LINK_STATE_ECM "}\n"
        "    CONG_POLICY in {" NONE_CA " " MB_ECN_CA "}\n"
        "    [Data Transfer Constants]\n"
        "        [addr <address size> (default: %d)]\n"
        "        [eid <eid size> (default: %d)]\n"
        "        [ttl <max time-to-live>, default: %d)]\n"
        "if DIRECTORY_POLICY == " DHT_DIR "\n"
        "        [dht_alpha <search factor> (default: %u)]\n"
        "        [dht_k <replication factor> (default: %u)]\n"
        "        [dht_t_expire <expiration (s)> (default: %u)]\n"
        "        [dht_t_refresh <contact refresh (s)> (default: %u)]\n"
        "        [dht_t_replicate <replication (s)> (default: %u)]\n"
        "if TYPE == " IP_UDP "\n"
        "        ip <IP address in dotted notation>\n"
        "        [port <UDP port> (default: %d)]\n"
        "        [dns <DDNS IP address in dotted notation>"
        " (default: none)]\n\n"
        "if TYPE == " ETH_LLC "\n"
        "        dev <interface name>\n"
        "        [hash [ALGORITHM] (default: %s)]\n"
        "where ALGORITHM in {" SHA3_224 " " SHA3_256 " "
        SHA3_384 " " SHA3_512 "}\n\n"
        "if TYPE == " ETH_DIX "\n"
        "        dev <interface name>\n"
        "        [ethertype <ethertype> (default: 0x%4X)]\n"
        "        [hash [ALGORITHM] (default: %s)]\n"
        "where ALGORITHM in {" SHA3_224 " " SHA3_256 " "
        SHA3_384 " " SHA3_512 "}\n\n"
        "if TYPE == " LOCAL "\n"
        "        [hash [ALGORITHM] (default: %s)]\n"
        "where ALGORITHM in {" SHA3_224 " " SHA3_256 " "
        SHA3_384 " " SHA3_512 "}\n\n"
        "if TYPE == " BROADCAST "\n"
        "        [autobind]\n\n";

static void usage(void)
{
        /* FIXME: Add ipcp_config stuff. */
        printf(usage_str,
               /* unicast */
               FLAT_RANDOM, DHT_DIR, SHA3_256, LINK_STATE, MB_ECN_CA,
               /* dt */
               DT(addr_size), DT(eid_size), DT(max_ttl),
               /* dht */
               DHT(alpha), DHT(k), DHT(t_expire),
               DHT(t_refresh), DHT(t_replicate),
               /* udp */
               UDP(port),
               /* eth_llc */
               SHA3_256,
               /* eth_dix */
               DIX(ethertype),
               SHA3_256,
               /* local */
               SHA3_256,
               /* broadcast */
               SHA3_256);
}

int do_bootstrap_ipcp(int     argc,
                      char ** argv)
{
        char *                  ipcp           = NULL;
        pid_t                   pid            = -1;
        struct ipcp_config      conf;
        struct dir_config       dir_config     = default_dir_config;
        uint8_t                 addr_size      = DT(addr_size);
        uint8_t                 eid_size       = DT(eid_size);
        uint8_t                 max_ttl        = DT(max_ttl);
        enum pol_routing        routing_type   = DT(routing_type);
        enum pol_addr_auth      addr_auth_type = UNI(addr_auth_type);
        enum pol_cong_avoid     cong_avoid     = UNI(cong_avoid);
        enum pol_dir_hash       hash_algo      = DIR_HASH_SHA3_256;
        uint32_t                ip_addr        = 0;
        uint32_t                dns_addr       = UDP(dns_addr);
        int                     port           = UDP(port);
        char *                  ipcp_type      = NULL;
        enum ipcp_type          type           = IPCP_INVALID;
        char *                  layer          = NULL;
        char *                  dev            = NULL;
        uint16_t                ethertype      = DIX(ethertype);
        struct ipcp_list_info * ipcps;
        ssize_t                 len            = 0;
        int                     i              = 0;
        bool                    autobind       = false;
        int                     cargs;

        while (argc > 0) {
                cargs = 2;
                if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "layer") == 0) {
                        layer = *(argv + 1);
                } else if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
                } else if (matches(*argv, "hash") == 0) {
                        if (strcmp(*(argv + 1), SHA3_224) == 0)
                                hash_algo = DIR_HASH_SHA3_224;
                        else if (strcmp(*(argv + 1), SHA3_256) == 0)
                                hash_algo = DIR_HASH_SHA3_256;
                        else if (strcmp(*(argv + 1), SHA3_384) == 0)
                                hash_algo = DIR_HASH_SHA3_384;
                        else if (strcmp(*(argv + 1), SHA3_512) == 0)
                                hash_algo = DIR_HASH_SHA3_512;
                        else
                                goto unknown_param;
                } else if (matches(*argv, "ip") == 0) {
                        if (inet_pton (AF_INET, *(argv + 1), &ip_addr) != 1)
                                goto unknown_param;
                } else if (matches(*argv, "dns") == 0) {
                        if (inet_pton(AF_INET, *(argv + 1), &dns_addr) != 1)
                                goto unknown_param;
                } else if (matches(*argv, "device") == 0) {
                        dev = *(argv + 1);
                } else if (matches(*argv, "ethertype") == 0) {
                        /* NOTE: We might do some more checks on strtol. */
                        if (matches(*(argv + 1), "0x") == 0)
                                ethertype = strtol(*(argv + 1), NULL, 0);
                        else
                                ethertype = strtol(*(argv + 1), NULL, 16);
                        if (ethertype < 0x0600 || ethertype >= 0xFFFF) {
                                printf("Invalid Ethertype: \"%s\".\n"
                                       "Recommended range: 0xA000-0xEFFF.\n",
                                       *(argv + 1));
                                return -1;
                        }
                } else if (matches(*argv, "addr") == 0) {
                        addr_size = atoi(*(argv + 1));
                } else if (matches(*argv, "eid") == 0) {
                        eid_size = atoi(*(argv + 1));
                } else if (matches(*argv, "ttl") == 0) {
                        max_ttl = atoi(*(argv + 1));
                } else if (matches(*argv, "port") == 0) {
                        port = atoi(*(argv + 1));
                } else if (matches(*argv, "autobind") == 0) {
                        autobind = true;
                        cargs = 1;
                } else if (matches(*argv, "addr_auth") == 0) {
                        if (strcmp(FLAT_RANDOM, *(argv + 1)) == 0)
                                addr_auth_type = ADDR_AUTH_FLAT_RANDOM;
                        else
                                goto unknown_param;
                } else if (matches(*argv, "directory") == 0) {
                        if (strcmp(DHT_DIR, *(argv + 1)) == 0)
                                dir_config.pol = DIR_DHT;
                        else
                                goto unknown_param;
                } else if (matches(*argv, "dht_alpha") == 0) {
                        dir_config.dht.params.alpha = atoi(*(argv + 1));
                } else if (matches(*argv, "dht_k") == 0) {
                        dir_config.dht.params.k = atoi(*(argv + 1));
                } else if (matches(*argv, "dht_t_expire") == 0) {
                        dir_config.dht.params.t_expire = atoi(*(argv + 1));
                } else if (matches(*argv, "dht_t_refresh") == 0) {
                        dir_config.dht.params.t_refresh = atoi(*(argv + 1));
                } else if (matches(*argv, "dht_t_replicate") == 0) {
                        dir_config.dht.params.t_replicate = atoi(*(argv + 1));
                } else if (matches(*argv, "routing") == 0) {
                        if (strcmp(LINK_STATE, *(argv + 1)) == 0)
                                routing_type = ROUTING_LINK_STATE;
                        else if (strcmp(LINK_STATE_LFA,
                                        *(argv + 1)) == 0)
                                routing_type = ROUTING_LINK_STATE_LFA;
                        else if (strcmp(LINK_STATE_ECM,
                                        *(argv + 1)) == 0)
                                routing_type = ROUTING_LINK_STATE_ECMP;
                        else
                                goto unknown_param;
                } else if (matches(*argv, "congestion") == 0) {
                        if (strcmp(NONE_CA, *(argv + 1)) == 0)
                                cong_avoid = CA_NONE;
                        else if (strcmp(MB_ECN_CA,
                                        *(argv + 1)) == 0)
                                cong_avoid = CA_MB_ECN;
                        else
                                goto unknown_param;
                } else {
                        printf("Unknown option: \"%s\".\n", *argv);
                        return -1;
                }

                argc -= cargs;
                argv += cargs;
        }

        if (ipcp == NULL || layer == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++) {
                if (wildcard_match(ipcps[i].name, ipcp) == 0) {
                        pid = ipcps[i].pid;
                        break;
                }
        }

        if (ipcp_type != NULL) {
                if (strcmp(ipcp_type, UNICAST) == 0)
                        type = IPCP_UNICAST;
                else if (strcmp(ipcp_type, BROADCAST) == 0)
                        type = IPCP_BROADCAST;
                else if (strcmp(ipcp_type, IP_UDP) == 0)
                        type = IPCP_UDP;
                else if (strcmp(ipcp_type, ETH_LLC) == 0)
                        type = IPCP_ETH_LLC;
                else if (strcmp(ipcp_type, ETH_DIX) == 0)
                        type = IPCP_ETH_DIX;
                else if (strcmp(ipcp_type, LOCAL) == 0)
                        type = IPCP_LOCAL;
                else goto fail_usage;
        }

        if (pid == -1) {
                if (ipcp_type == NULL) {
                        printf("No IPCPs matching %s found.\n\n", ipcp);
                        goto fail;
                }

                pid = irm_create_ipcp(ipcp, type);
                if (pid < 0)
                        goto fail;
                free(ipcps);
                len = irm_list_ipcps(&ipcps);
        }

        for (i = 0; i < len; i++) {
                if (wildcard_match(ipcps[i].name, ipcp) == 0) {
                        pid = ipcps[i].pid;
                        if (ipcp_type != NULL && type != ipcps[i].type) {
                                printf("Types do not match.\n\n");
                                goto fail;
                        }

                        conf.type = ipcps[i].type;

                        if (autobind && (conf.type != IPCP_UNICAST &&
                                         conf.type != IPCP_BROADCAST)) {
                                printf("Can not bind this IPCP type,"
                                       "autobind disabled.\n\n");
                                autobind = false;
                        }

                        if (strlen(layer) > LAYER_NAME_SIZE) {
                                printf("Layer name too long.\n\n");
                                goto fail_usage;
                        }

                        strcpy(conf.layer_info.name, layer);
                        conf.layer_info.dir_hash_algo = hash_algo;

                        switch (conf.type) {
                        case IPCP_UNICAST:
                                conf.unicast.dt.addr_size    = addr_size;
                                conf.unicast.dt.eid_size     = eid_size;
                                conf.unicast.dt.max_ttl      = max_ttl;
                                conf.unicast.dt.routing_type = routing_type;
                                conf.unicast.addr_auth_type  = addr_auth_type;
                                conf.unicast.cong_avoid      = cong_avoid;
                                conf.unicast.dir             = dir_config;
                                break;
                        case IPCP_UDP:
                                if (ip_addr == 0)
                                        goto fail_usage;
                                conf.udp.ip_addr  = ip_addr;
                                conf.udp.dns_addr = dns_addr;
                                conf.udp.port     = port;
                                break;
                        case IPCP_ETH_DIX:
                                conf.eth.ethertype = ethertype;
                                /* FALLTHRU */
                        case IPCP_ETH_LLC:
                                if (dev == NULL)
                                        goto fail_usage;
                                if (strlen(dev) > DEV_NAME_SIZE) {
                                        printf("Device name too long.\n\n");
                                        goto fail_usage;
                                }

                                strcpy(conf.eth.dev, dev);
                                break;
                        case IPCP_BROADCAST:
                                /* FALLTHRU */
                        case IPCP_LOCAL:
                                break;
                        default:
                                assert(false);
                                break;
                        }

                        if (autobind && irm_bind_process(pid, ipcp)) {
                                printf("Failed to bind %d to %s.\n", pid, ipcp);
                                goto fail;
                        }

                        if (autobind && irm_bind_process(pid, layer)) {
                                printf("Failed to bind %d to %s.\n",
                                       pid, layer);
                                irm_unbind_process(pid, ipcp);
                                goto fail;
                        }

                        if (irm_bootstrap_ipcp(pid, &conf)) {
                                if (autobind) {
                                        irm_unbind_process(pid, ipcp);
                                        irm_unbind_process(pid, layer);
                                }
                                goto fail;
                        }
                }
        }

        free(ipcps);

        return 0;

 unknown_param:
        printf("Unknown parameter for %s: \"%s\".\n", *argv, *(argv + 1));
        return -1;

 fail_usage:
        usage();
 fail:
        free(ipcps);
        return -1;
}
