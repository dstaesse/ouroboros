/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Bootstrap IPC Processes
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#define NORMAL                 "normal"
#define UDP                    "udp"
#define ETH_LLC                "eth-llc"
#define ETH_DIX                "eth-dix"
#define LOCAL                  "local"
#define RAPTOR                 "raptor"

#define MD5                    "MD5"
#define SHA3_224               "SHA3_224"
#define SHA3_256               "SHA3_256"
#define SHA3_384               "SHA3_384"
#define SHA3_512               "SHA3_512"

#define DEFAULT_ADDR_SIZE      4
#define DEFAULT_EID_SIZE       2
#define DEFAULT_DDNS           0
#define DEFAULT_TTL            60
#define DEFAULT_ADDR_AUTH      ADDR_AUTH_FLAT_RANDOM
#define DEFAULT_ROUTING        ROUTING_LINK_STATE
#define DEFAULT_PFF            PFF_SIMPLE
#define DEFAULT_HASH_ALGO      DIR_HASH_SHA3_256
#define DEFAULT_ETHERTYPE      0xA000

#define FLAT_RANDOM_ADDR_AUTH  "flat"
#define LINK_STATE_ROUTING     "link_state"
#define LINK_STATE_LFA_ROUTING "lfa"
#define SIMPLE_PFF             "simple"
#define ALTERNATE_PFF          "alternate"

static void usage(void)
{
        /* FIXME: Add ipcp_config stuff. */
        printf("Usage: irm ipcp bootstrap\n"
               "                name <ipcp name>\n"
               "                layer <layer name>\n"
               "                [type [TYPE]]\n"
               "where TYPE = {" NORMAL " " LOCAL " "
               UDP " " ETH_LLC " " ETH_DIX " " RAPTOR "},\n\n"
               "if TYPE == " NORMAL "\n"
               "                [addr <address size> (default: %d)]\n"
               "                [eid <eid size> (default: %d)]\n"
               "                [ttl (max time-to-live value, default: %d)]\n"
               "                [addr_auth <ADDRESS_POLICY> (default: %s)]\n"
               "                [routing <ROUTING_POLICY> (default: %s)]\n"
               "                [pff [PFF_POLICY] (default: %s)]\n"
               "                [hash [ALGORITHM] (default: %s)]\n"
               "                [autobind]\n"
               "where ADDRESS_POLICY = {"FLAT_RANDOM_ADDR_AUTH"}\n"
               "      ROUTING_POLICY = {"LINK_STATE_ROUTING " "
               LINK_STATE_LFA_ROUTING "}\n"
               "      PFF_POLICY = {" SIMPLE_PFF " " ALTERNATE_PFF "}\n"
               "      ALGORITHM = {" SHA3_224 " " SHA3_256 " "
               SHA3_384 " " SHA3_512 "}\n\n"
               "if TYPE == " UDP "\n"
               "                ip <IP address in dotted notation>\n"
               "                [dns <DDNS IP address in dotted notation>"
               " (default: none)]\n\n"
               "if TYPE == " ETH_LLC "\n"
               "                dev <interface name>\n"
               "                [hash [ALGORITHM] (default: %s)]\n"
               "where ALGORITHM = {" SHA3_224 " " SHA3_256 " "
               SHA3_384 " " SHA3_512 "}\n\n"
               "if TYPE == " ETH_DIX "\n"
               "                dev <interface name>\n"
               "                [ethertype <ethertype> (default: 0x%4X)]\n"
               "                [hash [ALGORITHM] (default: %s)]\n"
               "where ALGORITHM = {" SHA3_224 " " SHA3_256 " "
               SHA3_384 " " SHA3_512 "}\n\n"
               "if TYPE == " LOCAL "\n"
               "                [hash [ALGORITHM] (default: %s)]\n"
               "where ALGORITHM = {" SHA3_224 " " SHA3_256 " "
               SHA3_384 " " SHA3_512 "}\n\n"
               "if TYPE == " RAPTOR "\n"
               "                [hash [ALGORITHM] (default: %s)]\n"
               "where ALGORITHM = {" SHA3_224 " " SHA3_256 " "
               SHA3_384 " " SHA3_512 "}\n\n",
               DEFAULT_ADDR_SIZE, DEFAULT_EID_SIZE, DEFAULT_TTL,
               FLAT_RANDOM_ADDR_AUTH, LINK_STATE_ROUTING, SIMPLE_PFF,
               SHA3_256, SHA3_256, 0xA000, SHA3_256, SHA3_256, SHA3_256);
}

int do_bootstrap_ipcp(int     argc,
                      char ** argv)
{
        char *             ipcp           = NULL;
        pid_t              pid            = -1;
        struct ipcp_config conf;
        uint8_t            addr_size      = DEFAULT_ADDR_SIZE;
        uint8_t            eid_size       = DEFAULT_EID_SIZE;
        uint8_t            max_ttl        = DEFAULT_TTL;
        enum pol_addr_auth addr_auth_type = DEFAULT_ADDR_AUTH;
        enum pol_routing   routing_type   = DEFAULT_ROUTING;
        enum pol_pff       pff_type       = DEFAULT_PFF;
        enum pol_dir_hash  hash_algo      = DEFAULT_HASH_ALGO;
        uint32_t           ip_addr        = 0;
        uint32_t           dns_addr       = DEFAULT_DDNS;
        char *             ipcp_type      = NULL;
        enum ipcp_type     type;
        char *             layer          = NULL;
        char *             dev            = NULL;
        uint16_t           ethertype      = DEFAULT_ETHERTYPE;
        struct ipcp_info * ipcps;
        ssize_t            len            = 0;
        int                i              = 0;
        bool               autobind       = false;
        int                cargs;

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
                        if (ethertype < 0x0600 || ethertype == 0xFFFF) {
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
                } else if (matches(*argv, "autobind") == 0) {
                        autobind = true;
                        cargs = 1;
                } else if (matches(*argv, "addr_auth") == 0) {
                        if (strcmp(FLAT_RANDOM_ADDR_AUTH, *(argv + 1)) == 0)
                                addr_auth_type = ADDR_AUTH_FLAT_RANDOM;
                        else
                                goto unknown_param;
                } else if (matches(*argv, "routing") == 0) {
                        if (strcmp(LINK_STATE_ROUTING, *(argv + 1)) == 0)
                                routing_type = ROUTING_LINK_STATE;
                        else if (strcmp(LINK_STATE_LFA_ROUTING,
                                        *(argv + 1)) == 0)
                                routing_type = ROUTING_LINK_STATE_LFA;
                        else
                                goto unknown_param;
                } else if (matches(*argv, "pff") == 0) {
                        if (strcmp(SIMPLE_PFF, *(argv + 1)) == 0)
                                pff_type = PFF_SIMPLE;
                        else if (strcmp(ALTERNATE_PFF, *(argv + 1)) == 0)
                                pff_type = PFF_ALTERNATE;
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

        if (pid == -1) {
                if (ipcp_type == NULL) {
                        printf("No IPCPs matching %s found.\n\n", ipcp);
                        goto fail;
                } else {
                        if (strcmp(ipcp_type, NORMAL) == 0)
                                type = IPCP_NORMAL;
                        else if (strcmp(ipcp_type, UDP) == 0)
                                type = IPCP_UDP;
                        else if (strcmp(ipcp_type, ETH_LLC) == 0)
                                type = IPCP_ETH_LLC;
                        else if (strcmp(ipcp_type, ETH_DIX) == 0)
                                type = IPCP_ETH_DIX;
                        else if (strcmp(ipcp_type, LOCAL) == 0)
                                type = IPCP_LOCAL;
                        else if (strcmp(ipcp_type, RAPTOR) == 0)
                                type = IPCP_RAPTOR;
                        else goto fail_usage;
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

                        if (autobind && conf.type != IPCP_NORMAL) {
                                printf("Can only bind normal IPCPs, "
                                       "autobind disabled.\n");
                                autobind = false;
                        }

                        strcpy(conf.layer_info.layer_name, layer);
                        if (conf.type == IPCP_UDP)
                                conf.layer_info.dir_hash_algo = hash_algo;

                        switch (conf.type) {
                        case IPCP_NORMAL:
                                conf.addr_size      = addr_size;
                                conf.eid_size       = eid_size;
                                conf.max_ttl        = max_ttl;
                                conf.addr_auth_type = addr_auth_type;
                                conf.routing_type   = routing_type;
                                conf.pff_type       = pff_type;
                                break;
                        case IPCP_UDP:
                                if (ip_addr == 0)
                                        goto fail_usage;
                                conf.ip_addr = ip_addr;
                                conf.dns_addr = dns_addr;
                                break;
                        case IPCP_ETH_LLC:
                                if (dev == NULL)
                                        goto fail_usage;
                                conf.dev = dev;
                                break;
                        case IPCP_ETH_DIX:
                                if (dev == NULL)
                                        goto fail_usage;
                                conf.dev = dev;
                                conf.ethertype = ethertype;
                                break;
                        case IPCP_LOCAL:
                                /* FALLTHRU */
                        case IPCP_RAPTOR:
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
