/*
 * Ouroboros - Copyright (C) 2016 - 2017
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#endif
#include <ouroboros/irm.h>
#include <ouroboros/ipcp.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define NORMAL                 "normal"
#define SHIM_UDP               "shim-udp"
#define SHIM_ETH_LLC           "shim-eth-llc"
#define LOCAL                  "local"
#define RAPTOR                 "raptor"

#define MD5                    "MD5"
#define SHA3_224               "SHA3_224"
#define SHA3_256               "SHA3_256"
#define SHA3_384               "SHA3_384"
#define SHA3_512               "SHA3_512"

#define DEFAULT_ADDR_SIZE      4
#define DEFAULT_FD_SIZE        2
#define DEFAULT_DDNS           0
#define DEFAULT_ADDR_AUTH      ADDR_AUTH_FLAT_RANDOM
#define DEFAULT_ROUTING        ROUTING_LINK_STATE
#define DEFAULT_PFF            PFF_SIMPLE
#define DEFAULT_HASH_ALGO      DIR_HASH_SHA3_256
#define FLAT_RANDOM_ADDR_AUTH  "flat"
#define LINK_STATE_ROUTING     "link_state"
#define LINK_STATE_LFA_ROUTING "lfa"
#define SIMPLE_PFF             "simple"
#define ALTERNATE_PFF          "alternate"

static void usage(void)
{
        /* FIXME: Add ipcp_config stuff */
        printf("Usage: irm ipcp bootstrap\n"
               "                name <ipcp name>\n"
               "                dif <DIF name>\n"
               "                type [TYPE]\n"
               "where TYPE = {" NORMAL " " LOCAL " "
               SHIM_UDP " " SHIM_ETH_LLC " " RAPTOR "},\n\n"
               "if TYPE == " NORMAL "\n"
               "                [addr <address size> (default: %d)]\n"
               "                [fd <fd size> (default: %d)]\n"
               "                [ttl (add time to live value in the PCI)]\n"
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
               "if TYPE == " SHIM_UDP "\n"
               "                ip <IP address in dotted notation>\n"
               "                [dns <DDNS IP address in dotted notation>"
               " (default: none)]\n\n"
               "if TYPE == " SHIM_ETH_LLC "\n"
               "                if_name <interface name>\n"
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
               DEFAULT_ADDR_SIZE, DEFAULT_FD_SIZE, FLAT_RANDOM_ADDR_AUTH,
               LINK_STATE_ROUTING, SIMPLE_PFF, SHA3_256, SHA3_256, SHA3_256,
               SHA3_256);
}

int do_bootstrap_ipcp(int     argc,
                      char ** argv)
{
        char *             name           = NULL;
        pid_t              pid;
        struct ipcp_config conf;
        uint8_t            addr_size      = DEFAULT_ADDR_SIZE;
        uint8_t            fd_size        = DEFAULT_FD_SIZE;
        bool               has_ttl        = false;
        enum pol_addr_auth addr_auth_type = DEFAULT_ADDR_AUTH;
        enum pol_routing   routing_type   = DEFAULT_ROUTING;
        enum pol_pff       pff_type       = DEFAULT_PFF;
        enum pol_dir_hash  hash_algo      = DEFAULT_HASH_ALGO;
        uint32_t           ip_addr        = 0;
        uint32_t           dns_addr       = DEFAULT_DDNS;
        char *             ipcp_type      = NULL;
        char *             dif_name       = NULL;
        char *             if_name        = NULL;
        pid_t *            pids           = NULL;
        ssize_t            len            = 0;
        int                i              = 0;
        bool               autobind       = false;
        int                cargs;

        while (argc > 0) {
                cargs = 2;
                if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "dif") == 0) {
                        dif_name = *(argv + 1);
                } else if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
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
                } else if (matches(*argv, "if_name") == 0) {
                        if_name = *(argv + 1);
                } else if (matches(*argv, "addr") == 0) {
                        addr_size = atoi(*(argv + 1));
                } else if (matches(*argv, "fd") == 0) {
                        fd_size = atoi(*(argv + 1));
                } else if (matches(*argv, "ttl") == 0) {
                        has_ttl = true;
                        cargs = 1;
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

        if (name == NULL || dif_name == NULL || ipcp_type == NULL) {
                usage();
                return -1;
        }

        strcpy(conf.dif_info.dif_name, dif_name);
        if (strcmp(ipcp_type, SHIM_UDP) != 0)
                conf.dif_info.dir_hash_algo = hash_algo;

        if (strcmp(ipcp_type, NORMAL) == 0) {
                conf.type = IPCP_NORMAL;
                conf.addr_size = addr_size;
                conf.fd_size = fd_size;
                conf.has_ttl = has_ttl;
                conf.addr_auth_type = addr_auth_type;
                conf.routing_type = routing_type;
                conf.pff_type = pff_type;
        } else if (strcmp(ipcp_type, SHIM_UDP) == 0) {
                conf.type = IPCP_SHIM_UDP;
                if (ip_addr == 0) {
                        usage();
                        return -1;
                }
                conf.ip_addr = ip_addr;
                conf.dns_addr = dns_addr;
        } else if (strcmp(ipcp_type, LOCAL) == 0) {
                conf.type = IPCP_LOCAL;
        } else if (strcmp(ipcp_type, RAPTOR) == 0) {
                conf.type = IPCP_RAPTOR;
        } else if (strcmp(ipcp_type, SHIM_ETH_LLC) == 0) {
                conf.type = IPCP_SHIM_ETH_LLC;
                if (if_name == NULL) {
                        usage();
                        return -1;
                }
                conf.if_name = if_name;
        } else {
                usage();
                return -1;
        }

        if (autobind && conf.type != IPCP_NORMAL) {
                printf("Can only bind normal IPCPs, autobind disabled.\n");
                autobind = false;
        }

        len = irm_list_ipcps(name, &pids);
        if (len <= 0) {
                pid = irm_create_ipcp(name, conf.type);
                if (pid== 0)
                        return -1;
                len = irm_list_ipcps(name, &pids);
        }

        for (i = 0; i < len; i++) {
                if (autobind && irm_bind_process(pids[i], name)) {
                        printf("Failed to bind %d to %s.\n", pids[i], name);
                        free(pids);
                        return -1;
                }

                if (autobind && irm_bind_process(pids[i], dif_name)) {
                        printf("Failed to bind %d to %s.\n", pids[i], dif_name);
                        irm_unbind_process(pids[i], name);
                        free(pids);
                        return -1;
                }

                if (irm_bootstrap_ipcp(pids[i], &conf)) {
                        if (autobind) {
                                irm_unbind_process(pids[i], name);
                                irm_unbind_process(pids[i], dif_name);
                        }
                        free(pids);
                        return -1;
                }
        }

        free(pids);

        return 0;

 unknown_param:
        printf("Unknown parameter for %s: \"%s\".\n", *argv, *(argv + 1));
        return -1;
}
