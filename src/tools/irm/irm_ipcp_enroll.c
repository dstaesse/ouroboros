/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Enroll IPC Processes
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

#include <stdio.h>
#include <stdlib.h>

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

#include <arpa/inet.h>
#include <string.h>

#define UNICAST    "unicast"
#define BROADCAST "broadcast"

static void usage(void)
{
        printf("Usage: irm ipcp enroll\n"
               "                name <ipcp name>\n"
               "                [layer <layer to enroll with>]\n"
               "                [dst <destination to enroll with>]\n"
               "                [type [TYPE], default = " UNICAST "]\n"
               "                [autobind]\n"
               "                [transit [on|off] (default: on)]\n"
               "                [udp [UDP_PEER]]\n"
               "                [eth [dev <device>] [ethertype <ethertype>]]\n"
               "where TYPE in {" UNICAST " " BROADCAST "}\n"
               "and UDP_PEER is <IP address or host>[:<port>]\n");
}

static int get_layer_name(const char * ipcp,
                          char *       layer_name)
{
        struct ipcp_list_info * ipcps;
        ssize_t                 len;
        ssize_t                 i;

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++)
                if (strcmp(ipcps[i].name, ipcp) == 0) {
                        strcpy(layer_name, ipcps[i].layer);
                        free(ipcps);
                        return 0;
                }

        free(ipcps);

        return -1;
}

int do_enroll_ipcp(int     argc,
                   char ** argv)
{
        char *                  ipcp      = NULL;
        char *                  layer     = NULL;
        char *                  dst       = NULL;
        char *                  udpstr    = NULL;
        char *                  devstr    = NULL;
        uint16_t                ethertype = POA_ETHERTYPE;
        bool                    eth       = false;
        struct poa_addr         addr;
        struct poa_addr *       pa        = NULL;
        struct ipcp_list_info * ipcps;
        pid_t                   pid       = -1;
        ssize_t                 len       = 0;
        int                     i         = 0;
        bool                    autobind  = false;
        uint32_t                flags     = IPCP_FLAG_TRANSIT;
        uint32_t                mask      = 0;
        int                     cargs;
        char *                  ipcp_type = UNICAST;
        enum ipcp_type          type      = IPCP_INVALID;

        while (argc > 0) {
                cargs = 2;
                if (strcmp(*argv, "eth") == 0)
                        cargs = 1;
                else if (matches(*argv, "autobind") == 0)
                        cargs = 1;

                if (argc < cargs) {
                        usage();
                        return -1;
                }

                if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
                } else if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "layer") == 0) {
                        layer = *(argv + 1);
                } else if (strcmp(*argv, "dst") == 0) {
                        dst = *(argv + 1);
                } else if (strcmp(*argv, "udp") == 0) {
                        udpstr = *(argv + 1);
                } else if (strcmp(*argv, "dev") == 0) {
                        devstr = *(argv + 1);
                } else if (strcmp(*argv, "ethertype") == 0) {
                        if (parse_ethertype(*(argv + 1), &ethertype) < 0) {
                                printf("Invalid ethertype: \"%s\".\n",
                                       *(argv + 1));
                                return -1;
                        }
                } else if (strcmp(*argv, "eth") == 0) {
                        eth = true;
                        cargs = 1;
                } else if (matches(*argv, "autobind") == 0) {
                        autobind = true;
                        cargs = 1;
                } else if (matches(*argv, "transit") == 0) {
                        if (transit_value(*(argv + 1), &flags) < 0)
                                return -1;
                        mask = IPCP_FLAG_TRANSIT;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "enroll_ipcp\".\n", *argv);
                        return -1;
                }

                argc -= cargs;
                argv += cargs;
        }

        if ((layer == NULL && dst == NULL) || ipcp == NULL) {
                usage();
                return -1;
        }

        if (dst == NULL)
                dst = layer;

        memset(&addr, 0, sizeof(addr));

        if (udpstr != NULL) {
                if (poa_addr_set_udp(&addr, udpstr) < 0)
                        return -1;
                pa = &addr;
        }

        if (eth) {
                if (udpstr != NULL) {
                        printf("Enroll via udp or eth, not both.\n");
                        return -1;
                }

                if (poa_addr_set_eth(&addr, devstr, ethertype) < 0)
                        return -1;
                pa = &addr;
        }

        if (strcmp(ipcp_type, UNICAST) == 0)
                type = IPCP_UNICAST;
        else if (strcmp(ipcp_type, BROADCAST) == 0)
                type = IPCP_BROADCAST;

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++)
                if (wildcard_match(ipcps[i].name, ipcp) == 0 &&
                    ipcps[i].type == type)
                        pid = ipcps[i].pid;

        if (pid < 0) {
                pid = irm_create_ipcp(ipcp, type, flags);
                if (pid < 0)
                        goto fail;
                free(ipcps);
                len = irm_list_ipcps(&ipcps);
        }

        for (i = 0; i < len; i++) {
                char enr_layer[LAYER_NAME_SIZE];
                if (ipcps[i].type != type)
                        continue;

                if (wildcard_match(ipcps[i].name, ipcp) != 0)
                        continue;

                pid = ipcps[i].pid;
                if (mask && irm_set_ipcp_flags(pid, flags, mask) < 0) {
                        printf("Failed to set transit on %s.\n", ipcp);
                        goto fail;
                }

                if (irm_enroll_ipcp(pid, dst, pa) < 0) {
                        printf("Failed to enroll IPCP.\n");
                        goto fail;
                }

                if (get_layer_name(ipcps[i].name, enr_layer)) {
                        printf("Could not get layer name.\n");
                        goto fail;
                }

                if (layer != NULL && strcmp(enr_layer, layer)) {
                        printf("Enrollment destination does not "
                               "match requested layer.\n");
                        goto fail;
                }

                if (autobind && irm_bind_process(pid, ipcp)) {
                        printf("Failed to bind %d to %s.\n", pid, ipcp);
                        goto fail;
                }

                if (autobind && irm_bind_process(pid, enr_layer)) {
                        printf("Failed to bind %d to %s.\n", pid, enr_layer);
                        goto fail;
                }
        }

        free(ipcps);

        return 0;

 fail:
        free(ipcps);
        return -1;
}
