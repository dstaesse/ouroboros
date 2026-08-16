/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * List the points of attachment of an IPC process
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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void)
{
        printf("Usage: irm ipcp poa list\n"
               "                name <ipcp name>\n");
}

static void print_poa(const struct poa_spec * poa)
{
        char buf[INET6_ADDRSTRLEN];

        switch (poa->type) {
        case POA_UDP4:
                if (inet_ntop(AF_INET, &poa->udp4.ip_addr, buf,
                              sizeof(buf)) == NULL)
                        return;
                printf("%-6s %s:%u\n", "udp4", buf, poa->udp4.port);
                break;
        case POA_UDP6:
                if (inet_ntop(AF_INET6, &poa->udp6.ip_addr, buf,
                              sizeof(buf)) == NULL)
                        return;
                printf("%-6s [%s]:%u\n", "udp6", buf, poa->udp6.port);
                break;
        case POA_ETH:
                printf("%-6s %s 0x%04X %02x:%02x:%02x:%02x:%02x:%02x\n",
                       "eth", poa->eth.dev, poa->eth.ethertype,
                       poa->eth.mac[0], poa->eth.mac[1], poa->eth.mac[2],
                       poa->eth.mac[3], poa->eth.mac[4], poa->eth.mac[5]);
                break;
        default:
                break;
        }
}

int do_list_poas(int     argc,
                 char ** argv)
{
        char *                  ipcp  = NULL;
        struct poa_spec *       poas  = NULL;
        struct ipcp_list_info * ipcps;
        ssize_t                 len   = 0;
        pid_t                   pid   = -1;
        ssize_t                 n;
        ssize_t                 i;

        while (argc > 1) {
                if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm ipcp "
                               "poa list\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (ipcp == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++)
                if (strcmp(ipcps[i].name, ipcp) == 0)
                        pid = ipcps[i].pid;

        free(ipcps);

        if (pid == -1) {
                printf("No such IPCP: \"%s\".\n", ipcp);
                return -1;
        }

        n = irm_list_poas(pid, &poas);
        if (n < 0) {
                printf("Failed to list PoAs of %s.\n", ipcp);
                return -1;
        }

        for (i = 0; i < n; i++)
                print_poa(&poas[i]);

        free(poas);

        return 0;
}
