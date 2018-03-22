/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Create IPC Processes
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NORMAL  "normal"
#define UDP     "udp"
#define ETH_LLC "eth-llc"
#define ETH_DIX "eth-dix"
#define LOCAL   "local"
#define RAPTOR  "raptor"

static void usage(void)
{
        printf("Usage: irm ipcp list\n"
               "                [name  <ipcp name>]\n"
               "                [layer <layer_name>]\n\n"
               "                [type [TYPE]]\n\n"
               "where TYPE = {" NORMAL " " LOCAL " "
               UDP " " ETH_LLC " " ETH_DIX " " RAPTOR "}\n");
}

static char * str_type(enum ipcp_type type)
{
        switch(type) {
        case IPCP_NORMAL:
                return NORMAL;
        case IPCP_ETH_LLC:
                return ETH_LLC;
        case IPCP_ETH_DIX:
                return ETH_DIX;
        case IPCP_UDP:
                return UDP;
        case IPCP_RAPTOR:
                return RAPTOR;
        case IPCP_LOCAL:
                return LOCAL;
        default:
                return "UNKNOWN";
        }
};

int do_list_ipcp(int     argc,
                 char ** argv)
{
        char *             ipcp_type = NULL;
        char *             ipcp_name = NULL;
        enum ipcp_type     type      = -1;
        struct ipcp_info * ipcps;
        ssize_t            len;
        ssize_t            i;

        while (argc > 0) {
                if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "name") == 0) {
                        ipcp_name = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcp list\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (ipcp_type != NULL) {
                if (strcmp(ipcp_type, NORMAL) == 0)
                        type = IPCP_NORMAL;
                else if (strcmp(ipcp_type, UDP) == 0)
                        type = IPCP_UDP;
                else if (strcmp(ipcp_type, LOCAL) == 0)
                        type = IPCP_LOCAL;
                else if (strcmp(ipcp_type, ETH_LLC) == 0)
                        type = IPCP_ETH_LLC;
                else if (strcmp(ipcp_type, ETH_DIX) == 0)
                        type = IPCP_ETH_DIX;
                else if (strcmp(ipcp_type, RAPTOR) == 0)
                        type = IPCP_RAPTOR;
                else {
                        usage();
                        return -1;
                }
        }

        len = irm_list_ipcps(&ipcps);
        if (len == 0) {
                printf("No IPCPs in system.\n\n");
                return 0;
        }

        /* FIXME: Implement filtering based on type and name. */
        (void) type;
        (void) ipcp_name;

        printf("+---------+----------------------+------------+"
               "----------------------+\n");
        printf("| %7s | %20s | %10s | %20s |\n", "pid", "name", "type", "layer");
        printf("+---------+----------------------+------------+"
               "----------------------+\n");

        for (i = 0; i < len; i++)
                printf("| %7d | %20s | %10s | %20s |\n",
                       ipcps[i].pid,
                       ipcps[i].name,
                       str_type(ipcps[i].type),
                       ipcps[i].layer);

        printf("+---------+----------------------+------------+"
               "----------------------+\n\n");

        free(ipcps);

        return 0;
}
