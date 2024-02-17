/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Create IPC Processes
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

#include <stdio.h>
#include <string.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define UNICAST                "unicast"
#define BROADCAST              "broadcast"
#define UDP                    "udp"
#define ETH_LLC                "eth-llc"
#define ETH_DIX                "eth-dix"
#define LOCAL                  "local"

static void usage(void)
{
        printf("Usage: irm ipcp create\n"
               "                name <ipcp name>\n"
               "                type [TYPE]\n\n"
               "where TYPE in {" UNICAST " " BROADCAST " " LOCAL " "
               UDP " " ETH_LLC " " ETH_DIX "}\n");
}

int do_create_ipcp(int     argc,
                   char ** argv)
{
        char *         ipcp_type = NULL;
        char *         ipcp_name = NULL;
        enum ipcp_type type      = 0;
        pid_t          pid;

        while (argc > 0) {
                if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "name") == 0) {
                        ipcp_name = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcp create\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (ipcp_type == NULL || ipcp_name == NULL) {
                usage();
                return -1;
        }

        if (strcmp(ipcp_type, UNICAST) == 0)
                type = IPCP_UNICAST;
        else if (strcmp(ipcp_type, BROADCAST) == 0)
                type = IPCP_BROADCAST;
        else if (strcmp(ipcp_type, UDP) == 0)
                type = IPCP_UDP;
        else if (strcmp(ipcp_type, LOCAL) == 0)
                type = IPCP_LOCAL;
        else if (strcmp(ipcp_type, ETH_LLC) == 0)
                type = IPCP_ETH_LLC;
        else if (strcmp(ipcp_type, ETH_DIX) == 0)
                type = IPCP_ETH_DIX;
        else {
                printf("IPCP type \"%s\" is unknown.\n", ipcp_type);
                usage();
                return -1;
        }

        pid = irm_create_ipcp(ipcp_name, type);
        if (pid < 0)
                return -1;

        return 0;
}
