/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Connect components of unicast or broadcast IPC processes
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void)
{
        printf("Usage: irm ipcp poa attach\n"
               "                name <ipcp name>\n"
               "                [udp [UDP_POA]]\n"
               "                [eth [ETH_POA]]\n"
               "where exactly one of udp or eth is given\n"
               "and UDP_POA is <local IP address>[:<port>]\n"
               "and ETH_POA is dev <device> [ethertype <ethertype>]\n");
}

int do_attach_ipcp(int     argc,
                   char ** argv)
{
        char *                  ipcp      = NULL;
        char *                  udpstr    = NULL;
        char *                  devstr    = NULL;
        uint16_t                ethertype = POA_ETHERTYPE;
        bool                    eth       = false;
        struct poa_spec         poa;
        char                    str[POA_STRLEN + 1];
        struct ipcp_list_info * ipcps;
        ssize_t                 len       = 0;
        pid_t                   pid       = -1;
        ssize_t                 i;
        int                     cargs;

        while (argc > 0) {
                cargs = 2;

                if (strcmp(*argv, "eth") == 0)
                        cargs = 1;

                if (argc < cargs) {
                        usage();
                        return -1;
                }

                if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
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
                } else {
                        printf("\"%s\" is unknown, try \"irm ipcp "
                               "poa attach\".\n", *argv);
                        return -1;
                }

                argc -= cargs;
                argv += cargs;
        }

        if (ipcp == NULL) {
                usage();
                return -1;
        }

        if (eth && udpstr != NULL) {
                printf("A PoA is udp or eth, not both.\n");
                return -1;
        }

        if (eth && devstr == NULL) {
                printf("An eth PoA needs a device.\n");
                return -1;
        }

        if (!eth && udpstr == NULL) {
                usage();
                return -1;
        }

        if (poa_spec_set(&poa, udpstr, devstr, ethertype) < 0)
                return -1;

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++)
                if (strcmp(ipcps[i].name, ipcp) == 0)
                        pid = ipcps[i].pid;

        free(ipcps);

        if (pid == -1) {
                printf("No such IPCP: \"%s\".\n", ipcp);
                return -1;
        }

        if (irm_attach_ipcp(pid, &poa) < 0) {
                poa_spec_str(&poa, str, sizeof(str));
                printf("Failed to attach PoA %s on IPCP %s.\n", str, ipcp);
                return -1;
        }

        return 0;
}
