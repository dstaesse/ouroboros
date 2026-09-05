/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Set options on IPC Processes
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
        printf("Usage: irm ipcp set\n"
               "                name <ipcp name>\n"
               "                transit <on|off>\n");
}

int do_set_ipcp(int     argc,
                char ** argv)
{
        char *                  ipcp    = NULL;
        char *                  transit = NULL;
        struct ipcp_list_info * ipcps;
        uint32_t                flags = 0;
        uint32_t                mask  = IPCP_FLAG_TRANSIT;
        ssize_t                 len;
        int                     i;

        while (argc > 0) {
                if (argc < 2) {
                        usage();
                        return -1;
                }

                if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
                } else if (matches(*argv, "transit") == 0) {
                        transit = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcp set\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (ipcp == NULL || transit == NULL) {
                usage();
                return -1;
        }

        if (transit_value(transit, &flags) < 0)
                return -1;

        len = irm_list_ipcps(&ipcps);
        if (len <= 0) {
                printf("No IPCPs in system.\n");
                return -1;
        }

        for (i = 0; i < len; i++)
                if (strcmp(ipcps[i].name, ipcp) == 0) {
                        if (irm_set_ipcp_flags(ipcps[i].pid, flags, mask) < 0) {
                                printf("Failed to set transit on \"%s\".\n",
                                       ipcp);
                                goto fail_set;
                        }
                        break;
                }

        if (i == len) {
                printf("No such IPCP: \"%s\".\n", ipcp);
                goto fail_set;
        }

        free(ipcps);

        return 0;
 fail_set:
        free(ipcps);
        return -1;
}
