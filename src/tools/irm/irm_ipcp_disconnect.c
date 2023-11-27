/*
 * Ouroboros - Copyright (C) 2016 - 2023
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

#define DT   "dt"
#define MGMT "mgmt"

static void usage(void)
{
        printf("Usage: irm ipcp disconnect\n"
               "                name      <ipcp name>\n"
               "                dst       <name of destination IPCP>\n"
               "                [component [COMPONENT]]\n\n"
               "where COMPONENT = {" DT " " MGMT "}\n");
}

int do_disconnect_ipcp(int     argc,
                       char ** argv)
{
        char *                  ipcp = NULL;
        char *                  dst  = NULL;
        char *                  comp = "*";
        char *                  component = NULL;
        struct ipcp_list_info * ipcps;
        ssize_t                 len  = 0;
        pid_t                   pid  = -1;
        ssize_t                 i;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
                } else if (matches(*argv, "dst") == 0) {
                        dst = *(argv + 1);
                } else if (matches(*argv, "component") == 0) {
                        comp = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcp connect\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (ipcp == NULL || dst == NULL || comp == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++)
                if (strcmp(ipcps[i].name, ipcp) == 0)
                        pid = ipcps[i].pid;

        free(ipcps);

        if (pid == -1)
                return -1;

        if (wildcard_match(comp, DT) == 0) {
                component = DT_COMP;
                if (irm_disconnect_ipcp(pid, dst, component))
                        return -1;
        }

        if (wildcard_match(comp, MGMT) == 0) {
                component = MGMT_COMP;
                if (irm_disconnect_ipcp(pid, dst, component))
                        return -1;
        }

        return 0;
}
