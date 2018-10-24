/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Enroll IPC Processes
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

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

#include <string.h>

#define NORMAL    "normal"
#define BROADCAST "broadcast"

static void usage(void)
{
        printf("Usage: irm ipcp enroll\n"
               "                name <ipcp name>\n"
               "                layer <layer to enroll in>\n"
               "                [type [TYPE], default = normal]\n"
               "                [autobind]\n"
               "where TYPE = {" NORMAL " " BROADCAST "}\n");
}

int do_enroll_ipcp(int     argc,
                   char ** argv)
{
        char *             ipcp      = NULL;
        char *             layer     = NULL;
        struct ipcp_info * ipcps;
        pid_t              pid       = -1;
        ssize_t            len       = 0;
        int                i         = 0;
        bool               autobind  = false;
        int                cargs;
        char *             ipcp_type = NORMAL;
        enum ipcp_type     type      = IPCP_INVALID;

        while (argc > 0) {
                cargs = 2;
                if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
                } else if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "layer") == 0) {
                        layer = *(argv + 1);
                } else if (matches(*argv, "autobind") == 0) {
                        autobind = true;
                        cargs = 1;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "enroll_ipcp\".\n", *argv);
                        return -1;
                }

                argc -= cargs;
                argv += cargs;
        }

        if (layer == NULL || ipcp == NULL) {
                usage();
                return -1;
        }

        if (strcmp(ipcp_type, NORMAL) == 0)
                type = IPCP_NORMAL;
        else if (strcmp(ipcp_type, BROADCAST) == 0)
                type = IPCP_BROADCAST;

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++)
                if (wildcard_match(ipcps[i].name, ipcp) == 0 &&
                    ipcps[i].type == type)
                        pid = ipcps[i].pid;

        if (pid < 0) {
                pid = irm_create_ipcp(ipcp, type);
                if (pid < 0)
                        goto fail;
                free(ipcps);
                len = irm_list_ipcps(&ipcps);
        }

        for (i = 0; i < len; i++) {
                if (ipcps[i].type != type)
                        continue;
                if (wildcard_match(ipcps[i].name, ipcp) == 0) {
                        pid = ipcps[i].pid;
                        if (autobind && irm_bind_process(pid, ipcp)) {
                                printf("Failed to bind %d to %s.\n", pid, ipcp);
                                goto fail;
                        }

                        if (irm_enroll_ipcp(pid, layer)) {
                                if (autobind)
                                        irm_unbind_process(pid, ipcp);
                                goto fail;
                        }

                        if (autobind && irm_bind_process(pid, layer)) {
                                printf("Failed to bind %d to %s.\n",
                                       pid, layer);
                                goto fail;
                        }
                }
        }

        free(ipcps);

        return 0;

 fail:
        free(ipcps);
        return -1;
}
