/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Connect components of unicast or broadcast IPC processes
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
#include <ouroboros/qos.h>

#include "irm_ops.h"
#include "irm_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DT   "dt"
#define MGMT "mgmt"

static void usage(void)
{
        printf("Usage: irm ipcp connect\n"
               "                name      <ipcp name>\n"
               "                dst       <name of destination IPCP>\n"
               "                [component [COMPONENT]]\n"
               "where COMPONENT = {" DT " " MGMT "}\n\n"
               "if COMPONENT == " DT "\n"
               "                [qos       [QOS]\n"
               "where QOS       = {raw, best, voice, video, data}\n\n");
}

int do_connect_ipcp(int     argc,
                    char ** argv)
{
        char *             ipcp      = NULL;
        char *             dst       = NULL;
        char *             comp      = "*";
        char *             component = NULL;
        char *             qos       = NULL;
        struct ipcp_info * ipcps;
        ssize_t            len       = 0;
        pid_t              pid       = -1;
        ssize_t            i;
        qosspec_t          qs        = qos_raw;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
                } else if (matches(*argv, "dst") == 0) {
                        dst = *(argv + 1);
                } else if (matches(*argv, "component") == 0) {
                        comp = *(argv + 1);
                } else if (matches(*argv, "qos") == 0) {
                        qos = *(argv + 1);
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

        if (qos != NULL) {
                if (strcmp(qos, "best") == 0)
                        qs = qos_best_effort;
                else if (strcmp(qos, "raw") == 0)
                        qs = qos_raw;
                else if (strcmp(qos, "video") == 0)
                        qs = qos_video;
                else if (strcmp(qos, "voice") == 0)
                        qs = qos_voice;
                else if (strcmp(qos, "data") == 0)
                        qs = qos_data;
                else
                        printf("Unknown QoS cube, defaulting to raw.\n");
        }

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++)
                if (strcmp(ipcps[i].name, ipcp) == 0)
                        pid = ipcps[i].pid;

        free(ipcps);

        if (pid == -1)
                return -1;

        if (wildcard_match(comp, MGMT) == 0) {
                component = MGMT_COMP;
                /* FIXME: move to qos_data when stable */
                if (irm_connect_ipcp(pid, dst, component, qos_raw))
                        return -1;
        }

        if (wildcard_match(comp, DT) == 0) {
                component = DT_COMP;
                if (irm_connect_ipcp(pid, dst, component, qs))
                        return -1;
        }

        return 0;
}
