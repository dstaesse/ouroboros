/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Connect components of normal IPC Processes
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

#define DT      "dt"
#define MGMT    "mgmt"

static void usage(void)
{
        printf("Usage: irm ipcp disconnect\n"
               "                name      <ipcp name>\n"
               "                component [COMPONENT]\n"
               "                dst       <name of destination IPCP>\n\n"
               "where COMPONENT = {" DT " " MGMT "}\n");
}

int do_disconnect_ipcp(int     argc,
                       char ** argv)
{
        char *  name      = NULL;
        char *  dst_name  = NULL;
        char *  comp_name = NULL;
        pid_t * pids      = NULL;
        ssize_t len       = 0;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else if (matches(*argv, "dst") == 0) {
                        dst_name = *(argv + 1);
                } else if (matches(*argv, "component") == 0) {
                        comp_name = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcpi connect\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (name == NULL || dst_name == NULL || comp_name == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(name, &pids);
        if (len != 1)
                return -1;

        if (!strcmp(comp_name, DT))
                comp_name = DT_COMP;

        if (!strcmp(comp_name , MGMT))
                comp_name = MGMT_COMP;

        if (irm_disconnect_ipcp(pids[0], dst_name, comp_name)) {
                free(pids);
                return -1;
        }

        if (pids != NULL)
                free(pids);

        return 0;
}
