/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Register names with IPCPs
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_IPCPS  128
#define MAX_LAYERS 128

static void usage(void)
{
        printf("Usage: irm name register <name>\n"
               "           ipcp <ipcp to register with>\n"
               "           [ipcp <ipcp to register with>]\n"
               "           [... (maximum %d ipcps)]\n"
               "           layer <layer to register with>\n"
               "           [layer <layer to register with>]\n"
               "           [... (maximum %d layers)]\n"
               , MAX_IPCPS, MAX_LAYERS);
}


int do_reg_name(int     argc,
                char ** argv)
{
        char *                  name       = NULL;
        char *                  layers[MAX_LAYERS];
        size_t                  layers_len = 0;
        char *                  ipcp[MAX_IPCPS];
        size_t                  ipcp_len   = 0;
        struct ipcp_list_info * ipcps;
        ssize_t                 ipcps_len;
        struct name_info *      names;
        ssize_t                 names_len;
        bool                    name_create = true;
        ssize_t                 i;

        name = *(argv++);
        --argc;

        while (argc > 0) {
                if (matches(*argv, "layer") == 0) {
                        layers[layers_len++] = *(argv + 1);
                        if (layers_len > MAX_LAYERS) {
                                printf("Too many layers specified.\n");
                                return -1;
                        }
                } else if (matches(*argv, "ipcp") == 0) {
                        ipcp[ipcp_len++] = *(argv + 1);
                        if (ipcp_len > MAX_IPCPS) {
                                printf("Too many IPCPs specified.\n");
                                return -1;
                        }
                } else {
                        printf("\"%s\" is unknown, try \"irm name "
                               "register\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if ((layers_len < 1 && ipcp_len < 1) || name == NULL) {
                usage();
                return -1;
        }

        ipcps_len = irm_list_ipcps(&ipcps);
        if (ipcps_len < 0)
                return ipcps_len;

        names_len = irm_list_names(&names);
        if (names_len < 0) {
                free(ipcps);
                return names_len;
        }

        for (i = 0; i < names_len; ++i) {
                if (strcmp(names[i].name, name) == 0) {
                        name_create = false;
                        break;
                }
        }

        if (name_create && irm_create_name(name, LB_SPILL)) {
                printf("Error creating name.");
                free(ipcps);
                free(name);
                return -1;
        }

        for (i = 0; i < ipcps_len; ++i) {
                size_t j;
                for (j = 0; j < layers_len; j++) {
                        if (wildcard_match(layers[j], ipcps[i].layer) == 0) {
                                if (irm_reg_name(name, ipcps[i].pid)) {
                                        free(ipcps);
                                        free(names);
                                        return -1;
                                }
                        }
                }
                for (j = 0; j < ipcp_len; j++) {
                        if (wildcard_match(ipcp[j], ipcps[i].name) == 0) {
                                if (irm_reg_name(name, ipcps[i].pid)) {
                                        free(ipcps);
                                        free(names);
                                        return -1;
                                }
                        }
                }
        }

        free(ipcps);
        free(names);

        return 0;
}
