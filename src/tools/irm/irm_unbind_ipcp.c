/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Unbind name from IPCP Instance
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

#include <stdio.h>
#include <stdlib.h>

#include <ouroboros/irm.h>
#include <ouroboros/errno.h>

#include "irm_ops.h"
#include "irm_utils.h"

#include <string.h>

static void usage(void)
{
        printf("Usage: irm unbind ipcp <name>\n"
               "                  [name <name> (default: remove all IPCP info)]"
               "\n");
}

int do_unbind_ipcp(int     argc,
                   char ** argv)
{
        char *             ipcp = NULL;
        char *             name = NULL;
        struct ipcp_info * ipcps;
        ssize_t            len;
        ssize_t            i;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                        ++argv;
                        --argc;
                } else if (matches(*argv, "ipcp") == 0) {
                        ipcp = *(argv + 1);
                        ++argv;
                        --argc;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "unbind ipcp\".\n", *argv);
                        return -1;
                }

                ++argv;
                --argc;
        }

        if (ipcp == NULL || name  == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; ++i)
                if (strcmp(ipcps[i].name, ipcp) == 0) {
                        if (irm_unbind_process(ipcps[i].pid, name)) {
                                free(ipcps);
                                return -1;
                        }
                        break;
                }

        free(ipcps);

        return 0;
}
