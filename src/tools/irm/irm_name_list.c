/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * List names
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
#include <ouroboros/errno.h>

#include "irm_ops.h"
#include "irm_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RR    "round-robin"
#define SPILL "spillover"

static char * str_pol(enum pol_balance p)
{
        switch(p) {
        case LB_RR:
                return RR;
        case LB_SPILL:
                return SPILL;
        default:
                return "UNKNOWN";
        }
};

int do_list_name(int     argc,
                 char ** argv)
{
        char *             name = NULL;
        struct name_info * names;
        ssize_t            len;
        ssize_t            i;

        while (argc > 0) {
                if (matches(*argv, "list") == 0) {
                        name = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "name list.\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        len = irm_list_names(&names);
        if (len == 0) {
                printf("No names in system.\n\n");
                return 0;
        } else if (len == -EIRMD) {
                printf("Failed to communicate with the "
                       "Ouroboros IPC Resource Manager daemon.\n");
                return -1;
        } else if (len < 0)
                return len;

        printf("+----------------------------------------------------"
               "+----------------------+\n");
        printf("| %50s | %20s |\n", "name", "load-balance policy");
        printf("+----------------------------------------------------"
               "+----------------------+\n");

        for (i = 0; i < len; i++) {
                if (name != NULL && matches(names[i].name, name))
                        continue;
                printf("| %50s | %20s |\n",
                       names[i].name,
                       str_pol(names[i].pol_lb));
        }
        printf("+----------------------------------------------------"
               "+----------------------+\n");

        free(names);

        return 0;
}
