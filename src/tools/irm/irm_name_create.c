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

#define RR    "round-robin"
#define SPILL "spillover"

static void usage(void)
{
        printf("Usage: irm name create\n"
               "                <name>\n"
               "                lb [LB_POLICY], default: %s\n\n"
               "where LB_POLICY in {" RR " " SPILL "}\n", RR);
}

int do_create_name(int     argc,
                   char ** argv)
{
        char * name             = NULL;
        char * lb_pol           = RR;
        enum pol_balance pol_lb = LB_RR;

        name = *(argv++);
        --argc;

        while (argc > 0) {
                if (matches(*argv, "lb") == 0) {
                        lb_pol = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "name create\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (name == NULL) {
                usage();
                return -1;
        }

        if (strcmp(lb_pol, RR) == 0)
                pol_lb = LB_RR;
        else if (strcmp(lb_pol, SPILL) == 0)
                pol_lb = LB_SPILL;
        else {
                usage();
                return -1;
        }

        return irm_create_name(name, pol_lb);
}
