/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Unbind programs
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

#include "irm_ops.h"
#include "irm_utils.h"

static void usage(void)
{
        printf("Usage: irm unbind program <program>\n"
               "                  [name <name> (default: unbind all names)]"
               "\n");
}

int do_unbind_program(int     argc,
                      char ** argv)
{
        char * name = NULL;
        char * prog = NULL;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                        ++argv;
                        --argc;
                } else if (matches(*argv, "program") == 0) {
                        prog = *(argv + 1);
                        ++argv;
                        --argc;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "unbind program\".\n", *argv);
                        return -1;
                }

                ++argv;
                --argc;
        }

        if (prog == NULL) {
                usage();
                return -1;
        }

        return irm_unbind_program(prog, name);
}
