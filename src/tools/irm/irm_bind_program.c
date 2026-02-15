/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Bind programs to a name
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

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ouroboros/irm.h>
#include <ouroboros/errno.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage(void)
{
        printf("Usage: irm bind program <program>\n"
               "           name <name>\n"
               "           [auto] (instantiate program if not running)\n"
               "           [-- <application arguments>]\n");
}


int do_bind_program(int     argc,
                    char ** argv)
{
        char *   name  = NULL;
        char *   prog  = NULL;
        uint16_t flags = 0;
        int      ret   = 0;
        char *   temp  = NULL;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                        ++argv;
                        --argc;
                } else if (matches(*argv, "program") == 0) {
                        ++argv;
                        temp = realpath(*argv, NULL);
                        if (temp != NULL)
                                *argv = temp;
                        prog = *argv;
                        --argc;
                } else if (strcmp(*argv, "auto") == 0) {
                        flags |= BIND_AUTO;
                } else if (strcmp(*argv, "--") == 0) {
                        ++argv;
                        --argc;
                        break;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "bind program\".\n", *argv);
                        return -1;
                }

                ++argv;
                --argc;
        }

        if (name == NULL || prog == NULL) {
                usage();
                return -1;
        }

        ret = irm_bind_program(prog, name, flags, argc, argv);
        if (ret == -ENOENT) {
                printf("%s does not exist.\n", prog);
                return ret;
        }

        if (ret == -EPERM) {
                printf("Cannot execute %s, please check permissions.\n", prog);
                return ret;
        }

        if (temp != NULL)
                free(temp);

        return ret;
}
