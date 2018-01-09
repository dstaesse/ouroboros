/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Bind a process to a name
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

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>

#include <ouroboros/irm.h>
#include <ouroboros/errno.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage(void)
{
        printf("Usage: irm bind process <pid> name <name>\n");
}

int do_bind_process(int     argc,
                    char ** argv)
{
        pid_t  pid  = -1;
        char * name = NULL;
        char * t;

        while (argc > 1) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                        ++argv;
                        --argc;
                } else if (matches(*argv, "process") == 0) {
                        pid = strtol(*(argv + 1), &t, 10);
                        if (*(argv + 1) == t || *t != '\0' || kill(pid, 0)) {
                                printf("\"%s\" is not a valid process id.\n",
                                       *(argv + 1));
                                return -1;
                        }
                        ++argv;
                        --argc;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "bind process\".\n", *argv);
                        return -1;
                }

                ++argv;
                --argc;
        }

        if (argc == 1 || pid < 0 || name == NULL) {
                usage();
                return -1;
        }

        return irm_bind_process(pid, name);
}
