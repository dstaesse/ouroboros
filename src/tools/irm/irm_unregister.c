/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Unregister names from IPCPs
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
#include <string.h>

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define MAX_LAYERS 128

static void usage(void)
{
        printf("Usage: irm unregister\n"
               "           name <name>\n"
               "           layer <layer to unregister from>\n"
               "           [layer <layer to unregister from>]\n"
               "           [... (maximum %d layers)]\n"
               , MAX_LAYERS);
}

int do_unregister(int argc, char ** argv)
{
        char * difs[MAX_LAYERS];
        size_t difs_len = 0;
        char * name = NULL;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else if (matches(*argv, "layer") == 0) {
                        difs[difs_len++] = *(argv + 1);
                        if (difs_len > MAX_LAYERS) {
                                printf("Too many difs specified\n");
                                return -1;
                        }
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "unregister\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (difs_len == 0 || name == NULL) {
                usage();
                return -1;
        }

        return irm_unreg(name, difs, difs_len);
}
