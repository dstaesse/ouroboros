/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Register names in IPCPs
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#include <ouroboros/irm.h>

#include <stdio.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define MAX_DIFS 128

static void usage(void)
{
        printf("Usage: irm register\n"
               "           name <name>\n"
               "           dif <dif name to register with>\n"
               "           [dif <dif name to register with>]\n"
               "           [... (maximum %d difs)]\n"
               , MAX_DIFS);
}


int do_register(int argc, char ** argv)
{
        char * name = NULL;
        char * difs[MAX_DIFS];
        size_t difs_len = 0;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else if (matches(*argv, "dif") == 0) {
                        difs[difs_len++] = *(argv + 1);
                        if (difs_len > MAX_DIFS) {
                                printf("Too many difs specified\n");
                                return -1;
                        }
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "register\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (difs_len < 1 || name == NULL) {
                usage();
                return -1;
        }

        return irm_reg(name, difs, difs_len);
}
