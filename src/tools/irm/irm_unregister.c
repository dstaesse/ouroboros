/*
 * Ouroboros - Copyright (C) 2016
 *
 * Unregister names from IPCPs
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <string.h>

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define MAX_DIFS 128

static void usage()
{
        printf("Usage: irm unregister\n"
               "           name <name>\n"
               "           dif <dif name to unregister from>\n"
               "           [dif <dif name to unregister from>]\n"
               "           [... (maximum %d difs)]\n"
               , MAX_DIFS);
}

int do_unregister(int argc, char ** argv)
{
        char * difs[MAX_DIFS];
        size_t difs_len = 0;
        char * name = NULL;

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
