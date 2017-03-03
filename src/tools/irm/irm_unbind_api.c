/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Unbind AP-I names
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage(void)
{
        printf("Usage: irm unbind api <pid>\n"
               "                  [name <name> (default: remove all AP-I info)]"
               "\n");
}

int do_unbind_api(int argc, char ** argv)
{
        pid_t api = -1;
        char * name = NULL;

        while (argc > 1) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                        ++argv;
                        --argc;
                } else if (matches(*argv, "api") == 0) {
                        api = strtol(*(argv + 1), NULL, 10);
                        ++argv;
                        --argc;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "unbind api\".\n", *argv);
                        return -1;
                }

                ++argv;
                --argc;
        }

        if (api < 0) {
                usage();
                return -1;
        }

        return irm_unbind_api(api, name);
}
