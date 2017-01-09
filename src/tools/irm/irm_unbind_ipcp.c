/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Unbind name from IPCP Instance
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#include <ouroboros/irm.h>
#include <ouroboros/errno.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage(void)
{
        printf("Usage: irm unbind ipcp <name>\n"
               "                  [name <name> (default: remove all IPCP info)]"
               "\n");
}

int do_unbind_ipcp(int argc, char ** argv)
{
        char * ipcp = NULL;
        char * name = NULL;

        pid_t * apis = NULL;
        ssize_t len  = 0;

        int i;

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

        if (ipcp == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(ipcp, &apis);

        for (i = 0; i < len; ++i)
                irm_unbind_api(apis[i], name);

        free(apis);

        return 0;
}
