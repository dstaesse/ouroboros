/*
 * Ouroboros - Copyright (C) 2016
 *
 * Create IPC Processes
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
#include <ouroboros/irm.h>
#include <ouroboros/common.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage()
{
        printf("Usage: irm create_ipcp\n"
               "           ap <application process name>\n"
               "           [api <application process instance>]\n"
               "           [ae <application entity name]\n"
               "           [aei <application entity instance>]\n"
               "           type <ipc process type>\n");
}

int do_create_ipcp(int argc, char ** argv)
{
        rina_name_t name;
        char * ipcp_type = NULL;

        name.ap_name = NULL;
        name.api_id = 0;
        name.ae_name = "";
        name.aei_id = 0;

        while (argc > 0) {
                if (!parse_name(argv, &name)) {
                        if (matches(*argv, "type") == 0) {
                                ipcp_type = *(argv + 1);
                        } else {
                                printf("\"%s\" is unknown, try \"irm "
                                       "create_ipcp\".\n", *argv);
                                return -1;
                        }
                }

                argc -= 2;
                argv += 2;
        }

        if (ipcp_type == NULL || name.ap_name == NULL) {
                usage();
                return -1;
        }

        return irm_create_ipcp(name, ipcp_type);
}
