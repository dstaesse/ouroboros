/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Connect components of normal IPC Processes
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

#include "irm_ops.h"
#include "irm_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DT      "dt"
#define MGMT    "mgmt"

static void usage(void)
{
        printf("Usage: irm ipcp disconnect\n"
               "                name <ipcp name>\n"
               "                comp <COMPONENT>\n"
               "                dst  <name of destination IPCP>\n"
               "where COMPONENT = {" DT " " MGMT "},\n\n");
}

int do_disconnect_ipcp(int     argc,
                       char ** argv)
{
        char *  name      = NULL;
        char *  dst_name  = NULL;
        char *  comp_name = NULL;
        pid_t * apis      = NULL;
        ssize_t len       = 0;

        while (argc > 0) {
                if (strcmp(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else if (matches(*argv, "dst") == 0) {
                        dst_name = *(argv + 1);
                } else if (matches(*argv, "comp") == 0) {
                        comp_name = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcpi connect\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (name == NULL || dst_name == NULL || comp_name == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(name, &apis);
        if (len != 1)
                return -1;

        if (!strcmp(comp_name, DT))
                comp_name = DT_AE;

        if (!strcmp(comp_name , MGMT))
                comp_name = MGMT_AE;

        if (irm_disconnect_ipcp(apis[0], dst_name, comp_name)) {
                free(apis);
                return -1;
        }

        if (apis != NULL)
                free(apis);

        return 0;
}
