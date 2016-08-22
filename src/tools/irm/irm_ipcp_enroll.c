/*
 * Ouroboros - Copyright (C) 2016
 *
 * Enroll IPC Processes
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
#include <stdlib.h>

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage()
{
        printf("Usage: irm ipcp enroll\n"
               "                name <ipcp name>\n"
               "                dif <dif to enroll in>\n");
}

int do_enroll_ipcp(int argc, char ** argv)
{
        char * name = NULL;
        char * dif_name = NULL;
        pid_t * apis = NULL;
        ssize_t len = 0;
        int i = 0;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else if (matches(*argv, "dif") == 0) {
                        dif_name = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "enroll_ipcp\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (dif_name == NULL || name == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(name, &apis);
        if (len <= 0) {
                if (!irm_create_ipcp(name, IPCP_NORMAL))
                        return -1;
                len = irm_list_ipcps(name, &apis);
        }

        for (i = 0; i < len; i++)
                if (irm_enroll_ipcp(apis[i], dif_name))
                        return -1;

        if (apis != NULL)
                free(apis);

        return 0;
}
