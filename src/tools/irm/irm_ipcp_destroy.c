/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Destroy IPC Processes
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#include "irm_ops.h"
#include "irm_utils.h"

static void usage(void)
{
        printf("Usage: irm ipcp destroy\n"
               "                name <ipcp name>\n");
}

int do_destroy_ipcp(int argc, char ** argv)
{
        char *  name = NULL;
        pid_t * apis;
        ssize_t len = 0;
        int     i = 0;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcp destroy\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (name == NULL) {
                usage();
                return -1;
        }

        len = irm_list_ipcps(name, &apis);
        if (len <= 0)
                return -1;

        for (i = 0; i < len; i++)
                if (irm_destroy_ipcp(apis[i]))
                        return -1;

        free(apis);

        return 0;
}
