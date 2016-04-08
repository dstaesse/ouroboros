/*
 * Ouroboros - Copyright (C) 2016
 *
 * Bootstrap IPC Processes
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
#include <ouroboros/dif_config.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage()
{
        /* FIXME: Add dif_config stuff */
        printf("Usage: irm bootstrap_ipcp\n"
               "           ap <application process name>\n"
               "           [api <application process instance>]\n");
}

int do_bootstrap_ipcp(int argc, char ** argv)
{
        instance_name_t api = {NULL, 0};
        struct dif_config conf;

        while (argc > 0) {
                if (matches(*argv, "ap") == 0) {
                        api.name = *(argv + 1);
                } else if (matches(*argv, "api") == 0) {
                        api.id = atoi(*(argv + 1));
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "destroy_ipcp\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (api.name == NULL) {
                usage();
                return -1;
        }

        return irm_bootstrap_ipcp(&api, &conf);
}
