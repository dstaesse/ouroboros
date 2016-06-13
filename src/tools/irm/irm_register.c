/*
 * Ouroboros - Copyright (C) 2016
 *
 * Register AP's in DIFs
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

#include <ouroboros/config.h>
#include <stdio.h>
#include <ouroboros/irm.h>
#include <ouroboros/common.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define MAX_DIFS 128

static void usage()
{
        printf("Usage: irm register\n"
               "           n <name>\n"
               "           apn <application process name>\n"
               "           [api <application instance id>]\n"
               "           [auto] (instantiate apn if not running)\n"
               "           [dif <dif name to register with>]\n"
               "           [... (maximum %d difs)]\n"
               "           [-- <application arguments>]\n"
               , MAX_DIFS);
}


int do_register(int argc, char ** argv)
{
        char * name = NULL;
        char ** args = NULL;
        char * difs[MAX_DIFS];
        size_t difs_len = 0;
        bool api_opt = false;
        bool args_opt = false;
        bool autoexec = false;
        int i = argc;

        instance_name_t api = {NULL, 0};

        while (i > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else if (matches(*argv, "apn") == 0) {
                        api.name = *(argv + 1);
                } else if (matches(*argv, "api") == 0) {
                        api.id = atoi(*(argv + 1));
                        api_opt = true;
                } else if (strcmp(*argv, "auto") == 0) {
                        autoexec = true;
                        ++i;
                        --argv;
                } else if (strcmp(*argv, "--") == 0) {
                        ++argv;
                        --i;
                        args_opt = true;
                        break;
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

                i -= 2;
                argv += 2;
        }

        if (name == NULL || api.name == NULL) {
                usage();
                return -1;
        }

        if (api_opt && kill(api.id, 0) < 0) {
                printf("No application running with that pid.");
                return -1;
        }

        if (api_opt && autoexec) {
                printf("Instance is given, auto disabled.\n");
                autoexec = false;
        }

        args = argv;

        if (args_opt && api_opt) {
                printf("Instance is given, args ignored.\n");
                args = NULL;
                i = 0;
        }

        return irm_reg(name, &api, i, args, autoexec, difs, difs_len);
}
