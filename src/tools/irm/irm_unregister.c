/*
 * Ouroboros - Copyright (C) 2016
 *
 * Unregister IPC Processes in an N-1 DIF
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
        printf("Usage: irm unregister\n"
               "           [name <name>]\n"
               "           [apn <application process name>]\n"
               "           [api <application process instance>]\n"
               "           dif <dif name to unregister from>\n"
               "           [dif <dif name to unregister from>]\n"
               "           [... (maximum %d difs)]\n"
               "           [hard] (unregisters everything using that name)\n"
               , MAX_DIFS);
}

int do_unregister(int argc, char ** argv)
{
        instance_name_t api = {NULL, 0};
        char * difs[MAX_DIFS];
        size_t difs_len = 0;
        char * name = NULL;
        bool hard_opt = false;
        bool ap_id = false;
        instance_name_t * ptr_api = NULL;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else if (matches(*argv, "ap") == 0) {
                        api.name = *(argv + 1);
                        ptr_api = &api;
                } else if (matches(*argv, "api") == 0) {
                        api.id = atoi(*(argv + 1));
                        ap_id = true;
                } else if (strcmp(*argv, "hard") == 0) {
                        hard_opt = true;
                        /* this has no value */
                        ++argc;
                        --argv;
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

        if (difs_len == 0) {
                usage();
                return -1;
        }

        if (name == NULL && api.name == NULL) {
                printf("apn or name must be set.\n");
                usage();
                return -1;
        }

        if (ap_id && api.name == NULL) {
                printf("api requires apn.\n");
                usage();
                return -1;
        }

        if (hard_opt && api.name != NULL) {
                printf("apn and/or api must not be set when using hard.\n");
                usage();
                return -1;
        }

        return irm_unreg(name, ptr_api, difs, difs_len, hard_opt);
}
