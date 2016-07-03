/*
 * Ouroboros - Copyright (C) 2016
 *
 * Bind AP to a name
 *
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
#include <sys/stat.h>

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage()
{
        printf("Usage: irm bind\n"
               "           name <name>\n"
               "           apn <application process name>\n"
               "           [auto] (instantiate apn if not running)\n"
               "           [unique] (there can only be one instantiation)\n"
               "           [-- <application arguments>]\n");
}


int do_bind(int argc, char ** argv)
{
        char * name = NULL;
        char * ap_name = NULL;
        uint16_t flags = 0;
        struct stat s;

        while (argc > 0) {
                if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                        ++argv;
                        --argc;
                } else if (matches(*argv, "apn") == 0) {
                        ap_name = *(argv + 1);
                        ++argv;
                        --argc;
                } else if (strcmp(*argv, "auto") == 0) {
                        flags |= BIND_AP_AUTO;
                } else if (strcmp(*argv, "unique") == 0) {
                        flags |= BIND_AP_UNIQUE;
                } else if (strcmp(*argv, "--") == 0) {
                        ++argv;
                        --argc;
                        break;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "bind\".\n", *argv);
                        return -1;
                }

                ++argv;
                --argc;
        }

        if (name == NULL || ap_name == NULL) {
                usage();
                return -1;
        }

        if (stat(ap_name, &s) != 0) {
                printf("Application %s does not exist.\n\n", ap_name);
                return -1;
        }

        if (!(s.st_mode & S_IXUSR)) {
                printf("Application %s is not executable.\n\n", ap_name);
                return -1;
        }

        return irm_bind(name, ap_name, flags, argc, argv);
}
