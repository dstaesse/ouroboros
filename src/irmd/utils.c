/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * The IPC Resource Manager - Utilities
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

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

void argvfree(char ** argv)
{
        char ** argv_dup = argv;
        if (argv == NULL)
                return;

        while (*argv_dup != NULL)
                free(*(argv_dup++));

        free(argv);
}

char ** argvdup(char ** argv)
{
        int argc = 0;
        char ** argv_dup = argv;
        int i;

        if (argv == NULL)
                return NULL;

        while (*(argv_dup++) != NULL)
                argc++;

        if (argc != 0) {
                argv_dup = malloc((argc + 1) * sizeof(*argv_dup));
                for (i = 0; i < argc; ++i) {
                        argv_dup[i] = strdup(argv[i]);
                        if (argv_dup[i] == NULL) {
                                argvfree(argv_dup);
                                return NULL;
                        }
                }
        }
        argv_dup[argc] = NULL;
        return argv_dup;
}
