/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager - Utilities
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

size_t argvlen(char ** argv)
{
        size_t argc   = 0;

        if (argv == NULL)
                return 0;

        while (*argv++ != NULL)
                argc++;

        return argc;
}

void argvfree(char ** argv)
{
        char ** argv_dup;

        if (argv == NULL)
                return;

        argv_dup = argv;
        while (*argv_dup != NULL)
                free(*(argv_dup++));

        free(argv);
}

char ** argvdup(char ** argv)
{
        int     argc = 0;
        char ** argv_dup = argv;
        int     i;

        if (argv == NULL)
                return NULL;

        while (*(argv_dup++) != NULL)
                argc++;

        argv_dup = malloc((argc + 1) * sizeof(*argv_dup));
        if (argv_dup == NULL)
                return NULL;

        for (i = 0; i < argc; ++i) {
                argv_dup[i] = strdup(argv[i]);
                if (argv_dup[i] == NULL) {
                        argvfree(argv_dup);
                        return NULL;
                }
        }

        argv_dup[argc] = NULL;
        return argv_dup;
}
