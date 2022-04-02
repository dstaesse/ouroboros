/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Utils of the IPC Resource Manager
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

#ifndef OUROBOROS_IRMD_UTILS_H
#define OUROBOROS_IRMD_UTILS_H

#include <sys/types.h>

struct str_el {
        struct list_head next;
        char *           str;
};

struct pid_el {
        struct list_head next;
        pid_t            pid;
};

/* functions for copying and destroying arguments list */
char ** argvdup(char ** argv);

void    argvfree(char ** argv);

#endif /* OUROBOROS_IRM_UTILS_H */
