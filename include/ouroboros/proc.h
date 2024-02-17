/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Processes and Programs
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_PROC_H
#define OUROBOROS_LIB_PROC_H

#include <sys/types.h>

#define PROG_NAME_SIZE 255
#define PROG_PATH_SIZE 255

/* Processes */
struct proc_info {
        pid_t pid;
        char  prog[PROG_NAME_SIZE + 1];  /* program instantiated */

};

/* Programs */
struct prog_info {
        char name[PROG_NAME_SIZE + 1];
        char path[PROG_PATH_SIZE + 1];
};

#endif /* OUROBOROS_LIB_PROC_H */