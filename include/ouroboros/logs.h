/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Logging facilities
 *
 *    Sander Vrijders       <sander.vrijders@intec.ugent.be>
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
 *    Dimitri Staessens     <dimitri.staessens@intec.ugent.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_LOGS_H
#define OUROBOROS_LOGS_H

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

#ifndef OUROBOROS_PREFIX
#error You must define OUROBOROS_PREFIX before including this file
#endif

int  set_logfile(char * filename);
void close_logfile(void);

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define DEBUG_CODE "DB"
#define ERROR_CODE "EE"
#define WARN_CODE  "WW"
#define INFO_CODE  "II"
#define IMPL_CODE  "NI"

extern FILE * logfile;

#define __LOG(CLR, FUNC, LVL, ...)                                      \
        do {                                                            \
                if (logfile != NULL) {                                  \
                        fprintf(logfile, OUROBOROS_PREFIX);             \
                        fprintf(logfile, "(" LVL "): ");                \
                        if (FUNC)                                       \
                                fprintf(logfile, "%s: ", __FUNCTION__); \
                        fprintf(logfile, __VA_ARGS__);                  \
                        fprintf(logfile, "\n");                         \
                        fflush(logfile);                                \
                } else {                                                \
                        printf(CLR "==%05d== ", getpid());              \
                        printf(OUROBOROS_PREFIX "(" LVL "): ");         \
                        if (FUNC)                                       \
                                printf("%s: ", __FUNCTION__);           \
                        printf(__VA_ARGS__);                            \
                        printf(ANSI_COLOR_RESET "\n");                  \
                }                                                       \
        } while (0)

#define LOG_ERR(...)  __LOG(ANSI_COLOR_RED, false, ERROR_CODE, __VA_ARGS__)
#define LOG_WARN(...) __LOG(ANSI_COLOR_YELLOW, false, WARN_CODE, __VA_ARGS__)
#define LOG_INFO(...) __LOG(ANSI_COLOR_GREEN, false, INFO_CODE, __VA_ARGS__)
#define LOG_NI(...)   __LOG(ANSI_COLOR_BLUE, false, IMPL_CODE, __VA_ARGS__)

#ifdef CONFIG_OUROBOROS_DEBUG
#define LOG_DBG(...)  __LOG("", false, DEBUG_CODE, __VA_ARGS__)
#define LOG_DBGF(...) __LOG("", true, DEBUG_CODE, __VA_ARGS__)
#else
#define LOG_DBG(...)  do { } while (0)
#define LOG_DBGF(...) do { } while (0)
#endif

#define LOG_MISSING LOG_NI("Missing code in %s:%d",__FILE__, __LINE__)

#endif
