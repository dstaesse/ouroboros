/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Logging facilities
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

#ifndef OUROBOROS_LIB_LOGS_H
#define OUROBOROS_LIB_LOGS_H

#ifndef OUROBOROS_PREFIX
#error You must define OUROBOROS_PREFIX before including this file
#endif

#include <ouroboros/hash.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>

#define CLR_RED     "\x1b[31m"
#define CLR_GREEN   "\x1b[32m"
#define CLR_YELLOW  "\x1b[33m"
#define CLR_RESET   "\x1b[0m"

#define DEBUG_CODE "DB"
#define ERROR_CODE "EE"
#define WARN_CODE  "WW"
#define INFO_CODE  "II"

extern bool log_syslog;

void log_init(bool sysout);

void log_fini(void);


#define __olog(CLR, LVL, SYSLVL, ...)                                         \
        do {                                                                  \
                if (log_syslog) {                                             \
                        syslog(SYSLVL, __VA_ARGS__);                          \
                } else {                                                      \
                        printf(CLR "==%05d== " OUROBOROS_PREFIX               \
                               "(" LVL "): ", getpid());                      \
                        printf(__VA_ARGS__);                                  \
                        printf(CLR_RESET "\n");                               \
                        fflush(stdout);                                       \
                }                                                             \
        } while (0)

#define __olog_id(CLR, LVL, SYSLVL, id, fmt, ...)                             \
        do {                                                                  \
                if (log_syslog) {                                             \
                        syslog(SYSLVL, "[" HASH_FMT64 "] " fmt,               \
                               HASH_VAL64(id), ## __VA_ARGS__);               \
                } else {                                                      \
                        printf(CLR "==%05d== " OUROBOROS_PREFIX               \
                               "(" LVL "): ", getpid());                      \
                        printf("[" HASH_FMT64 "] " fmt,                       \
                               HASH_VAL64(id), ## __VA_ARGS__);               \
                        printf(CLR_RESET "\n");                               \
                        fflush(stdout);                                       \
                }                                                             \
        } while (0)

#define log_err(...)                                                          \
         __olog(CLR_RED, ERROR_CODE, LOG_ERR, __VA_ARGS__)
#define log_warn(...)                                                         \
        __olog(CLR_YELLOW, WARN_CODE, LOG_WARNING, __VA_ARGS__)
#define log_info(...)                                                         \
        __olog(CLR_GREEN, INFO_CODE, LOG_INFO, __VA_ARGS__)


#define log_err_id(id, fmt, ...)                                              \
        __olog_id(CLR_RED, ERROR_CODE, LOG_ERR, id, fmt, ## __VA_ARGS__)
#define log_warn_id(id, fmt, ...)                                             \
        __olog_id(CLR_YELLOW, WARN_CODE, LOG_WARNING, id, fmt, ## __VA_ARGS__)
#define log_info_id(id, fmt, ...)                                             \
        __olog_id(CLR_GREEN, INFO_CODE, LOG_INFO, id, fmt, ## __VA_ARGS__)

#ifdef CONFIG_OUROBOROS_DEBUG
#define log_dbg(...)  __olog("", DEBUG_CODE, LOG_DEBUG, __VA_ARGS__)
#define log_dbg_id(id, fmt, ...)                                              \
        __olog_id("", DEBUG_CODE, LOG_DEBUG, id, fmt, ## __VA_ARGS__)
#else
#define log_dbg(...)  do { } while (0)
#define log_dbg_id(...)  do { } while (0)
#endif

#endif /* OUROBOROS_LIB_LOGS_H */
