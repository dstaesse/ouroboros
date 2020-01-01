/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Logging facilities
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#define OUROBOROS_PREFIX "logging"

#include <ouroboros/logs.h>

bool log_syslog;

void log_init(bool sysout)
{
        log_syslog = sysout;

        if (log_syslog)
                openlog(NULL, LOG_PID, LOG_DAEMON);
}

void log_fini(void)
{
        if (log_syslog)
                closelog();
}
