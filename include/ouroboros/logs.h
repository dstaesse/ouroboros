/*
 * Ouroboros - Copyright (C) 2016
 *
 * Logging facilities
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
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

#ifndef OUROBOROS_LOGS_H
#define OUROBOROS_LOGS_H

#include <stdio.h>

#ifndef OUROBOROS_PREFIX
#error You must define OUROBOROS_PREFIX before including this file
#endif

#define __LOG(PFX, LVL, FMT, ARGS...)                                   \
        do { printf(PFX "(" LVL "): " FMT "\n", ##ARGS); } while (0)

#define LOG_ERR(FMT,   ARGS...) __LOG(OUROBOROS_PREFIX, "ERR",  FMT, ##ARGS)
#define LOG_WARN(FMT,  ARGS...) __LOG(OUROBOROS_PREFIX, "WARN", FMT, ##ARGS)
#define LOG_INFO(FMT,  ARGS...) __LOG(OUROBOROS_PREFIX, "INFO", FMT, ##ARGS)

#ifdef CONFIG_OUROBOROS_DEBUG
#define LOG_DBG(FMT,   ARGS...) __LOG(OUROBOROS_PREFIX, "DBG", FMT, ##ARGS)
#else
#define LOG_DBG(FMT,   ARGS...) do { } while (0)
#endif

#define LOG_MISSING LOG_ERR("Missing code in %s:%d",__FILE__, __LINE__)

#endif
