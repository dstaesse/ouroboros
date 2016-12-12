/*
 * Ouroboros - Copyright (C) 2016
 *
 * Flows
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#ifndef OUROBOROS_FCNTL_H
#define OUROBOROS_FCNTL_H

#include <sys/time.h>

/* same values as fcntl.h */
#define FLOW_O_RDONLY   00000000
#define FLOW_O_WRONLY   00000001
#define FLOW_O_RDWR     00000002
#define FLOW_O_ACCMODE  00000003

#define FLOW_O_NONBLOCK 00004000
#define FLOW_O_DEFAULT  00000002

#define FLOW_O_INVALID  (FLOW_O_WRONLY | FLOW_O_RDWR)

int               flow_set_flags(int fd,
                                 int flags);

int               flow_get_flags(int fd);

int               flow_set_timeout(int               fd,
                                   struct timespec * to);

int               flow_get_timeout(int               fd,
                                   struct timespec * to);

int               flow_get_qosspec(int         fd,
                                   qosspec_t * spec);

#endif /* OUROBOROS_FCNTL_H */
