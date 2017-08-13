/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Flows
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

#ifndef OUROBOROS_FCNTL_H
#define OUROBOROS_FCNTL_H

#include <ouroboros/cdefs.h>

#include <sys/time.h>

/* same values as fcntl.h */
#define FLOW_O_RDONLY   00000000
#define FLOW_O_WRONLY   00000001
#define FLOW_O_RDWR     00000002
#define FLOW_O_ACCMODE  00000003

#define FLOW_O_NONBLOCK 00004000
#define FLOW_O_DEFAULT  00000002

#define FLOW_O_INVALID  (FLOW_O_WRONLY | FLOW_O_RDWR)

__BEGIN_DECLS

int flow_set_flags(int fd,
                   int flags);

int flow_get_flags(int fd);

int flow_set_timeout(int                     fd,
                     const struct timespec * to);

int flow_get_timeout(int               fd,
                     struct timespec * to);

int flow_get_qosspec(int         fd,
                     qosspec_t * qs);

__END_DECLS

#endif /* OUROBOROS_FCNTL_H */
