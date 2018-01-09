/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * API for applications
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

#ifndef OUROBOROS_DEV_H
#define OUROBOROS_DEV_H

#include <ouroboros/cdefs.h>
#include <ouroboros/qos.h>

#include <unistd.h>
#include <time.h>

__BEGIN_DECLS

/* Returns flow descriptor, qs updates to supplied QoS. */
int     flow_alloc(const char *            dst_name,
                   qosspec_t *             qs,
                   const struct timespec * timeo);

/* Returns flow descriptor, qs updates to supplied QoS. */
int     flow_accept(qosspec_t *             qs,
                    const struct timespec * timeo);

int     flow_dealloc(int fd);

ssize_t flow_write(int          fd,
                   const void * buf,
                   size_t       count);

ssize_t flow_read(int    fd,
                  void * buf,
                  size_t count);

__END_DECLS

#endif /* OUROBOROS_DEV_H */
