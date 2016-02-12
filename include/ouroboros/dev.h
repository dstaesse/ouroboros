/*
 * Ouroboros - Copyright (C) 2016
 *
 * API for applications
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#ifndef OUROBOROS_DEV_H
#define OUROBOROS_DEV_H

#include "common.h"

struct qos_spec * list_qos_cubes(rina_name_t dst,
                                 struct qos_spec min_qos);

/* Returns file descriptor */
int ap_reg(rina_name_t name, char ** difs);
int ap_unreg(rina_name_t name, char ** difs);

/* Returns file descriptor (> 0) */
int flow_accept(int fd, rina_name_t * name);
int flow_alloc_resp(int fd, int result);

/* Returns file descriptor */
int flow_alloc(rina_name_t src, rina_name_t dst,
               struct qos_spec qos, int oflags);

/* If flow is accepted returns a value > 0 */
int flow_alloc_res(int fd);
int flow_dealloc(int fd);

/* Wraps around fnctl */
int flow_cntl(int fd, int oflags);
int flow_write(int fd, buffer_t * sdu);
int flow_read(int fd, buffer_t * sdu);

#endif
