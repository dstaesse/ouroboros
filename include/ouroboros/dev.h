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

#include <ouroboros/qos.h>

#include <unistd.h>

#ifndef OUROBOROS_DEV_H
#define OUROBOROS_DEV_H

#define UNKNOWN_AE "__UNKNOWN_AE__"

/* These calls should be removed once we write the ouroboros OS. */
int     ap_init(char * ap_name);

void    ap_fini(void);

/* Returns flow descriptor (> 0), client AE name and qos spec. */
int     flow_accept(char **     ae_name,
                    qosspec_t * qos);

int     flow_alloc_resp(int fd,
                        int response);

/*
 * Returns flow descriptor (> 0).
 * On returning, qos will contain the actual supplied QoS.
 */
int     flow_alloc(char *      dst_name,
                   char *      src_ae_name,
                   qosspec_t * qos);

int     flow_alloc_res(int fd);

int     flow_dealloc(int fd);

ssize_t flow_write(int    fd,
                   void * buf,
                   size_t count);

ssize_t flow_read(int    fd,
                  void * buf,
                  size_t count);

#endif
