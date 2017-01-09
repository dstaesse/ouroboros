/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * API for applications
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
                    qosspec_t * spec);

int     flow_alloc_resp(int fd,
                        int response);

/*
 * Returns flow descriptor (> 0).
 * On returning, qos will contain the actual supplied QoS.
 */
int     flow_alloc(char *      dst_name,
                   char *      src_ae_name,
                   qosspec_t * spec);

int     flow_alloc_res(int fd);

int     flow_dealloc(int fd);

ssize_t flow_write(int    fd,
                   void * buf,
                   size_t count);

ssize_t flow_read(int    fd,
                  void * buf,
                  size_t count);

#endif
