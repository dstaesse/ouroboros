/*
 * Ouroboros - Copyright (C) 2016 - 2019
 *
 * Additional API for IPCPs
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

#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/qoscube.h>

#ifndef OUROBOROS_IPCP_DEV_H
#define OUROBOROS_IPCP_DEV_H

int  ipcp_create_r(pid_t pid,
                   int   result);

int  ipcp_flow_req_arr(pid_t           pid,
                       const uint8_t * dst,
                       size_t          len,
                       qosspec_t       qs);

int  ipcp_flow_alloc_reply(int fd,
                           int response);

int  ipcp_flow_read(int                   fd,
                    struct shm_du_buff ** sdb);

int  ipcp_flow_write(int                  fd,
                     struct shm_du_buff * sdb);

int  ipcp_flow_fini(int fd);

int  ipcp_flow_get_qoscube(int         fd,
                           qoscube_t * cube);

int  ipcp_sdb_reserve(struct shm_du_buff ** sdb,
                      size_t                len);

void ipcp_sdb_release(struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCP_DEV_H */
