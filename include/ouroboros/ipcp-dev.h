/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Additional API for IPCPs
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#include <ouroboros/shm_rdrbuff.h>

#ifndef OUROBOROS_IPCP_DEV_H
#define OUROBOROS_IPCP_DEV_H

int  ipcp_create_r(pid_t api,
                   int   result);

int  ipcp_flow_req_arr(pid_t  api,
                       char * dst_name,
                       char * src_ae_name,
                       qoscube_t cube);

int  ipcp_flow_alloc_reply(int fd,
                           int response);

int  ipcp_flow_read(int                   fd,
                    struct shm_du_buff ** sdb);

int  ipcp_flow_write(int                  fd,
                     struct shm_du_buff * sdb);

void ipcp_flow_fini(int fd);

void ipcp_flow_del(struct shm_du_buff * sdb);

int  ipcp_flow_get_qoscube(int         fd,
                           qoscube_t * cube);

#endif /* OUROBOROS_IPCP_DEV_H */
