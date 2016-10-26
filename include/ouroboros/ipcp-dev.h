/*
 * Ouroboros - Copyright (C) 2016
 *
 * Additional API for IPCPs
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#include <unistd.h>
#include <time.h>

#include <ouroboros/qos.h>
#include <ouroboros/shm_rdrbuff.h>

#ifndef OUROBOROS_IPCP_DEV_H
#define OUROBOROS_IPCP_DEV_H

int  ipcp_create_r(pid_t api);

int  ipcp_flow_req_arr(pid_t  api,
                       char * dst_name,
                       char * src_ae_name);

int  ipcp_flow_alloc_reply(int fd,
                           int response);

int  ipcp_flow_read(int                   fd,
                    struct shm_du_buff ** sdb);

int  ipcp_flow_write(int                  fd,
                     struct shm_du_buff * sdb);

void ipcp_flow_fini(int fd);

void ipcp_flow_del(struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCP_DEV_H */
