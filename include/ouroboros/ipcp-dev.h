/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Additional API for IPCPs
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#ifndef OUROBOROS_LIB_IPCP_DEV_H
#define OUROBOROS_LIB_IPCP_DEV_H

#include <ouroboros/ipcp.h>
#include <ouroboros/qoscube.h>
#include <ouroboros/ssm_pool.h>
#include <ouroboros/utils.h>

int    ipcp_create_r(const struct ipcp_info * info);

int    ipcp_flow_req_arr(const buffer_t * dst,
                         qosspec_t        qs,
                         time_t           mpl,
                         const buffer_t * data);

int    ipcp_flow_alloc_reply(int              fd,
                             int              response,
                             time_t           mpl,
                             const buffer_t * data);

int    ipcp_flow_read(int                   fd,
                      struct ssm_pk_buff ** spb);

int    ipcp_flow_write(int                  fd,
                       struct ssm_pk_buff * spb);

int    np1_flow_read(int                   fd,
                     struct ssm_pk_buff ** spb,
                     struct ssm_pool *     pool);

int    np1_flow_write(int                  fd,
                      struct ssm_pk_buff * spb,
                      struct ssm_pool *    pool);

int    ipcp_flow_dealloc(int fd);

int    ipcp_flow_fini(int fd);

int    ipcp_flow_get_qoscube(int         fd,
                             qoscube_t * cube);

size_t ipcp_flow_queued(int fd);

int    ipcp_spb_reserve(struct ssm_pk_buff ** spb,
                        size_t                len);

void   ipcp_spb_release(struct ssm_pk_buff * spb);

#endif /* OUROBOROS_LIB_IPCP_DEV_H */
