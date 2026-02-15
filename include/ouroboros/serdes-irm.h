/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Ouroboros IRM Protocol - serialization/deserialization
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_SERDES_IRM_H
#define OUROBOROS_LIB_SERDES_IRM_H

#include <ouroboros/crypt.h>
#include <ouroboros/flow.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/proc.h>
#include <ouroboros/time.h>
#include <ouroboros/utils.h>

#include <inttypes.h>

int flow_alloc__irm_req_ser(buffer_t *               buf,
                            const struct flow_info * flow,
                            const char *             dst,
                            const struct timespec *  timeo);

int flow_join__irm_req_ser(buffer_t *               buf,
                           const struct flow_info * flow,
                           const char *             dst,
                           const struct timespec *  timeo);

int flow_accept__irm_req_ser(buffer_t *               buf,
                             const struct flow_info * flow,
                             const struct timespec *  timeo);

int ipcp_flow_req_arr__irm_req_ser(buffer_t *               buf,
                                   const buffer_t *         dst,
                                   const struct flow_info * flow,
                                   const buffer_t *         data);

int ipcp_flow_alloc_reply__irm_msg_ser(buffer_t *               buf,
                                       const struct flow_info * flow,
                                       int                      response,
                                       const buffer_t *         data);

int flow__irm_result_des(buffer_t *         buf,
                         struct flow_info * flow,
                         struct crypt_sk *  sk);

int flow_dealloc__irm_req_ser(buffer_t *               buf,
                              const struct flow_info * flow,
                              const struct timespec *  timeo);

int ipcp_flow_dealloc__irm_req_ser(buffer_t *               buf,
                                   const struct flow_info * info);

int ipcp_create_r__irm_req_ser(buffer_t *               buf,
                               const struct ipcp_info * ipcp);

int proc_announce__irm_req_ser(buffer_t *               buf,
                               const struct proc_info * proc);

int proc_exit__irm_req_ser(buffer_t *   buf);

int irm__irm_result_des(buffer_t * buf);

#endif /* OUROBOROS_LIB_SERDES_IRM_H*/
