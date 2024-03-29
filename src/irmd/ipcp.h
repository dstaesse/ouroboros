/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The API for the IRM to instruct IPCPs
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

#include <ouroboros/ipcp.h>
#include <ouroboros/protobuf.h>
#include <ouroboros/sockets.h>

#ifndef OUROBOROS_IRMD_IPCP_H
#define OUROBOROS_IRMD_IPCP_H

int   ipcp_enroll(pid_t               pid,
                  const char *        dst,
                  struct layer_info * info);

int   ipcp_bootstrap(pid_t                pid,
                     struct ipcp_config * conf,
                     struct layer_info *  info);

int   ipcp_connect(pid_t        pid,
                   const char * dst,
                   const char * component,
                   qosspec_t    qs);

int   ipcp_disconnect(pid_t        pid,
                      const char * dst,
                      const char * component);

int   ipcp_reg(pid_t          pid,
               const buffer_t hash);

int   ipcp_unreg(pid_t          pid,
                 const buffer_t hash);

int   ipcp_query(pid_t          pid,
                 const buffer_t dst);

int   ipcp_flow_alloc(const struct flow_info * flow,
                      const buffer_t           hash,
                      const buffer_t           data);

int   ipcp_flow_join(const struct flow_info * flow,
                     const buffer_t           dst);

int   ipcp_flow_alloc_resp(const struct flow_info * flow,
                           int                      response,
                           const buffer_t           data);

int   ipcp_flow_dealloc(pid_t  pid,
                        int    flow_id,
                        time_t timeo);

#endif /* OUROBOROS_IRMD_IPCP_H */
