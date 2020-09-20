/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * The API for the IRM to instruct IPCPs
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
#include <ouroboros/sockets.h>

#include <sys/types.h>

#ifndef OUROBOROS_IRMD_IPCP_H
#define OUROBOROS_IRMD_IPCP_H

pid_t ipcp_create(const char *   name,
                  enum ipcp_type ipcp_type);

int   ipcp_destroy(pid_t pid);

int   ipcp_enroll(pid_t               pid,
                  const char *        dst,
                  struct layer_info * info);

int   ipcp_bootstrap(pid_t               pid,
                     ipcp_config_msg_t * conf,
                     struct layer_info * info);

int   ipcp_connect(pid_t        pid,
                   const char * dst,
                   const char * component,
                   qosspec_t    qs);

int   ipcp_disconnect(pid_t        pid,
                      const char * dst,
                      const char * component);

int   ipcp_reg(pid_t           pid,
               const uint8_t * hash,
               size_t          len);

int   ipcp_unreg(pid_t           pid,
                 const uint8_t * hash,
                 size_t          len);

int   ipcp_query(pid_t           pid,
                 const uint8_t * hash,
                 size_t          len);

int   ipcp_flow_alloc(pid_t           pid,
                      int             flow_id,
                      pid_t           n_pid,
                      const uint8_t * dst,
                      size_t          len,
                      qosspec_t       qs,
                      const void *    data,
                      size_t          dlen);

int   ipcp_flow_join(pid_t           pid,
                     int             flow_id,
                     pid_t           n_pid,
                     const uint8_t * dst,
                     size_t          len,
                     qosspec_t       qs);

int   ipcp_flow_alloc_resp(pid_t        pid,
                           int          flow_id,
                           pid_t        n_pid,
                           int          response,
                           const void * data,
                           size_t       len);

int   ipcp_flow_dealloc(pid_t  pid,
                        int    flow_id,
                        time_t timeo);

#endif /* OUROBOROS_IRMD_IPCP_H */
