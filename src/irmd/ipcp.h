/*
 * Ouroboros - Copyright (C) 2016 - 2017
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/ipcp.h>
#include <ouroboros/sockets.h>
#include <ouroboros/shared.h>

#include <sys/types.h>

#ifndef OUROBOROS_IRMD_IPCP_H
#define OUROBOROS_IRMD_IPCP_H

pid_t ipcp_create(const char *   name,
                  enum ipcp_type ipcp_type);

int   ipcp_destroy(pid_t api);

int   ipcp_enroll(pid_t        api,
                  const char * dst);

int   ipcp_bootstrap(pid_t              api,
                     ipcp_config_msg_t * conf);

int   ipcp_reg(pid_t           api,
               const uint8_t * hash,
               size_t          len);

int   ipcp_unreg(pid_t           api,
                 const uint8_t * hash,
                 size_t          len);

int   ipcp_query(pid_t           api,
                 const uint8_t * hash,
                 size_t          len);

int   ipcp_flow_alloc(pid_t           api,
                      int             port_id,
                      pid_t           n_api,
                      const uint8_t * dst,
                      size_t          len,
                      qoscube_t       qos);

int   ipcp_flow_alloc_resp(pid_t api,
                           int   port_id,
                           pid_t n_api,
                           int   response);

int   ipcp_flow_dealloc(pid_t api,
                        int   port_id);

#endif /* OUROBOROS_IRMD_IPCP_H */
