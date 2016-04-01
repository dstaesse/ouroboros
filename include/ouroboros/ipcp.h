/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API for the IRM to instruct IPCPs
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

#ifndef OUROBOROS_IPCP_H
#define OUROBOROS_IPCP_H

#include <ouroboros/common.h>
#include <ouroboros/instance_name.h>

#include <sys/types.h>

struct ipcp;

/* Returns the process id */
pid_t ipcp_create(instance_name_t * api,
                  char *            ipcp_type);
int   ipcp_destroy(pid_t pid);

int   ipcp_reg(pid_t   pid,
               char ** difs,
               size_t  difs_size);
int   ipcp_unreg(pid_t   pid,
                 char ** difs,
                 size_t  difs_size);

int   ipcp_bootstrap(pid_t               pid,
                     struct dif_config * conf);
int   ipcp_enroll(pid_t  pid,
                  char * member_name,
                  char * n_1_dif);

/* Flow related ops, these go from IRMd to IPCP */

int   ipcp_ap_reg(pid_t    pid,
                  uint32_t reg_api_id,
                  char *   ap_name);
int   ipcp_ap_unreg(pid_t    pid,
                    uint32_t reg_api_id);

int   ipcp_flow_alloc(pid_t             pid,
                      uint32_t          port_id,
                      char *            dst_ap_name,
                      char *            src_ap_name,
                      char *            src_ae_name,
                      struct qos_spec * qos);
int   ipcp_flow_alloc_resp(pid_t    pid,
                           uint32_t port_id,
                           int      result);

/* These operations go from the IPCP to the IRMd */

/* Returns the port_id */
int   ipcp_flow_req_arr(pid_t    pid,
                        uint32_t reg_api_id,
                        char *   ap_name,
                        char *   ae_name);
int   ipcp_flow_alloc_reply(pid_t    pid,
                            uint32_t port_id,
                            int      result);

/*
 * This operation can go both ways
 * pid == 0 means the IRMd is the destination
 */
int   ipcp_flow_dealloc(pid_t    pid,
                        uint32_t port_id);


#endif /* OUROBOROS_IPCP_H */
