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

#include <ouroboros/irm_config.h>
#include <ouroboros/sockets.h>
#include <ouroboros/shared.h>

#include <sys/types.h>

#ifndef OUROBOROS_IPCP_H
#define OUROBOROS_IPCP_H

/* Returns the process id */
pid_t ipcp_create(enum ipcp_type ipcp_type);

int   ipcp_destroy(pid_t api);

int   ipcp_enroll(pid_t  api,
                  char * dif_name);

int   ipcp_bootstrap(pid_t              api,
                     dif_config_msg_t * conf);

int   ipcp_name_reg(pid_t  api,
                    char * name);
int   ipcp_name_unreg(pid_t  api,
                      char * name);

int   ipcp_flow_alloc(pid_t         api,
                      int           port_id,
                      pid_t         n_api,
                      char *        dst_name,
                      char *        src_ae_name,
                      enum qos_cube qos);
int   ipcp_flow_alloc_resp(pid_t api,
                           int   port_id,
                           pid_t n_api,
                           int   response);

int   ipcp_flow_dealloc(pid_t api,
                        int   port_id);

#endif /* OUROBOROS_IPCP_H */
