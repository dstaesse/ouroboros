/*
 * Ouroboros - Copyright (C) 2016
 *
 * Flow manager of the IPC Process
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

#ifndef OUROBOROS_IPCP_FMGR_H
#define OUROBOROS_IPCP_FMGR_H

#include <ouroboros/qos.h>
#include <ouroboros/shared.h>

int fmgr_init();
int fmgr_fini();

/* N-flow ops */
int fmgr_mgmt_flow(char * dst_name);
int fmgr_dt_flow(char * dst_name);

/* N+1-flow ops */
int fmgr_flow_alloc(pid_t         n_api,
                    int           port_id,
                    char *        dst_ap_name,
                    char *        src_ae_name,
                    enum qos_cube qos);

int fmgr_flow_alloc_resp(pid_t n_api,
                         int   port_id,
                         int   response);

int fmgr_flow_dealloc(int port_id);

/* RIB Manager calls this (param will be of type fmgr_msg_t) */
int fmgr_flow_msg();

#endif
