/*
 * Ouroboros - Copyright (C) 2016
 *
 * IPC process ops
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

#ifndef IPCPD_IPCP_OPS_H
#define IPCPD_IPCP_OPS_H

#include <ouroboros/common.h>
#include <ouroboros/dif_config.h>
#include <sys/types.h>

struct ipcp_ops {
        int   (* ipcp_bootstrap)(struct dif_config * conf);
        int   (* ipcp_enroll)(char * member_name,
                              char * n_1_dif);
        int   (* ipcp_reg)(char ** dif_names,
                           size_t len);
        int   (* ipcp_unreg)(char ** dif_names,
                             size_t len);
        int   (* ipcp_ap_reg)(char *   ap_name,
                              uint32_t reg_ap_id);
        int   (* ipcp_ap_unreg)(uint32_t reg_ap_id);
        int   (* ipcp_flow_alloc)(uint32_t          port_id,
                                  char *            dst_ap_name,
                                  char *            src_ap_name,
                                  char *            src_ae_name,
                                  struct qos_spec * qos);
        int   (* ipcp_flow_alloc_resp)(uint32_t port_id,
                                       int      result);
        int   (* ipcp_flow_dealloc)(uint32_t port_id);

        /* FIXME: let's see how this will work with the shm_du_map */
        int   (* ipcp_du_write)(uint32_t port_id,
                           size_t map_index);

        int   (* ipcp_du_read)(uint32_t port_id,
                               size_t map_index);
};

#endif /* IPCPD_IPCP_OPS_H */
