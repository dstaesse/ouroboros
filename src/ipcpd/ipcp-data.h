/*
 * Ouroboros - Copyright (C) 2016
 *
 * Utitilies for building IPC processes
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

#ifndef IPCPD_IPCP_DATA_H
#define IPCPD_IPCP_DATA_H

#include <ouroboros/common.h>
#include <ouroboros/instance_name.h>
#include <ouroboros/list.h>
#include <sys/types.h>
#include <pthread.h>

#include "ipcp-ops.h"
#include "flow.h"

struct ipcp_data {
        instance_name_t   * iname;
        enum ipcp_type      type;

        struct shm_du_map * dum;

        struct list_head    registry;
        pthread_mutex_t     reg_lock;

        struct list_head    flows;
        pthread_mutex_t     flow_lock;

        struct list_head    directory;
        pthread_mutex_t     dir_lock;

        pthread_mutex_t     lock;
};

struct ipcp_data * ipcp_data_create();
struct ipcp_data * ipcp_data_init(struct ipcp_data * dst,
                                  instance_name_t *  iname,
                                  enum ipcp_type     ipcp_type);
void               ipcp_data_destroy(struct ipcp_data * data);

int          ipcp_data_add_reg_entry(struct ipcp_data * data,
                                     char *             ap_name,
                                     uint32_t           reg_ap_id);
int          ipcp_data_del_reg_entry(struct ipcp_data * data,
                                     uint32_t           reg_ap_id);
int          ipcp_data_add_dir_entry(struct ipcp_data * data,
                                     char *             ap_name,
                                     uint64_t           addr);
int          ipcp_data_del_dir_entry(struct ipcp_data * data,
                                     const char *       ap_name,
                                     uint64_t           addr);
bool         ipcp_data_is_in_registry(struct ipcp_data * data,
                                      const char *       ap_name);
uint32_t     ipcp_data_get_reg_ap_id(struct ipcp_data * data,
                                     const char *       ap_name);
const char * ipcp_data_get_reg_ap_name(struct ipcp_data * data,
                                       uint32_t           reg_ap_id);
bool         ipcp_data_is_in_directory(struct ipcp_data * data,
                                       const char *       ap_name);
uint64_t     ipcp_data_get_addr(struct ipcp_data * data,
                                const char *       ap_name);
bool         ipcp_data_has_flow(struct ipcp_data * data,
                                uint32_t           port_id);
flow_t *     ipcp_data_find_flow(struct ipcp_data * data,
                                 uint32_t           port_id);
int          ipcp_data_add_flow(struct ipcp_data * data,
                                flow_t *           flow);
int          ipcp_data_del_flow(struct ipcp_data * data,
                                uint32_t           port_id);

#endif /* IPCPD_IPCP_DATA_H */
