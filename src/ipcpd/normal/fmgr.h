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

#include <ouroboros/shared.h>

#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

#include "frct.h"

#define MGMT_AE "Management"
#define DT_AE "Data transfer"

int fmgr_init();
int fmgr_fini();

/* N-flow ops */
int fmgr_mgmt_flow(char * dst_name);

int fmgr_dt_flow(char * dst_name,
                 enum qos_cube qos);

/* N+1-flow ops, local */
int fmgr_flow_alloc(int           fd,
                    char *        dst_ap_name,
                    char *        src_ae_name,
                    enum qos_cube qos);

int fmgr_flow_alloc_resp(int fd,
                         int response);

int fmgr_flow_dealloc(int fd);

/* N+1-flow ops, remote */
int fmgr_frct_post_buf(cep_id_t   id,
                       buffer_t * buf);

/* SDU for N+1-flow */
int fmgr_frct_post_sdu(cep_id_t             id,
                       struct shm_du_buff * sdb);

#endif
