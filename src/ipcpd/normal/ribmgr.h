/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * RIB manager of the IPC Process
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#ifndef OUROBOROS_IPCPD_NORMAL_RIBMGR_H
#define OUROBOROS_IPCPD_NORMAL_RIBMGR_H

#include <ouroboros/irm_config.h>
#include <ouroboros/utils.h>

#include "dt_const.h"

int               ribmgr_init(void);

int               ribmgr_fini(void);

int               ribmgr_add_nm1_flow(int fd);

int               ribmgr_nm1_mgt_flow(char * dst_name);

int               ribmgr_bootstrap(struct dif_config * conf);

int               ribmgr_enrol(void);

int               ribmgr_start_policies(void);

struct dt_const * ribmgr_dt_const(void);

uint64_t          ribmgr_address(void);

enum pol_gam      ribmgr_dt_gam(void);

#endif /* OUROBOROS_IPCPD_NORMAL_RIBMGR_H */
