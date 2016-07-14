/*
 * Ouroboros - Copyright (C) 2016
 *
 * RIB manager of the IPC Process
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

#ifndef OUROBOROS_IPCP_RIBMGR_H
#define OUROBOROS_IPCP_RIBMGR_H

#include <ouroboros/irm_config.h>

int ribmgr_init();
int ribmgr_fini();

int ribmgr_mgmt_flow(int fd);
int ribmgr_bootstrap(struct dif_config * conf);

/* Called by Flow Manager (param of type fmgr_msg_t) */
int ribmgr_fmgr_msg();

#endif
