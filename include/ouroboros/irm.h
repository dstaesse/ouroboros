/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API to instruct the IRM
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

#ifndef OUROBOROS_IRM_H
#define OUROBOROS_IRM_H

#include "common.h"

int     irm_create_ipcp(rina_name_t name,
                        char * ipcp_type);
int     irm_destroy_ipcp(rina_name_t name);

int     irm_bootstrap_ipcp(rina_name_t name,
                           struct dif_info info);
int     irm_enroll_ipcp(rina_name_t name,
                        char * dif_name);

int     irm_reg_ipcp(rina_name_t name,
                     char ** difs,
                     size_t difs_size);
int     irm_unreg_ipcp(rina_name_t name,
                       char ** difs,
                       size_t difs_size);

#endif
