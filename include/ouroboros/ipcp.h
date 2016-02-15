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

#include "common.h"

int ipcp_create(rina_name_t name,
                char * ipcp_type);
int ipcp_destroy(int instance);

int ipcp_reg(int instance,
             char ** difs);
int ipcp_unreg(int instance,
               char ** difs);

int ipcp_bootstrap(int instance,
                   struct dif_info info);
int ipcp_enroll(int instance,
                char * dif_name,
                rina_name_t member);

#endif
