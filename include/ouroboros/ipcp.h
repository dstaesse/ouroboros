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

#include <sys/types.h>

#include "common.h"
#include "rina_name.h"

struct ipcp;

/* Returns the process id */
pid_t ipcp_create(rina_name_t name,
                  char *      ipcp_type);
int ipcp_destroy(pid_t pid);

int ipcp_reg(pid_t   pid,
             char ** difs,
             size_t  difs_size);
int ipcp_unreg(pid_t   pid,
               char ** difs,
               size_t  difs_size);

int ipcp_bootstrap(pid_t               pid,
                   struct dif_config * conf);
int ipcp_enroll(pid_t   pid,
                char *  dif_name,
                char *  member_name,
                char ** n_1_difs,
                ssize_t n_1_difs_size);

#endif
