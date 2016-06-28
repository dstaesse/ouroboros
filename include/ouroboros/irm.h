/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API to instruct the IPC Resource Manager
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

#include <ouroboros/irm_config.h>
#include <sys/types.h>

pid_t   irm_create_ipcp(char *         name,
                        enum ipcp_type ipcp_type);

int     irm_destroy_ipcp(pid_t api);

/* APIs is an out-parameter */
ssize_t irm_list_ipcps(char *   name,
                       pid_t ** apis);

int     irm_enroll_ipcp(pid_t  api,
                        char * dif_name);

int     irm_bootstrap_ipcp(pid_t               api,
                           struct dif_config * conf);

int     irm_bind(char *   name,
                 char *   ap_name,
                 uint16_t opts,
                 int      argc,
                 char **  argv);

int     irm_unbind(char *   name,
                   char *   ap_name,
                   uint16_t opts);

int     irm_reg(char *  name,
                char ** difs,
                size_t  difs_size);

int     irm_unreg(char *  name,
                  char ** difs,
                  size_t  difs_size);

#endif /* OUROBOROS_IRM_H */
