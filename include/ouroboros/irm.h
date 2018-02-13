/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * The API to instruct the IPC Resource Manager
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_IRM_H
#define OUROBOROS_IRM_H

#include <ouroboros/cdefs.h>
#include <ouroboros/ipcp.h>

#include <sys/types.h>

/* Normal IPCP components. */
#define DT_COMP   "Data Transfer"
#define MGMT_COMP "Management"

/* Name binding options. */
#define BIND_AUTO   0x01

__BEGIN_DECLS

pid_t   irm_create_ipcp(const char *   name,
                        enum ipcp_type ipcp_type);

int     irm_destroy_ipcp(pid_t pid);

/* pids is an out-parameter */
ssize_t irm_list_ipcps(const char * name,
                       pid_t **     pids);

int     irm_enroll_ipcp(pid_t        pid,
                        const char * layer_name);

int     irm_bootstrap_ipcp(pid_t                      pid,
                           const struct ipcp_config * conf);

int     irm_connect_ipcp(pid_t        pid,
                         const char * component,
                         const char * dst);

int     irm_disconnect_ipcp(pid_t        pid,
                            const char * component,
                            const char * dst);

int     irm_bind_program(const char * prog,
                         const char * name,
                         uint16_t     opts,
                         int          argc,
                         char **      argv);

int     irm_unbind_program(const char * progr,
                           const char * name);

int     irm_bind_process(pid_t        pid,
                         const char * name);

int     irm_unbind_process(pid_t        pid,
                           const char * name);

int     irm_reg(const char *  name,
                char **       layers,
                size_t        len);

int     irm_unreg(const char * name,
                  char **      layers,
                  size_t       len);

__END_DECLS

#endif /* OUROBOROS_IRM_H */
