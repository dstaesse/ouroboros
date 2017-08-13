/*
 * Ouroboros - Copyright (C) 2016 - 2017
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

/* Name binding options */

#define BIND_AP_AUTO   0x01
#define BIND_AP_UNIQUE 0x02

__BEGIN_DECLS

pid_t   irm_create_ipcp(const char *   name,
                        enum ipcp_type ipcp_type);

int     irm_destroy_ipcp(pid_t api);

/* apis is an out-parameter */
ssize_t irm_list_ipcps(const char * name,
                       pid_t **     apis);

int     irm_enroll_ipcp(pid_t        api,
                        const char * dif_name);

int     irm_bootstrap_ipcp(pid_t                      api,
                           const struct ipcp_config * conf);

int     irm_bind_ap(const char * ap,
                    const char * name,
                    uint16_t     opts,
                    int          argc,
                    char **      argv);

int     irm_unbind_ap(const char * ap,
                      const char * name);

int     irm_bind_api(pid_t        api,
                     const char * name);

int     irm_unbind_api(pid_t        api,
                       const char * name);

int     irm_reg(const char *  name,
                char **       difs,
                size_t        len);

int     irm_unreg(const char * name,
                  char **      difs,
                  size_t       len);

__END_DECLS

#endif /* OUROBOROS_IRM_H */
