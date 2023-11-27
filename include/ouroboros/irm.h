/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The API to instruct the IPC Resource Manager
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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
#include <ouroboros/qos.h>

#include <sys/types.h>

/* Name binding options. */
#define BIND_AUTO   0x01

#define NAME_SIZE 256
#define LAYER_SIZE LAYER_NAME_SIZE

/* Load balancing policy for incoming flows. */
enum pol_balance {
        LB_RR = 0,
        LB_SPILL,
        LB_INVALID
};

struct ipcp_list_info {
        pid_t          pid;
        enum ipcp_type type;
        char           name[NAME_SIZE];
        char           layer[LAYER_SIZE];
};

struct name_info {
        char             name[NAME_SIZE];
        enum pol_balance pol_lb;
};

__BEGIN_DECLS

pid_t   irm_create_ipcp(const char *   name,
                        enum ipcp_type type);

int     irm_destroy_ipcp(pid_t pid);

ssize_t irm_list_ipcps(struct ipcp_list_info ** ipcps);

int     irm_enroll_ipcp(pid_t        pid,
                        const char * dst);

int     irm_bootstrap_ipcp(pid_t                      pid,
                           const struct ipcp_config * conf);

int     irm_connect_ipcp(pid_t        pid,
                         const char * component,
                         const char * dst,
                         qosspec_t    qs);

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

int     irm_create_name(const char *     name,
                        enum pol_balance pol);

int     irm_destroy_name(const char * name);

ssize_t irm_list_names(struct name_info ** names);

int     irm_reg_name(const char * name,
                     pid_t        pid);

int     irm_unreg_name(const char * name,
                       pid_t        pid);

__END_DECLS

#endif /* OUROBOROS_IRM_H */
