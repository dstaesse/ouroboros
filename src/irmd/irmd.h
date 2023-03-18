/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_IRMD_H
#define OUROBOROS_IRMD_H

#include <ouroboros/ipcp.h>
#include <ouroboros/irm.h>

int create_ipcp(const char *   name,
                enum ipcp_type type);

int bootstrap_ipcp(pid_t                pid,
                   struct ipcp_config * conf);

int enroll_ipcp(pid_t        pid,
                const char * dst);

int connect_ipcp(pid_t        pid,
                 const char * dst,
                 const char * component,
                 qosspec_t    qs);

int get_layer_for_ipcp(pid_t  pid,
                       char * buf);

int name_create(const char *     name,
                enum pol_balance pol);

int name_reg(const char * name,
             pid_t        pid);

int bind_process(pid_t        pid,
                 const char * name);

int bind_program(const char *  prog,
                 const char *  name,
                 uint16_t      flags,
                 int           argc,
                 char **       argv);

#endif /* OUROBOROS_IRMD_H*/