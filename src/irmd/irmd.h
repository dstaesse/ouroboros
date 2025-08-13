/*
 * Ouroboros - Copyright (C) 2016 - 2024
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

int create_ipcp(struct ipcp_info * info);

int bootstrap_ipcp(pid_t                pid,
                   struct ipcp_config * conf);

int enroll_ipcp(pid_t        pid,
                const char * dst);

int connect_ipcp(pid_t        pid,
                 const char * dst,
                 const char * component,
                 qosspec_t    qs);

int name_create(struct name_info * info);

int name_reg(const char * name,
             pid_t        pid);

int bind_process(pid_t        pid,
                 const char * name);

int bind_program(char **      exec,
                 const char * name,
                 uint8_t      flags);

#endif /* OUROBOROS_IRMD_H*/
