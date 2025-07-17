/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry
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

#ifndef OUROBOROS_IRMD_REG_H
#define OUROBOROS_IRMD_REG_H

#include <ouroboros/flow.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/name.h>
#include <ouroboros/proc.h>
#include <ouroboros/protobuf.h>
#include <ouroboros/time.h>
#include <ouroboros/utils.h>

int   reg_init(void);

void  reg_clear(void);

void  reg_fini(void);

int   reg_create_flow(struct flow_info * info);

int   reg_destroy_flow(int flow_id);

bool  reg_has_flow(int flow_id);

int   reg_create_proc(const struct proc_info * info);

/* Use this for all processes, including ipcps */
int   reg_destroy_proc(pid_t pid);

bool  reg_has_proc(pid_t pid);

void  reg_kill_all_proc(int signal);

pid_t reg_get_dead_proc(void);

int   reg_create_spawned(pid_t pid);

bool  reg_has_spawned(pid_t pid);

void  reg_kill_all_spawned(int signal);

int   reg_first_spawned(void);

int   reg_bind_proc(const char * name,
                    pid_t        proc);

int   reg_unbind_proc(const char * name,
                      pid_t        proc);

int   reg_create_ipcp(const struct ipcp_info * info);

bool  reg_has_ipcp(pid_t pid);

int   reg_set_layer_for_ipcp(struct ipcp_info *        info,
                             const struct layer_info * layer);

int   reg_get_ipcp(struct ipcp_info *  info,
                   struct layer_info * layer);

int   reg_get_ipcp_by_layer(struct ipcp_info *  info,
                            struct layer_info * layer);

/* TODO don't rely on protobuf here */
int   reg_list_ipcps(ipcp_list_msg_t *** msg);

int   reg_create_name(const struct name_info * info);

int   reg_destroy_name(const char * name);

bool  reg_has_name(const char * name);

/* TODO don't rely on protobuf here */
int   reg_list_names(name_info_msg_t *** names);

int   reg_create_prog(const struct prog_info * info);

int   reg_destroy_prog(const char * name);

bool  reg_has_prog(const char * name);

int   reg_get_exec(enum hash_algo  algo,
                   const uint8_t * hash,
                   char ***        exec);

int   reg_bind_prog(const char * name,
                    char **      exec,
                    uint8_t      flags);

int   reg_unbind_prog(const char * name,
                      const char * prog);

int   reg_prepare_flow_alloc(struct flow_info * info);

int   reg_wait_flow_allocated(struct flow_info *      info,
                              buffer_t *              pbuf,
                              const struct timespec * abstime);

int   reg_respond_alloc(struct flow_info * info,
                        buffer_t *         pbuf);

int   reg_prepare_flow_accept(struct flow_info * info);

int   reg_wait_flow_accepted(struct flow_info *      info,
                             buffer_t *              pbuf,
                             const struct timespec * abstime);

int   reg_wait_flow_accepting(enum hash_algo          algo,
                              const uint8_t *         hash,
                              const struct timespec * abstime);

int   reg_respond_accept(struct flow_info * info,
                         buffer_t *         pbuf);

void  reg_dealloc_flow(struct flow_info * info);

void  reg_dealloc_flow_resp(struct flow_info * info);

int   reg_wait_proc(pid_t                   pid,
                    const struct timespec * abstime);

int   reg_wait_ipcp_boot(struct ipcp_info *      ipcp,
                         const struct timespec * abstime);

int   reg_respond_ipcp(const struct ipcp_info * info);

#endif /* OUROBOROS_IRMD_REG_H */
