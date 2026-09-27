/*
 * Ouroboros - Copyright (C) 2016 - 2026
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

#include "pool.h"

int    reg_init(void);

void   reg_clear(void);

void   reg_fini(void);

int    reg_create_flow(struct flow_info * info);

int    reg_destroy_flow(int flow_id);

bool   reg_has_flow(int flow_id);

int    reg_create_proc(const struct proc_info * info);

/* Use this for all processes, including ipcps */
int    reg_destroy_proc(pid_t pid);

bool   reg_has_proc(pid_t pid);

bool   reg_is_proc_privileged(pid_t pid);

int    reg_prepare_pool(uid_t uid,
                        gid_t gid);

uid_t  reg_get_proc_uid(pid_t pid);

void   reg_kill_all_proc(int signal);

pid_t  reg_get_dead_proc(void);

int    reg_create_spawned(pid_t pid);

bool   reg_has_spawned(pid_t pid);

void   reg_kill_all_spawned(int signal);

pid_t  reg_first_spawned(void);

void   reg_kill_all_ipcps(int signal);

pid_t  reg_first_ipcp(void);

int    reg_bind_proc(const char * name,
                     pid_t        proc);

int    reg_unbind_proc(const char * name,
                       pid_t        proc);

int    reg_create_ipcp(const struct ipcp_info * info);

bool   reg_has_ipcp(pid_t pid);

int    reg_set_flags_for_ipcp(pid_t    pid,
                              uint32_t flags);

int    reg_set_layer_for_ipcp(struct ipcp_info *        info,
                              const struct layer_info * layer);

int    reg_get_ipcp(struct ipcp_info *  info,
                    struct layer_info * layer);

int    reg_get_ipcp_by_layer(struct ipcp_info *  info,
                             struct layer_info * layer);

/* TODO don't rely on protobuf here */
int    reg_list_ipcps(ipcp_list_msg_t *** msg);

int    reg_create_name(const struct name_info * info);

int    reg_destroy_name(const char * name);

bool   reg_has_name(const char * name);

int    reg_get_name_info(const char *       name,
                         struct name_info * info);

int    reg_get_name_for_hash(char *          buf,
                             enum hash_algo  algo,
                             const uint8_t * hash);

int    reg_get_name_for_flow_id(char * buf,
                                int    flow_id);

void   reg_set_name_for_flow_id(const char * name,
                                int          flow_id);

/* TODO don't rely on protobuf here */
int    reg_list_names(name_info_msg_t *** names);

int    reg_create_prog(const struct prog_info * info);

int    reg_destroy_prog(const char * name);

bool   reg_has_prog(const char * name);

int    reg_get_exec(const char * name,
                    char ***     exec);

int    reg_bind_prog(const char * name,
                     char **      exec,
                     uint8_t      flags);

int    reg_unbind_prog(const char * name,
                       const char * prog);

int    reg_prepare_flow_alloc(struct flow_info * info);

int    reg_wait_flow_allocated(struct flow_info *      info,
                               buffer_t *              pbuf,
                               const struct timespec * abstime);

int    reg_respond_alloc(struct flow_info * info,
                         buffer_t *         pbuf,
                         int                response);

int    reg_prepare_flow_accept(struct flow_info * info);

int    reg_wait_flow_accepted(struct flow_info *      info,
                              buffer_t *              pbuf,
                              const struct timespec * abstime);

int    reg_wait_flow_accepting(const char *            name,
                               const struct timespec * abstime);

int    reg_respond_accept(struct flow_info * info,
                          buffer_t *         pbuf);

int    reg_prepare_flow_direct(struct flow_info * info,
                               buffer_t *         pbuf,
                               uid_t              alloc_uid);

int    reg_respond_flow_direct(int        flow_id,
                               buffer_t * pbuf);

int    reg_wait_flow_direct(int                     flow_id,
                            buffer_t *              pbuf,
                            const struct timespec * abstime);

bool   reg_flow_is_direct(int flow_id);

bool   reg_flow_is_poa(int flow_id);

int    reg_flow_set_poa(int flow_id);

int    reg_flow_set_oap_ctx(int    flow_id,
                            void * ctx);

void * reg_flow_take_oap_ctx(int flow_id);

/* Per-flow snapshot for the re-key timer */
struct rekey_info {
        int     flow_id;
        pid_t   n_pid;
        pid_t   n_1_pid;
        char    name[NAME_SIZE + 1];
        uint8_t epoch;
        bool    direct;
};

void   reg_flow_set_rekey(int      flow_id,
                          bool     initiator,
                          buffer_t peer_crt);

int    reg_flow_get_peer_crt(int        flow_id,
                             buffer_t * crt);

int    reg_flow_get_epoch(int flow_id);

bool   reg_flow_rekey_pending(int flow_id);

pid_t  reg_flow_get_n_1_pid(int flow_id);

int    reg_flow_snapshot_rekey_due(struct rekey_info * snap,
                                   int                 max);

void   reg_flow_clear_in_flight(int flow_id);

bool   reg_flow_rekey_begin(int flow_id);

bool   reg_flow_rekey_should_yield(int flow_id);

int    reg_flow_store_pending(int             flow_id,
                              const uint8_t * seed,
                              uint8_t         epoch,
                              bool            initiator);

int    reg_flow_store_pending_direct(int             flow_id,
                                     const uint8_t * seed,
                                     uint8_t         epoch);

int    reg_flow_take_pending(int       flow_id,
                             uid_t     uid,
                             pid_t     cpid,
                             uint8_t * seed,
                             uint8_t * epoch,
                             bool *    initiator);

bool   reg_flow_rekey_arr_admit(int   flow_id,
                                pid_t n_1_pid,
                                bool  is_req);

void   reg_flow_rekey_arr_done(int  flow_id,
                               bool is_req);

bool   reg_flow_owned_by(int   flow_id,
                         uid_t uid);

void   reg_notify_flow(int flow_id,
                       int event);

void   reg_notify_flow_peers(int flow_id,
                             int event);

void   reg_dealloc_flow(struct flow_info * info);

void   reg_dealloc_flow_resp(struct flow_info * info);

int    reg_get_proc_flow(pid_t              pid,
                         struct flow_info * info);

int    reg_wait_proc(pid_t                   pid,
                     const struct timespec * abstime);

int    reg_wait_ipcp_boot(struct ipcp_info *      ipcp,
                          const struct timespec * abstime);

int    reg_respond_ipcp(const struct ipcp_info * info);

#endif /* OUROBOROS_IRMD_REG_H */
