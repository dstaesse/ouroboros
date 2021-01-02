/*
 * Ouroboros - Copyright (C) 2016 - 2021
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

#ifndef OUROBOROS_IRMD_REGISTRY_H
#define OUROBOROS_IRMD_REGISTRY_H

#include <ouroboros/hash.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/list.h>
#include <ouroboros/irm.h>

#include "proc_table.h"
#include "prog_table.h"

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

#define registry_has_name(r, name) \
        (registry_get_entry(r, name) != NULL)

enum reg_name_state {
        REG_NAME_NULL = 0,
        REG_NAME_IDLE,
        REG_NAME_AUTO_ACCEPT,
        REG_NAME_AUTO_EXEC,
        REG_NAME_FLOW_ACCEPT,
        REG_NAME_FLOW_ARRIVED,
        REG_NAME_DESTROY
};

/* An entry in the registry */
struct reg_entry {
        struct list_head    next;
        char *              name;

        /* Policies for this name. */
        enum pol_balance    pol_lb;  /* Load balance incoming flows. */
        /* Programs that can be instantiated by the irmd. */
        struct list_head    reg_progs;
        /* Processes that are listening for this name. */
        struct list_head    reg_pids;

        enum reg_name_state state;
        pthread_cond_t      state_cond;
        pthread_mutex_t     state_lock;
};

int                 reg_entry_add_prog(struct reg_entry *  e,
                                       struct prog_entry * a);

void                reg_entry_del_prog(struct reg_entry * e,
                                       const char *       prog);

char *              reg_entry_get_prog(struct reg_entry * e);

int                 reg_entry_add_pid(struct reg_entry * e,
                                      pid_t              pid);

void                reg_entry_del_pid(struct reg_entry * e,
                                      pid_t              pid);

void                reg_entry_del_pid_el(struct reg_entry * e,
                                         struct pid_el *    a);

pid_t               reg_entry_get_pid(struct reg_entry * e);

void                reg_entry_set_policy(struct reg_entry * e,
                                         enum pol_balance   p);

enum reg_name_state reg_entry_get_state(struct reg_entry * e);

int                 reg_entry_set_state(struct reg_entry *  e,
                                        enum reg_name_state state);

int                 reg_entry_leave_state(struct reg_entry *  e,
                                          enum reg_name_state state,
                                          struct timespec *   timeout);

int                 reg_entry_wait_state(struct reg_entry *   e,
                                         enum reg_name_state  state,
                                         struct timespec *    timeout);

struct reg_entry *  registry_add_name(struct list_head * registry,
                                      const char *       name);

void                registry_del_name(struct list_head * registry,
                                      const char *       name);

void                registry_del_process(struct list_head * registry,
                                         pid_t              pid);

void                registry_sanitize_pids(struct list_head * registry);

struct reg_entry *  registry_get_entry(struct list_head * registry,
                                       const char *       name);

struct reg_entry *  registry_get_entry_by_hash(struct list_head * registry,
                                               enum hash_algo     algo,
                                               const uint8_t *    hash,
                                               size_t             len);

void                registry_destroy(struct list_head * registry);

#endif /* OUROBOROS_IRMD_REGISTRY_H */
