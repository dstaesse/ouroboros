/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager - Registry - Names
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

#ifndef OUROBOROS_IRMD_REG_NAME_H
#define OUROBOROS_IRMD_REG_NAME_H

#include <ouroboros/hash.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/list.h>
#include <ouroboros/irm.h>

#include "proc.h"
#include "prog.h"

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

enum name_state {
        NAME_NULL = 0,
        NAME_IDLE,
        NAME_AUTO_ACCEPT,
        NAME_AUTO_EXEC,
        NAME_FLOW_ACCEPT,
        NAME_FLOW_ARRIVED,
        NAME_DESTROY
};

/* An entry in the registry */
struct reg_name {
        struct list_head    next;
        char *              name;

        /* Policies for this name. */
        enum pol_balance    pol_lb;  /* Load balance incoming flows. */
        /* Programs that can be instantiated by the irmd. */
        struct list_head    reg_progs;
        /* Processes that are listening for this name. */
        struct list_head    reg_pids;

        enum name_state     state;
        pthread_cond_t      cond;
        pthread_mutex_t     mtx;
};

struct reg_name * reg_name_create(const char *     name,
                                  enum pol_balance lb);

void              reg_name_destroy(struct reg_name * n);

int               reg_name_add_prog(struct reg_name * n,
                                    struct reg_prog * p);

void              reg_name_del_prog(struct reg_name * n,
                                    const char *      prog);

char *            reg_name_get_prog(struct reg_name * n);

int               reg_name_add_pid(struct reg_name * n,
                                   pid_t             pid);

void              reg_name_del_pid(struct reg_name * n,
                                   pid_t             pid);

void              reg_name_del_pid_el(struct reg_name * n,
                                      struct pid_el *   p);

pid_t             reg_name_get_pid(struct reg_name * n);

void              reg_name_set_policy(struct reg_name * n,
                                      enum pol_balance  lb);

enum name_state   reg_name_get_state(struct reg_name * n);

int               reg_name_set_state(struct reg_name * n,
                                     enum name_state   state);

int               reg_name_leave_state(struct reg_name * n,
                                       enum name_state   state,
                                       struct timespec * timeout);

#endif /* OUROBOROS_IRMD_REG_NAME_H */
