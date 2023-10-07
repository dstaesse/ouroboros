/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager - Registry - Processes
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

#ifndef OUROBOROS_IRMD_REG_PROC_H
#define OUROBOROS_IRMD_REG_PROC_H

#include <ouroboros/shm_flow_set.h>

#include "utils.h"

#include <unistd.h>
#include <ouroboros/pthread.h>

enum proc_state {
        PROC_NULL = 0,
        PROC_INIT,
        PROC_SLEEP,
        PROC_WAKE,
        PROC_DESTROY
};

struct reg_proc {
        struct list_head      next;
        pid_t                 pid;
        char *                prog;  /* program instantiated */
        struct list_head      names; /* names for which process accepts flows */
        struct shm_flow_set * set;

        struct reg_name *     name;  /* name for which a flow arrived */

        /* The process will block on this */
        enum proc_state       state;
        pthread_cond_t        cond;
        pthread_mutex_t       lock;
};

struct reg_proc * reg_proc_create(pid_t        proc,
                                  const char * prog);

void              reg_proc_destroy(struct reg_proc * proc);

int               reg_proc_sleep(struct reg_proc * proc,
                                 struct timespec * timeo);

void              reg_proc_wake(struct reg_proc * proc,
                                struct reg_name * name);

void              reg_proc_cancel(struct reg_proc * proc);

int               reg_proc_add_name(struct reg_proc * proc,
                                    const char *      name);

void              reg_proc_del_name(struct reg_proc * proc,
                                    const char *      name);

#endif /* OUROBOROS_IRMD_REG_PROC_H */
