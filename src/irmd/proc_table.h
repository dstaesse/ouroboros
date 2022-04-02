/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * The IPC Resource Manager - Process Table
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

#ifndef OUROBOROS_IRMD_PROC_TABLE_H
#define OUROBOROS_IRMD_PROC_TABLE_H

#include <ouroboros/shm_flow_set.h>

#include "utils.h"

#include <unistd.h>
#include <pthread.h>

enum proc_state {
        PROC_NULL = 0,
        PROC_INIT,
        PROC_SLEEP,
        PROC_WAKE,
        PROC_DESTROY
};

struct proc_entry {
        struct list_head      next;
        pid_t                 pid;
        char *                prog;  /* program instantiated */
        struct list_head      names; /* names for which process accepts flows */
        struct shm_flow_set * set;

        struct reg_entry *    re;    /* reg_entry for which a flow arrived */

        /* The process will block on this */
        enum proc_state       state;
        pthread_cond_t        cond;
        pthread_mutex_t       lock;
};

struct proc_entry * proc_entry_create(pid_t  proc,
                                      char * prog);

void                proc_entry_destroy(struct proc_entry * e);

int                 proc_entry_sleep(struct proc_entry * e,
                                     struct timespec *   timeo);

void                proc_entry_wake(struct proc_entry * e,
                                    struct reg_entry *  re);

void                proc_entry_cancel(struct proc_entry * e);

int                 proc_entry_add_name(struct proc_entry * e,
                                        char *              name);

void                proc_entry_del_name(struct proc_entry * e,
                                        const char *        name);

int                 proc_table_add(struct list_head *  proc_table,
                                   struct proc_entry * e);

void                proc_table_del(struct list_head * proc_table,
                                   pid_t              pid);

struct proc_entry * proc_table_get(struct list_head * proc_table,
                                   pid_t              pid);

#endif /* OUROBOROS_IRMD_PROC_TABLE_H */
