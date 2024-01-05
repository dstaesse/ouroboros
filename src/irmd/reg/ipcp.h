/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - IPCPs
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

#ifndef OUROBOROS_IRMD_REG_IPCP_H
#define OUROBOROS_IRMD_REG_IPCP_H

#include <ouroboros/list.h>

enum ipcp_state {
        IPCP_NULL = 0,
        IPCP_BOOT,
        IPCP_LIVE
};

struct reg_ipcp {
        struct list_head next;

        struct ipcp_info info;

        pid_t            pid;
        enum hash_algo   dir_hash_algo;
        char *           layer;

        enum ipcp_state  state;
        pthread_cond_t   cond;
        pthread_mutex_t  mtx;
};

struct reg_ipcp * reg_ipcp_create(const struct ipcp_info * info);

void              reg_ipcp_destroy(struct reg_ipcp * i);

void              reg_ipcp_set_state(struct reg_ipcp * i,
                                     enum ipcp_state   state);

int               reg_ipcp_wait_boot(struct reg_ipcp * i);

#endif /* OUROBOROS_IRMD_REG_IPCP_H */