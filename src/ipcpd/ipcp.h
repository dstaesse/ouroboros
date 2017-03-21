/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * IPC process structure
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef IPCPD_IPCP_H
#define IPCPD_IPCP_H

#include <ouroboros/config.h>
#include <ouroboros/irm_config.h>

#include "shim-data.h"

#include <pthread.h>
#include <time.h>

enum ipcp_state {
        IPCP_NULL = 0,
        IPCP_INIT,
        IPCP_OPERATIONAL,
        IPCP_SHUTDOWN
};

struct ipcp_ops {
        int   (* ipcp_bootstrap)(struct dif_config * conf);

        int   (* ipcp_enroll)(char * dif_name);

        int   (* ipcp_name_reg)(char * name);

        int   (* ipcp_name_unreg)(char * name);

        int   (* ipcp_name_query)(char * name);

        int   (* ipcp_flow_alloc)(int       fd,
                                  char *    dst_ap_name,
                                  qoscube_t qos);

        int   (* ipcp_flow_alloc_resp)(int fd,
                                       int response);

        int   (* ipcp_flow_dealloc)(int fd);
};

struct ipcp {
        int                irmd_api;
        char *             name;

        enum ipcp_type     type;
        char *             dif_name;

        uint64_t           dt_addr;

        struct ipcp_ops *  ops;
        int                irmd_fd;

        struct shim_data * shim_data;

        enum ipcp_state    state;
        pthread_rwlock_t   state_lock;
        pthread_mutex_t    state_mtx;
        pthread_cond_t     state_cond;

        int                sockfd;
        char *             sock_path;
        pthread_t *        threadpool;
} ipcpi;

int             ipcp_init(int               argc,
                          char **           argv,
                          enum ipcp_type    type,
                          struct ipcp_ops * ops);

int             ipcp_boot(void);

void            ipcp_shutdown(void);

void            ipcp_fini(void);

void            ipcp_set_state(enum ipcp_state state);

enum ipcp_state ipcp_get_state(void);

int             ipcp_wait_state(enum ipcp_state         state,
                                const struct timespec * timeout);

int             ipcp_parse_arg(int    argc,
                               char * argv[]);

#endif
