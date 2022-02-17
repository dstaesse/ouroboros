/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * IPC process structure
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

#ifndef OUROBOROS_IPCPD_IPCP_H
#define OUROBOROS_IPCPD_IPCP_H

#include <ouroboros/hash.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/list.h>
#include <ouroboros/sockets.h>
#include <ouroboros/tpm.h>

#include <pthread.h>
#include <time.h>

enum ipcp_state {
        IPCP_NULL = 0,
        IPCP_INIT,
        /* Layer name must be set for states below. */
        IPCP_OPERATIONAL,
        IPCP_SHUTDOWN
};

struct ipcp_ops {
        int   (* ipcp_bootstrap)(const struct ipcp_config * conf);

        int   (* ipcp_enroll)(const char *        dst,
                              struct layer_info * info);

        int   (* ipcp_connect)(const char * dst,
                               const char * component,
                               qosspec_t    qs);

        int   (* ipcp_disconnect)(const char * dst,
                                  const char * component);

        int   (* ipcp_reg)(const uint8_t * hash);

        int   (* ipcp_unreg)(const uint8_t * hash);

        int   (* ipcp_query)(const uint8_t * hash);

        int   (* ipcp_flow_alloc)(int             fd,
                                  const uint8_t * dst,
                                  qosspec_t       qs,
                                  const void *    data,
                                  size_t          len);

        int   (* ipcp_flow_join)(int             fd,
                                 const uint8_t * dst,
                                 qosspec_t       qs);

        int   (* ipcp_flow_alloc_resp)(int          fd,
                                       int          response,
                                       const void * data,
                                       size_t       len);

        int   (* ipcp_flow_dealloc)(int fd);
};

#define ipcp_dir_hash_strlen() (hash_len(ipcpi.dir_hash_algo) * 2)
#define ipcp_dir_hash_len() (hash_len(ipcpi.dir_hash_algo))

extern struct ipcp {
        pid_t              irmd_pid;
        char *             name;

        enum ipcp_type     type;
        char *             layer_name;

        uint64_t           dt_addr;

        enum hash_algo     dir_hash_algo;

        struct ipcp_ops *  ops;
        int                irmd_fd;

        enum ipcp_state    state;
        pthread_rwlock_t   state_lock;
        pthread_mutex_t    state_mtx;
        pthread_cond_t     state_cond;

        int                sockfd;
        char *             sock_path;

        struct list_head   cmds;
        pthread_cond_t     cmd_cond;
        pthread_mutex_t    cmd_lock;

        int                alloc_id;
        pthread_cond_t     alloc_cond;
        pthread_mutex_t    alloc_lock;

        struct tpm *       tpm;

        pthread_t          acceptor;
} ipcpi;

int             ipcp_init(int               argc,
                          char **           argv,
                          struct ipcp_ops * ops,
                          enum ipcp_type    type);

int             ipcp_boot(void);

void            ipcp_shutdown(void);

void            ipcp_fini(void);

void            ipcp_set_state(enum ipcp_state state);

enum ipcp_state ipcp_get_state(void);

int             ipcp_parse_arg(int    argc,
                               char * argv[]);

/* Helper functions for directory entries, could be moved */
uint8_t *       ipcp_hash_dup(const uint8_t * hash);

void            ipcp_hash_str(char            buf[],
                              const uint8_t * hash);

/* Helper function to lock a thread to a core. */
void            ipcp_lock_to_core(void);

#endif /* OUROBOROS_IPCPD_IPCP_H */
