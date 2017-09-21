/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Local IPC process
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200112L

#include "config.h"

#define OUROBOROS_PREFIX "ipcpd-local"

#include <ouroboros/hash.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/local-dev.h>

#include "ipcp.h"
#include "shim-data.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/wait.h>
#include <assert.h>

#define THIS_TYPE     IPCP_LOCAL
#define ALLOC_TIMEOUT 10 /* ms */

struct {
        struct shim_data * shim_data;

        int                in_out[SYS_MAX_FLOWS];
        fset_t *           flows;
        fqueue_t *         fq;

        pthread_rwlock_t   lock;
        pthread_t          sduloop;
} local_data;

static int local_data_init(void)
{
        int i;
        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                local_data.in_out[i] = -1;

        local_data.flows = fset_create();
        if (local_data.flows == NULL)
                return -ENFILE;

        local_data.fq = fqueue_create();
        if (local_data.fq == NULL) {
                fset_destroy(local_data.flows);
                return -ENOMEM;
        }

        local_data.shim_data = shim_data_create();
        if (local_data.shim_data == NULL) {
                fqueue_destroy(local_data.fq);
                fset_destroy(local_data.flows);
                return -ENOMEM;
        }

        pthread_rwlock_init(&local_data.lock, NULL);

        return 0;
}

static void local_data_fini(void){
        shim_data_destroy(local_data.shim_data);
        fset_destroy(local_data.flows);
        fqueue_destroy(local_data.fq);
        pthread_rwlock_destroy(&local_data.lock);
}

static void * ipcp_local_sdu_loop(void * o)
{
        (void) o;

        while (true) {
                int     fd;
                ssize_t idx;

                fevent(local_data.flows, local_data.fq, NULL);

                while ((fd = fqueue_next(local_data.fq)) >= 0) {
                        idx = local_flow_read(fd);
                        if (idx < 0)
                                continue;

                        assert(idx < (SHM_BUFFER_SIZE));

                        pthread_rwlock_rdlock(&local_data.lock);

                        fd = local_data.in_out[fd];

                        pthread_rwlock_unlock(&local_data.lock);

                        if (fd != -1)
                                local_flow_write(fd, idx);
                }
        }

        return (void *) 0;
}

static int ipcp_local_bootstrap(const struct ipcp_config * conf)
{
        assert(conf);
        assert(conf->type == THIS_TYPE);

        (void) conf;

        ipcp_set_state(IPCP_OPERATIONAL);

        if (pthread_create(&local_data.sduloop, NULL,
                           ipcp_local_sdu_loop, NULL)) {
                ipcp_set_state(IPCP_INIT);
                return -1;
        }

        log_info("Bootstrapped local IPCP with api %d.", getpid());

        return 0;
}

static int ipcp_local_reg(const uint8_t * hash)
{
        if (shim_data_reg_add_entry(local_data.shim_data, hash)) {
                log_dbg("Failed to add " HASH_FMT " to local registry.",
                        HASH_VAL(hash));
                return -1;
        }

        log_info("Registered " HASH_FMT ".", HASH_VAL(hash));

        return 0;
}

static int ipcp_local_unreg(const uint8_t * hash)
{
        shim_data_reg_del_entry(local_data.shim_data, hash);

        log_info("Unregistered " HASH_FMT ".",  HASH_VAL(hash));

        return 0;
}

static int ipcp_local_query(const uint8_t * hash)
{
        int ret;

        ret = (shim_data_reg_has(local_data.shim_data, hash) ? 0 : -1);

        return ret;
}

static int ipcp_local_flow_alloc(int             fd,
                                 const uint8_t * dst,
                                 qoscube_t       cube)
{
        struct timespec ts     = {0, ALLOC_TIMEOUT * MILLION};
        struct timespec abstime;
        int             out_fd = -1;

        log_dbg("Allocating flow to " HASH_FMT " on fd %d.", HASH_VAL(dst), fd);

        assert(dst);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != -1 && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_dbg("Won't allocate over non-operational IPCP.");
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                return -1;
        }

        assert(ipcpi.alloc_id == -1);

        out_fd = ipcp_flow_req_arr(getpid(), dst, ipcp_dir_hash_len(), cube);
        if (out_fd < 0) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                log_dbg("Flow allocation failed: %d", out_fd);
                return -1;
        }

        pthread_rwlock_wrlock(&local_data.lock);

        local_data.in_out[fd] = out_fd;
        local_data.in_out[out_fd] = fd;

        pthread_rwlock_unlock(&local_data.lock);

        ipcpi.alloc_id = out_fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        fset_add(local_data.flows, fd);

        log_info("Pending local allocation request on fd %d.", fd);

        return 0;
}

static int ipcp_local_flow_alloc_resp(int fd,
                                      int response)
{
        struct timespec ts     = {0, ALLOC_TIMEOUT * MILLION};
        struct timespec abstime;
        int             out_fd = -1;
        int             ret    = -1;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != fd && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                return -1;
        }

        ipcpi.alloc_id = -1;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        pthread_rwlock_wrlock(&local_data.lock);

        if (response) {
                if (local_data.in_out[fd] != -1)
                        local_data.in_out[local_data.in_out[fd]] = fd;
                local_data.in_out[fd] = -1;
                pthread_rwlock_unlock(&local_data.lock);
                return 0;
        }

        out_fd = local_data.in_out[fd];
        if (out_fd == -1) {
                pthread_rwlock_unlock(&local_data.lock);
                return -1;
        }

        pthread_rwlock_unlock(&local_data.lock);

        fset_add(local_data.flows, fd);

        if ((ret = ipcp_flow_alloc_reply(out_fd, response)) < 0)
                return -1;

        log_info("Flow allocation completed, fds (%d, %d).", out_fd, fd);

        return 0;
}

static int ipcp_local_flow_dealloc(int fd)
{
        assert(!(fd < 0));

        ipcp_flow_fini(fd);

        pthread_rwlock_wrlock(&local_data.lock);

        fset_del(local_data.flows, fd);

        local_data.in_out[fd] = -1;

        pthread_rwlock_unlock(&local_data.lock);

        flow_dealloc(fd);

        log_info("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops local_ops = {
        .ipcp_bootstrap       = ipcp_local_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_connect         = NULL,
        .ipcp_disconnect      = NULL,
        .ipcp_reg             = ipcp_local_reg,
        .ipcp_unreg           = ipcp_local_unreg,
        .ipcp_query           = ipcp_local_query,
        .ipcp_flow_alloc      = ipcp_local_flow_alloc,
        .ipcp_flow_alloc_resp = ipcp_local_flow_alloc_resp,
        .ipcp_flow_dealloc    = ipcp_local_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, THIS_TYPE, &local_ops) < 0) {
                ipcp_create_r(getpid(), -1);
                exit(EXIT_FAILURE);
        }

        if (local_data_init() < 0) {
                log_err("Failed to init local data.");
                ipcp_create_r(getpid(), -1);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                ipcp_create_r(getpid(), -1);
                local_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (ipcp_create_r(getpid(), 0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                ipcp_shutdown();
                local_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                pthread_cancel(local_data.sduloop);
                pthread_join(local_data.sduloop, NULL);
        }

        local_data_fini();

        ipcp_fini();

        exit(EXIT_SUCCESS);
}
