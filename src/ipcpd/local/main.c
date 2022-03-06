/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Local IPC process
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

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

struct ipcp ipcpi;

struct {
        struct shim_data * shim_data;

        int                in_out[SYS_MAX_FLOWS];
        fset_t *           flows;
        fqueue_t *         fq;

        pthread_rwlock_t   lock;
        pthread_t          packet_loop;
} local_data;

static int local_data_init(void)
{
        int i;
        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                local_data.in_out[i] = -1;

        local_data.flows = fset_create();
        if (local_data.flows == NULL)
                goto fail_fset;

        local_data.fq = fqueue_create();
        if (local_data.fq == NULL)
                goto fail_fqueue;

        local_data.shim_data = shim_data_create();
        if (local_data.shim_data == NULL)
                goto fail_shim_data;

        if (pthread_rwlock_init(&local_data.lock, NULL) < 0)
                goto fail_rwlock_init;
        return 0;

 fail_rwlock_init:
        shim_data_destroy(local_data.shim_data);
 fail_shim_data:
        fqueue_destroy(local_data.fq);
 fail_fqueue:
        fset_destroy(local_data.flows);
 fail_fset:
        return -ENOMEM;
}

static void local_data_fini(void){
        shim_data_destroy(local_data.shim_data);
        fset_destroy(local_data.flows);
        fqueue_destroy(local_data.fq);
        pthread_rwlock_destroy(&local_data.lock);
}

static void * ipcp_local_packet_loop(void * o)
{
        (void) o;

        ipcp_lock_to_core();

        while (true) {
                int     fd;
                ssize_t idx;

                fevent(local_data.flows, local_data.fq, NULL);

                while ((fd = fqueue_next(local_data.fq)) >= 0) {
                        if (fqueue_type(local_data.fq) != FLOW_PKT)
                                continue;

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

        ipcpi.dir_hash_algo = conf->layer_info.dir_hash_algo;
        ipcpi.layer_name = strdup(conf->layer_info.layer_name);
        if (ipcpi.layer_name == NULL) {
                log_err("Failed to set layer name");
                return -ENOMEM;
        }

        ipcp_set_state(IPCP_OPERATIONAL);

        if (pthread_create(&local_data.packet_loop, NULL,
                           ipcp_local_packet_loop, NULL)) {
                ipcp_set_state(IPCP_INIT);
                return -1;
        }

        log_info("Bootstrapped local IPCP with pid %d.", getpid());

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
                                 qosspec_t       qs,
                                 const void *    data,
                                 size_t          len)
{
        struct timespec ts     = {0, ALLOC_TIMEOUT * MILLION};
        struct timespec abstime;
        int             out_fd = -1;
        time_t          mpl    = IPCP_LOCAL_MPL;

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

        out_fd = ipcp_flow_req_arr(dst, ipcp_dir_hash_len(), qs, mpl,
                                   data, len);
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

static int ipcp_local_flow_alloc_resp(int          fd,
                                      int          response,
                                      const void * data,
                                      size_t       len)
{
        struct timespec ts     = {0, ALLOC_TIMEOUT * MILLION};
        struct timespec abstime;
        int             out_fd = -1;
        time_t          mpl    = IPCP_LOCAL_MPL;

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

        if (ipcp_flow_alloc_reply(out_fd, response, mpl, data, len) < 0)
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
        .ipcp_flow_join       = NULL,
        .ipcp_flow_alloc_resp = ipcp_local_flow_alloc_resp,
        .ipcp_flow_dealloc    = ipcp_local_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, &local_ops, THIS_TYPE) < 0)
                goto fail_init;

        if (local_data_init() < 0) {
                log_err("Failed to init local data.");
                goto fail_data_init;
        }

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                goto fail_boot;
        }

        if (ipcp_create_r(0)) {
                log_err("Failed to notify IRMd we are initialized.");
                goto fail_create_r;
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                pthread_cancel(local_data.packet_loop);
                pthread_join(local_data.packet_loop, NULL);
        }

        local_data_fini();

        ipcp_fini();

        exit(EXIT_SUCCESS);
 fail_create_r:
        ipcp_set_state(IPCP_NULL);
        ipcp_shutdown();
 fail_boot:
        local_data_fini();
 fail_data_init:
        ipcp_fini();
 fail_init:
        ipcp_create_r(-1);
        exit(EXIT_FAILURE);
}
