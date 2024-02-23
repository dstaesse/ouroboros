/*
 * Ouroboros - Copyright (C) 2016 - 2024
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

#define THIS_TYPE IPCP_LOCAL

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
        pthread_rwlock_destroy(&local_data.lock);
        shim_data_destroy(local_data.shim_data);
        fqueue_destroy(local_data.fq);
        fset_destroy(local_data.flows);
}

static void * local_ipcp_packet_loop(void * o)
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

static int local_ipcp_bootstrap(const struct ipcp_config * conf)
{
        assert(conf);
        assert(conf->type == THIS_TYPE);

        ipcpi.dir_hash_algo = (enum hash_algo) conf->layer_info.dir_hash_algo;
        strcpy(ipcpi.layer_name,conf->layer_info.name);

        if (pthread_create(&local_data.packet_loop, NULL,
                           local_ipcp_packet_loop, NULL)) {
                log_err("Failed to create pthread: %s", strerror(errno));
                ipcp_set_state(IPCP_INIT);
                return -1;
        }

        return 0;
}

static int local_ipcp_reg(const uint8_t * hash)
{
        if (shim_data_reg_add_entry(local_data.shim_data, hash)) {
                log_err("Failed to add " HASH_FMT32 " to local registry.",
                        HASH_VAL32(hash));
                return -1;
        }

        return 0;
}

static int local_ipcp_unreg(const uint8_t * hash)
{
        shim_data_reg_del_entry(local_data.shim_data, hash);

        log_info("Unregistered " HASH_FMT32 ".",  HASH_VAL32(hash));

        return 0;
}

static int local_ipcp_query(const uint8_t * hash)
{
        int ret;

        ret = (shim_data_reg_has(local_data.shim_data, hash) ? 0 : -1);

        return ret;
}

static int local_ipcp_flow_alloc(int              fd,
                                 const uint8_t *  dst,
                                 qosspec_t        qs,
                                 const buffer_t * data)
{
        int out_fd = -1;

        log_dbg("Allocating flow to " HASH_FMT32 " on fd %d.",
                HASH_VAL32(dst), fd);
        assert(dst);

        out_fd = ipcp_wait_flow_req_arr(dst, qs, IPCP_LOCAL_MPL, data);
        if (out_fd < 0) {
                log_dbg("Flow allocation failed: %d", out_fd);
                return -1;
        }

        pthread_rwlock_wrlock(&local_data.lock);

        local_data.in_out[fd] = out_fd;
        local_data.in_out[out_fd] = fd;

        pthread_rwlock_unlock(&local_data.lock);

        fset_add(local_data.flows, fd);

        log_info("Pending local allocation request on fd %d.", fd);

        return 0;
}

static int local_ipcp_flow_alloc_resp(int              fd,
                                      int              response,
                                      const buffer_t * data)
{
        int    out_fd;
        time_t mpl = IPCP_LOCAL_MPL;

        if (ipcp_wait_flow_resp(fd) < 0) {
                log_err("Failed waiting for IRMd response.");
                return -1;
        }

        pthread_rwlock_wrlock(&local_data.lock);

        if (response < 0) {
                if (local_data.in_out[fd] != -1)
                        local_data.in_out[local_data.in_out[fd]] = fd;
                local_data.in_out[fd] = -1;
                pthread_rwlock_unlock(&local_data.lock);
                return 0;
        }

        out_fd = local_data.in_out[fd];
        if (out_fd == -1) {
                pthread_rwlock_unlock(&local_data.lock);
                log_err("Invalid out_fd.");
                return -1;
        }

        pthread_rwlock_unlock(&local_data.lock);

        fset_add(local_data.flows, fd);

        if (ipcp_flow_alloc_reply(out_fd, response, mpl, data) < 0) {
                log_err("Failed to reply to allocation");
                fset_del(local_data.flows, fd);
                return -1;
        }

        log_info("Flow allocation completed, fds (%d, %d).", out_fd, fd);

        return 0;
}

static int local_ipcp_flow_dealloc(int fd)
{
        assert(!(fd < 0));

        ipcp_flow_fini(fd);

        pthread_rwlock_wrlock(&local_data.lock);

        fset_del(local_data.flows, fd);

        local_data.in_out[fd] = -1;

        pthread_rwlock_unlock(&local_data.lock);

        ipcp_flow_dealloc(fd);

        log_info("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops local_ops = {
        .ipcp_bootstrap       = local_ipcp_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_connect         = NULL,
        .ipcp_disconnect      = NULL,
        .ipcp_reg             = local_ipcp_reg,
        .ipcp_unreg           = local_ipcp_unreg,
        .ipcp_query           = local_ipcp_query,
        .ipcp_flow_alloc      = local_ipcp_flow_alloc,
        .ipcp_flow_join       = NULL,
        .ipcp_flow_alloc_resp = local_ipcp_flow_alloc_resp,
        .ipcp_flow_dealloc    = local_ipcp_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (local_data_init() < 0) {
                log_err("Failed to init local data.");
                goto fail_data_init;
        }

        if (ipcp_init(argc, argv, &local_ops, THIS_TYPE) < 0)
                goto fail_init;

        if (ipcp_start() < 0) {
                log_err("Failed to start IPCP.");
                goto fail_start;
        }

        ipcp_sigwait();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                pthread_cancel(local_data.packet_loop);
                pthread_join(local_data.packet_loop, NULL);
        }

        ipcp_stop();

        ipcp_fini();

        local_data_fini();

        exit(EXIT_SUCCESS);

 fail_start:
        ipcp_fini();
 fail_init:
        local_data_fini();
 fail_data_init:
        exit(EXIT_FAILURE);
}
