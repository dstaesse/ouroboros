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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "ipcpd-local"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/local-dev.h>

#include "ipcp.h"

#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/wait.h>
#include <assert.h>

#define EVENT_WAIT_TIMEOUT 100 /* us */
#define THIS_TYPE IPCP_LOCAL

struct {
        int                   in_out[IRMD_MAX_FLOWS];
        flow_set_t *          flows;
        fqueue_t *            fq;

        pthread_rwlock_t      lock;
        pthread_t             sduloop;
} local_data;

static int local_data_init(void)
{
        int i;
        for (i = 0; i < IRMD_MAX_FLOWS; ++i)
                local_data.in_out[i] = -1;

        local_data.flows = flow_set_create();
        if (local_data.flows == NULL)
                return -ENFILE;

        local_data.fq = fqueue_create();
        if (local_data.fq == NULL) {
                flow_set_destroy(local_data.flows);
                return -ENOMEM;
        }

        pthread_rwlock_init(&local_data.lock, NULL);

        return 0;
}

static void local_data_fini(void)
{
        flow_set_destroy(local_data.flows);
        fqueue_destroy(local_data.fq);
        pthread_rwlock_destroy(&local_data.lock);
}

static void * ipcp_local_sdu_loop(void * o)
{
        struct timespec timeout = {0, EVENT_WAIT_TIMEOUT * 1000};

        (void) o;

        while (true) {
                int fd;
                ssize_t idx;

                pthread_rwlock_rdlock(&ipcpi.state_lock);

                if (ipcp_get_state() != IPCP_OPERATIONAL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        return (void *) 1; /* -ENOTENROLLED */
                }

                pthread_rwlock_unlock(&ipcpi.state_lock);

                flow_event_wait(local_data.flows, local_data.fq, &timeout);

                while ((fd = fqueue_next(local_data.fq)) >= 0) {
                        pthread_rwlock_rdlock(&ipcpi.state_lock);
                        pthread_rwlock_rdlock(&local_data.lock);

                        idx = local_flow_read(fd);

                        assert(idx < (SHM_BUFFER_SIZE));

                        fd = local_data.in_out[fd];

                        if (fd != -1)
                                local_flow_write(fd, idx);

                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        pthread_rwlock_unlock(&local_data.lock);
                }

        }

        return (void *) 0;
}

void ipcp_sig_handler(int         sig,
                      siginfo_t * info,
                      void *      c)
{
        (void) c;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
        case SIGQUIT:
                if (info->si_pid == ipcpi.irmd_api) {
                        pthread_rwlock_wrlock(&ipcpi.state_lock);

                        if (ipcp_get_state() == IPCP_INIT)
                                ipcp_set_state(IPCP_NULL);

                        if (ipcp_get_state() == IPCP_OPERATIONAL)
                                ipcp_set_state(IPCP_SHUTDOWN);

                        pthread_rwlock_unlock(&ipcpi.state_lock);
                }
        default:
                return;
        }
}

static int ipcp_local_bootstrap(struct dif_config * conf)
{
        (void) conf;

        assert(conf);
        assert(conf->type == THIS_TYPE);

        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("IPCP in wrong state.");
                return -1;
        }

        ipcp_set_state(IPCP_OPERATIONAL);

        pthread_create(&local_data.sduloop, NULL, ipcp_local_sdu_loop, NULL);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        log_info("Bootstrapped local IPCP with api %d.", getpid());

        return 0;
}

static int ipcp_local_name_reg(char * name)
{
        char * name_dup = strdup(name);
        if (name_dup == NULL) {
                log_err("Failed to duplicate name.");
                return -ENOMEM;
        }

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (shim_data_reg_add_entry(ipcpi.shim_data, name_dup)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_dbg("Failed to add %s to local registry.", name);
                free(name_dup);
                return -1;
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        log_info("Registered %s.", name);

        return 0;
}

static int ipcp_local_name_unreg(char * name)
{
        pthread_rwlock_rdlock(&ipcpi.state_lock);

        shim_data_reg_del_entry(ipcpi.shim_data, name);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        log_info("Unregistered %s.", name);

        return 0;
}

static int ipcp_local_name_query(char * name)
{
        int ret;

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        ret = (shim_data_reg_has(ipcpi.shim_data, name) ? 0 : -1);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        return ret;
}

static int ipcp_local_flow_alloc(int       fd,
                                 char *    dst_name,
                                 qoscube_t cube)
{
        int out_fd = -1;

        log_dbg("Allocating flow to %s on fd %d.", dst_name, fd);

        assert(dst_name);

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_dbg("Won't allocate over non-operational IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        /*
         * This function needs to return completely before
         * flow_resp. Taking the wrlock on the data is the simplest
         * way to achieve this.
         */

        pthread_rwlock_wrlock(&local_data.lock);

        out_fd = ipcp_flow_req_arr(getpid(), dst_name, cube);
        if (out_fd < 0) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_dbg("Flow allocation failed: %d", out_fd);
                return -1;
        }

        /*
         * The idea of the port_wait_assign in dev.c was to do the
         * above synchronisation. But if the lock is not taken, the
         * resp() function may be called before a lock would be taken
         * here. This shim will be deprecated, but ideally the sync is
         * fixed in ipcp.c.
         */

        local_data.in_out[fd] = out_fd;
        local_data.in_out[out_fd] = fd;

        pthread_rwlock_unlock(&local_data.lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        flow_set_add(local_data.flows, fd);

        log_info("Pending local allocation request on fd %d.", fd);

        return 0;
}

static int ipcp_local_flow_alloc_resp(int fd,
                                      int response)
{
        int out_fd = -1;
        int ret = -1;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&local_data.lock);

        if (response) {
                if (local_data.in_out[fd] != -1)
                        local_data.in_out[local_data.in_out[fd]] = fd;
                local_data.in_out[fd] = -1;
                pthread_rwlock_unlock(&local_data.lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return 0;
        }

        out_fd = local_data.in_out[fd];
        if (out_fd == -1) {
                pthread_rwlock_unlock(&local_data.lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        pthread_rwlock_unlock(&local_data.lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        flow_set_add(local_data.flows, fd);

        if ((ret = ipcp_flow_alloc_reply(out_fd, response)) < 0)
                return -1;

        log_info("Flow allocation completed, fds (%d, %d).", out_fd, fd);

        return ret;
}

static int ipcp_local_flow_dealloc(int fd)
{
        assert(!(fd < 0));

        ipcp_flow_fini(fd);

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&local_data.lock);

        flow_set_del(local_data.flows, fd);

        local_data.in_out[fd] = -1;

        pthread_rwlock_unlock(&local_data.lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        flow_dealloc(fd);

        log_info("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops local_ops = {
        .ipcp_bootstrap       = ipcp_local_bootstrap,
        .ipcp_enroll          = NULL,                       /* shim */
        .ipcp_name_reg        = ipcp_local_name_reg,
        .ipcp_name_unreg      = ipcp_local_name_unreg,
        .ipcp_name_query      = ipcp_local_name_query,
        .ipcp_flow_alloc      = ipcp_local_flow_alloc,
        .ipcp_flow_alloc_resp = ipcp_local_flow_alloc_resp,
        .ipcp_flow_dealloc    = ipcp_local_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        struct sigaction sig_act;
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        /* init sig_act */
        memset(&sig_act, 0, sizeof(sig_act));

        /* install signal traps */
        sig_act.sa_sigaction = &ipcp_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        sigaction(SIGINT,  &sig_act, NULL);
        sigaction(SIGTERM, &sig_act, NULL);
        sigaction(SIGHUP,  &sig_act, NULL);
        sigaction(SIGPIPE, &sig_act, NULL);

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

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                ipcp_create_r(getpid(), -1);
                local_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

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
