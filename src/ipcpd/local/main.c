/*
 * Ouroboros - Copyright (C) 2016
 *
 * Local IPC process
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#define OUROBOROS_PREFIX "ipcpd/local"

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

/* global for trapping signal */
int irmd_api;

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

        while (flow_event_wait(local_data.flows, local_data.fq, &timeout)) {
                int fd;
                ssize_t idx;

                pthread_rwlock_rdlock(&ipcpi.state_lock);

                if (ipcp_get_state() != IPCP_OPERATIONAL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        return (void *) 1; /* -ENOTENROLLED */
                }

                pthread_rwlock_rdlock(&local_data.lock);

                while ((fd = fqueue_next(local_data.fq)) >= 0) {
                        idx = local_flow_read(fd);

                        assert(idx < (SHM_BUFFER_SIZE));

                        fd = local_data.in_out[fd];

                        if (fd != -1)
                                local_flow_write(fd, idx);
                }

                pthread_rwlock_unlock(&local_data.lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
        }

        return (void *) 0;
}

void ipcp_sig_handler(int sig, siginfo_t * info, void * c)
{
        (void) c;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
        case SIGQUIT:
                if (info->si_pid == irmd_api) {
                        LOG_DBG("IPCP %d terminating by order of %d. Bye.",
                                getpid(), info->si_pid);

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
        assert(conf);
        assert(conf->type == THIS_TYPE);

        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("IPCP in wrong state.");
                return -1;
        }

        /* this IPCP doesn't need to maintain its dif_name */
        free(conf->dif_name);

        ipcp_set_state(IPCP_OPERATIONAL);

        pthread_create(&local_data.sduloop, NULL, ipcp_local_sdu_loop, NULL);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_INFO("Bootstrapped local IPCP with api %d.", getpid());

        return 0;
}

static int ipcp_local_name_reg(char * name)
{
        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_data_reg_add_entry(ipcpi.data, name)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_DBG("Failed to add %s to local registry.", name);
                return -1;
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_INFO("Registered %s.", name);

        return 0;
}

static int ipcp_local_name_unreg(char * name)
{
        pthread_rwlock_rdlock(&ipcpi.state_lock);

        ipcp_data_reg_del_entry(ipcpi.data, name);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_INFO("Unregistered %s.", name);

        return 0;
}

static int ipcp_local_name_query(char * name)
{
        int ret;

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        ret = (ipcp_data_reg_has(ipcpi.data, name) ? 0 : -1);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        return ret;
}

static int ipcp_local_flow_alloc(int       fd,
                                 char *    dst_name,
                                 char *    src_ae_name,
                                 qoscube_t cube)
{
        int out_fd = -1;

        LOG_DBG("Allocating flow to %s on fd %d.", dst_name, fd);

        assert(dst_name);
        assert(src_ae_name);

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_DBG("Won't register with non-enrolled IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        pthread_rwlock_wrlock(&local_data.lock);

        out_fd = ipcp_flow_req_arr(getpid(), dst_name, src_ae_name, cube);

        local_data.in_out[fd]  = out_fd;
        local_data.in_out[out_fd] = fd;

        flow_set_add(local_data.flows, fd);

        pthread_rwlock_unlock(&local_data.lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_INFO("Pending local allocation request on fd %d.", fd);

        return 0;
}

static int ipcp_local_flow_alloc_resp(int fd, int response)
{
        int out_fd = -1;
        int ret = -1;

        if (response)
                return 0;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_rdlock(&local_data.lock);

        out_fd = local_data.in_out[fd];
        if (out_fd < 0) {
                pthread_rwlock_unlock(&local_data.lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        flow_set_add(local_data.flows, fd);

        pthread_rwlock_unlock(&local_data.lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        if ((ret = ipcp_flow_alloc_reply(out_fd, response)) < 0)
                return -1;

        LOG_INFO("Flow allocation completed, fds (%d, %d).", out_fd, fd);

        return ret;
}

static int ipcp_local_flow_dealloc(int fd)
{
        assert(!(fd < 0));

        ipcp_flow_fini(fd);

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_DBG("Won't register with non-enrolled IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        pthread_rwlock_wrlock(&local_data.lock);

        flow_set_del(local_data.flows, fd);

        local_data.in_out[fd] = -1;

        flow_dealloc(fd);

        pthread_rwlock_unlock(&local_data.lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_INFO("Flow with fd %d deallocated.", fd);

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

int main(int argc, char * argv[])
{
        struct sigaction sig_act;
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        if (ipcp_parse_arg(argc, argv)) {
                LOG_ERR("Failed to parse arguments.");
                exit(EXIT_FAILURE);
        }

        if (ap_init(NULL) < 0) {
                LOG_ERR("Failed to init application.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        if (local_data_init() < 0) {
                LOG_ERR("Failed to init local data.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        /* store the process id of the irmd */
        irmd_api = atoi(argv[1]);

        /* init sig_act */
        memset(&sig_act, 0, sizeof(sig_act));

        /* install signal traps */
        sig_act.sa_sigaction = &ipcp_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        sigaction(SIGINT,  &sig_act, NULL);
        sigaction(SIGTERM, &sig_act, NULL);
        sigaction(SIGHUP,  &sig_act, NULL);
        sigaction(SIGPIPE, &sig_act, NULL);

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (ipcp_init(THIS_TYPE, &local_ops) < 0) {
                close_logfile();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        if (ipcp_create_r(getpid())) {
                LOG_ERR("Failed to notify IRMd we are initialized.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        ipcp_fini();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                pthread_cancel(local_data.sduloop);
                pthread_join(local_data.sduloop, NULL);
        }

        local_data_fini();

        ap_fini();

        close_logfile();

        exit(EXIT_SUCCESS);
}
