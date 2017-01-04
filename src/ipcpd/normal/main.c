/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Normal IPC Process
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "normal-ipcp"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/time_utils.h>

#include "fmgr.h"
#include "ribmgr.h"
#include "ipcp.h"
#include "frct.h"
#include "dir.h"

#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#define THIS_TYPE IPCP_NORMAL

/* global for trapping signal */
int irmd_api;

pthread_t acceptor;

void ipcp_sig_handler(int sig, siginfo_t * info, void * c)
{
        (void) c;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                if (info->si_pid == irmd_api) {
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

static void * flow_acceptor(void * o)
{
        int       fd;
        char *    ae_name;
        qosspec_t qs;

        (void) o;

        while (true) {
                pthread_rwlock_rdlock(&ipcpi.state_lock);

                if (ipcp_get_state() != IPCP_OPERATIONAL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        LOG_INFO("Shutting down flow acceptor.");
                        return 0;
                }

                pthread_rwlock_unlock(&ipcpi.state_lock);

                fd = flow_accept(&ae_name, &qs);
                if (fd < 0) {
                        LOG_WARN("Flow accept failed.");
                        continue;
                }

                LOG_DBG("New flow allocation request for AE %s.", ae_name);

                if (strcmp(ae_name, MGMT_AE) == 0) {
                        ribmgr_add_nm1_flow(fd);
                } else if (strcmp(ae_name, DT_AE) == 0) {
                        fmgr_nm1_add_flow(fd);
                } else {
                        LOG_DBG("Flow allocation request for unknown AE %s.",
                                ae_name);
                        if (flow_alloc_resp(fd, -1))
                                LOG_WARN("Failed to reply to flow allocation.");
                        flow_dealloc(fd);
                }

                free(ae_name);
        }

        return (void *) 0;
}

static int normal_ipcp_enroll(char * dst_name)
{
        int ret;

        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Won't enroll an IPCP that is not in INIT.");
                return -1; /* -ENOTINIT */
        }

        if (ribmgr_init()) {
                LOG_ERR("Failed to initialise RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        if (ribmgr_nm1_mgt_flow(dst_name)) {
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                LOG_ERR("Failed to establish management flow.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        ret = ribmgr_enrol();
        if (ret < 0) {
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                if (ret == -ETIMEDOUT)
                        LOG_ERR("Enrollment timed out.");
                else
                        LOG_ERR("Failed to enrol IPCP: %d.", ret);
                return -1;
        }

        if (ribmgr_start_policies()) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to start policies.");
                return -1;
        }

        if (fmgr_init()) {
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to start flow manager.");
                return -1;
        }

        if (frct_init()) {
                if (fmgr_fini())
                        LOG_WARN("Failed to finalize flow manager.");
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to initialize FRCT.");
                return -1;
        }

        ipcp_set_state(IPCP_OPERATIONAL);

        if (pthread_create(&acceptor, NULL, flow_acceptor, NULL)) {
                if (frct_fini())
                        LOG_WARN("Failed to finalize frct.");
                if (fmgr_fini())
                        LOG_WARN("Failed to finalize flow manager.");
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                ipcp_set_state(IPCP_INIT);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to create acceptor thread.");
                return -1;
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        /* FIXME: Remove once we obtain neighbors during enrollment */
        if (fmgr_nm1_dt_flow(dst_name, QOS_CUBE_BE)) {
                LOG_ERR("Failed to establish data transfer flow.");
                return -1;
        }

        LOG_DBG("Enrolled with %s.", dst_name);

        return 0;
}

static int normal_ipcp_bootstrap(struct dif_config * conf)
{
        if (conf == NULL || conf->type != THIS_TYPE) {
                LOG_ERR("Bad DIF configuration.");
                return -EINVAL;
        }

        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Won't bootstrap an IPCP that is not in INIT.");
                return -1; /* -ENOTINIT */
        }

        if (ribmgr_init()) {
                LOG_ERR("Failed to initialise RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        if (ribmgr_bootstrap(conf)) {
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to bootstrap RIB manager.");
                return -1;
        }

        if (ribmgr_start_policies()) {
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to start policies.");
                return -1;
        }

        if (fmgr_init()) {
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to start flow manager.");
                return -1;
        }

        if (frct_init()) {
                if (fmgr_fini())
                        LOG_WARN("Failed to finalize flow manager.");
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to initialize FRCT.");
                return -1;
        }

        ipcp_set_state(IPCP_OPERATIONAL);

        if (pthread_create(&acceptor, NULL, flow_acceptor, NULL)) {
                if (frct_fini())
                        LOG_WARN("Failed to finalize frct.");
                if (fmgr_fini())
                        LOG_WARN("Failed to finalize flow manager.");
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
                ipcp_set_state(IPCP_INIT);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to create acceptor thread.");
                return -1;
        }

        ipcpi.data->dif_name = conf->dif_name;

        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_DBG("Bootstrapped in DIF %s.", conf->dif_name);

        return 0;
}

static struct ipcp_ops normal_ops = {
        .ipcp_bootstrap       = normal_ipcp_bootstrap,
        .ipcp_enroll          = normal_ipcp_enroll,
        .ipcp_name_reg        = dir_name_reg,
        .ipcp_name_unreg      = dir_name_unreg,
        .ipcp_name_query      = dir_name_query,
        .ipcp_flow_alloc      = fmgr_np1_alloc,
        .ipcp_flow_alloc_resp = fmgr_np1_alloc_resp,
        .ipcp_flow_dealloc    = fmgr_np1_dealloc
};

int main(int argc, char * argv[])
{
        struct sigaction sig_act;
        sigset_t sigset;

        if (ap_init(argv[0])) {
                LOG_ERR("Failed to init AP");
                exit(EXIT_FAILURE);
        }

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        if (ipcp_parse_arg(argc, argv)) {
                LOG_ERR("Failed to parse arguments.");
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

        if (ipcp_init(THIS_TYPE, &normal_ops) < 0) {
                LOG_ERR("Failed to create instance.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (ipcp_boot() < 0) {
                LOG_ERR("Failed to boot IPCP.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        if (ipcp_create_r(getpid())) {
                LOG_ERR("Failed to notify IRMd we are initialized.");
                ipcp_fini();
                close_logfile();
                exit(EXIT_FAILURE);
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                pthread_cancel(acceptor);
                pthread_join(acceptor, NULL);

                if (frct_fini())
                        LOG_WARN("Failed to finalize FRCT.");
                if (fmgr_fini())
                        LOG_WARN("Failed to finalize flow manager.");
                if (ribmgr_fini())
                        LOG_WARN("Failed to finalize RIB manager.");
        }

        ipcp_fini();

        close_logfile();

        ap_fini();

        exit(EXIT_SUCCESS);
}
