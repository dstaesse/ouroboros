/*
 * Ouroboros - Copyright (C) 2016
 *
 * Normal IPC Process
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
#include <ouroboros/shm_du_map.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/time_utils.h>

#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include "fmgr.h"
#include "ribmgr.h"
#include "ipcp.h"
#include "frct.h"

#define THIS_TYPE IPCP_NORMAL

/* global for trapping signal */
int irmd_api;

struct ipcp * _ipcp;

#define normal_data(type) ((struct normal_ipcp_data *) type->data)

struct normal_ipcp_data {
        /* Keep ipcp_data first for polymorphism. */
        struct ipcp_data      ipcp_data;

        struct shm_du_map *   dum;
        struct shm_ap_rbuff * rb;

        pthread_t             mainloop;
};

void ipcp_sig_handler(int sig, siginfo_t * info, void * c)
{
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                if (info->si_pid == irmd_api) {
                        LOG_DBG("Terminating by order of %d. Bye.",
                                info->si_pid);

                        pthread_rwlock_wrlock(&_ipcp->state_lock);

                        ipcp_set_state(_ipcp, IPCP_SHUTDOWN);

                        pthread_rwlock_unlock(&_ipcp->state_lock);

                        if (fmgr_fini())
                                LOG_ERR("Failed to finalize flow manager.");

                        if (ribmgr_fini())
                                LOG_ERR("Failed to finalize RIB manager.");

                        if (frct_fini())
                                LOG_ERR("Failed to finalize FRCT.");
                }
        default:
                return;
        }
}

static int normal_ipcp_name_reg(char * name)
{
        pthread_rwlock_rdlock(&_ipcp->state_lock);

        if (ipcp_data_add_reg_entry(_ipcp->data, name)) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("Failed to add %s to local registry.", name);
                return -1;
        }

        pthread_rwlock_unlock(&_ipcp->state_lock);

        LOG_DBG("Registered %s.", name);

        return 0;
}

static int normal_ipcp_name_unreg(char * name)
{
        pthread_rwlock_rdlock(&_ipcp->state_lock);

        ipcp_data_del_reg_entry(_ipcp->data, name);

        pthread_rwlock_unlock(&_ipcp->state_lock);

        return 0;
}

static int normal_ipcp_enroll(char * dif_name)
{
        struct timespec timeout = {(ENROLL_TIMEOUT / 1000),
                                   (ENROLL_TIMEOUT % 1000) * MILLION};

        pthread_rwlock_rdlock(&_ipcp->state_lock);

        if (ipcp_get_state(_ipcp) != IPCP_INIT) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("Won't enroll an IPCP that is not in INIT.");
                return -1; /* -ENOTINIT */
        }

        if (fmgr_mgmt_flow(dif_name)) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("Failed to establish management flow.");
                return -1;
        }

        pthread_rwlock_unlock(&_ipcp->state_lock);

        if (ipcp_wait_state(_ipcp, IPCP_ENROLLED, &timeout) == -ETIMEDOUT) {
                LOG_ERR("Enrollment timed out.");
                return -1;
        }

        pthread_rwlock_rdlock(&_ipcp->state_lock);

        if (ipcp_get_state(_ipcp) != IPCP_ENROLLED) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                return -1;
        }

        return 0;
}

static int normal_ipcp_bootstrap(struct dif_config * conf)
{
        pthread_rwlock_wrlock(&_ipcp->state_lock);

        if (ipcp_get_state(_ipcp) != IPCP_INIT) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("Won't bootstrap an IPCP that is not in INIT.");
                return -1; /* -ENOTINIT */
        }

        if (ribmgr_bootstrap(conf)) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("Failed to bootstrap RIB manager.");
                return -1;
        }

        ipcp_set_state(_ipcp, IPCP_ENROLLED);

        _ipcp->data->dif_name = conf->dif_name;

        pthread_rwlock_unlock(&_ipcp->state_lock);

        LOG_DBG("Bootstrapped in DIF %s.", conf->dif_name);

        return 0;
}

static struct ipcp_ops normal_ops = {
        .ipcp_bootstrap       = normal_ipcp_bootstrap,
        .ipcp_enroll          = normal_ipcp_enroll,
        .ipcp_name_reg        = normal_ipcp_name_reg,
        .ipcp_name_unreg      = normal_ipcp_name_unreg,
        .ipcp_flow_alloc      = fmgr_flow_alloc,
        .ipcp_flow_alloc_resp = fmgr_flow_alloc_resp,
        .ipcp_flow_dealloc    = fmgr_flow_dealloc
};

struct normal_ipcp_data * normal_ipcp_data_create()
{
        struct normal_ipcp_data * normal_data;
        enum ipcp_type            ipcp_type;

        normal_data = malloc(sizeof(*normal_data));
        if (normal_data == NULL) {
                LOG_ERR("Failed to allocate.");
                return NULL;
        }

        ipcp_type = THIS_TYPE;
        if (ipcp_data_init((struct ipcp_data *) normal_data,
                           ipcp_type) == NULL) {
                free(normal_data);
                return NULL;
        }

        normal_data->dum = shm_du_map_open();
        if (normal_data->dum == NULL) {
                free(normal_data);
                return NULL;
        }

        normal_data->rb = shm_ap_rbuff_open(getpid());
        if (normal_data->rb == NULL) {
                shm_du_map_close(normal_data->dum);
                free(normal_data);
                return NULL;
        }

        return normal_data;
}


void normal_ipcp_data_destroy()
{
        if (_ipcp == NULL)
                return;

        pthread_rwlock_rdlock(&_ipcp->state_lock);

        if (ipcp_get_state(_ipcp) != IPCP_SHUTDOWN)
                LOG_WARN("Cleaning up while not in shutdown.");

        if (normal_data(_ipcp)->dum != NULL)
                shm_du_map_close_on_exit(normal_data(_ipcp)->dum);
        if (normal_data(_ipcp)->rb != NULL)
                shm_ap_rbuff_close(normal_data(_ipcp)->rb);

        pthread_rwlock_unlock(&_ipcp->state_lock);

        ipcp_data_destroy(_ipcp->data);
}

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

        _ipcp = ipcp_instance_create();
        if (_ipcp == NULL) {
                LOG_ERR("Failed to create instance.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        _ipcp->data = (struct ipcp_data *) normal_ipcp_data_create();
        if (_ipcp->data == NULL) {
                LOG_ERR("Failed to create instance data.");
                free(_ipcp);
                close_logfile();
                exit(EXIT_FAILURE);
        }

        _ipcp->ops = &normal_ops;
        _ipcp->state = IPCP_INIT;

        if (fmgr_init()) {
                normal_ipcp_data_destroy();
                free(_ipcp);
                close_logfile();
                exit(EXIT_FAILURE);
        }

        if (ribmgr_init()) {
                normal_ipcp_data_destroy();
                fmgr_fini();
                free(_ipcp);
                close_logfile();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        pthread_create(&normal_data(_ipcp)->mainloop, NULL,
                       ipcp_main_loop, _ipcp);

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        if (ipcp_create_r(getpid())) {
                LOG_ERR("Failed to notify IRMd we are initialized.");
                normal_ipcp_data_destroy();
                fmgr_fini();
                free(_ipcp);
                close_logfile();
                exit(EXIT_FAILURE);
        }

        pthread_join(normal_data(_ipcp)->mainloop, NULL);

        normal_ipcp_data_destroy();
        free(_ipcp);
        close_logfile();

        ap_fini();
        exit(EXIT_SUCCESS);
}
