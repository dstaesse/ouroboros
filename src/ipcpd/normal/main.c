/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Normal IPC Process
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "normal-ipcp"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/irm.h>
#include <ouroboros/rib.h>
#include <ouroboros/irm_config.h>

#include "addr_auth.h"
#include "ae.h"
#include "dir.h"
#include "enroll.h"
#include "fmgr.h"
#include "frct.h"
#include "ipcp.h"
#include "ribmgr.h"

#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define DLR          "/"
#define DIF_PATH     DLR DIF_NAME
#define BOOT_PATH    DLR BOOT_NAME
#define MEMBERS_PATH DLR MEMBERS_NAME

#define THIS_TYPE    IPCP_NORMAL

struct {
        pthread_t acceptor;
        struct addr_auth * auth;
} normal;

void ipcp_sig_handler(int         sig,
                      siginfo_t * info,
                      void *      c)
{
        (void) c;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
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
                        log_info("Shutting down flow acceptor.");
                        return 0;
                }

                pthread_rwlock_unlock(&ipcpi.state_lock);

                fd = flow_accept(&ae_name, &qs);
                if (fd < 0) {
                        log_warn("Flow accept failed.");
                        continue;
                }

                log_dbg("New flow allocation request for AE %s.", ae_name);

                if (strcmp(ae_name, ENROLL_AE) == 0) {
                        enroll_handle(fd);
                } else if (strcmp(ae_name, MGMT_AE) == 0) {
                        ribmgr_flow_arr(fd, qs);
                } else if (strcmp(ae_name, DT_AE) == 0) {
                        fmgr_nm1_flow_arr(fd, qs);
                } else {
                        log_dbg("Flow allocation request for unknown AE %s.",
                                ae_name);
                        if (flow_alloc_resp(fd, -1))
                                log_warn("Failed to reply to flow allocation.");
                        flow_dealloc(fd);
                }

                free(ae_name);
        }

        return (void *) 0;
}

/*
 * Boots the IPCP off information in the rib.
 * Common function after bootstrap or enroll.
 * Call under ipcpi.state_lock
 */
static int boot_components(void)
{
        char buf[256];
        ssize_t len;
        enum pol_addr_auth pa;

        len = rib_read(DIF_PATH, &buf, 256);
        if (len < 0) {
                log_err("Failed to read DIF name: %ld.", len);
                return -1;
        }

        ipcpi.dif_name = strdup(buf);
        if (ipcpi.dif_name == NULL) {
                log_err("Failed to set DIF name.");
                return -1;
        }

        if (rib_add(MEMBERS_PATH, ipcpi.name)) {
                log_warn("Failed to add name to " MEMBERS_PATH);
                return -1;
        }

        log_dbg("Starting components.");

        if (rib_read(BOOT_PATH "/addr_auth/type", &pa, sizeof(pa))
            != sizeof(pa)) {
                log_err("Failed to read policy for address authority.");
                return -1;
        }

        normal.auth = addr_auth_create(pa);
        if (normal.auth == NULL) {
                log_err("Failed to init address authority.");
                return -1;
        }

        ipcpi.address = normal.auth->address();
        if (ipcpi.address == 0) {
                log_err("Failed to get a valid address.");
                addr_auth_destroy(normal.auth);
                return -1;
        }

        log_dbg("IPCP got address %lu.", ipcpi.address);

        log_dbg("Starting ribmgr.");

        if (ribmgr_init()) {
                log_err("Failed to initialize RIB manager.");
                addr_auth_destroy(normal.auth);
                return -1;
        }

        if (dir_init()) {
                log_err("Failed to initialize directory.");
                ribmgr_fini();
                addr_auth_destroy(normal.auth);
                return -1;
        }

        log_dbg("Ribmgr started.");

        if (fmgr_init()) {
                dir_fini();
                ribmgr_fini();
                addr_auth_destroy(normal.auth);
                log_err("Failed to start flow manager.");
                return -1;
        }

        if (frct_init()) {
                fmgr_fini();
                dir_fini();
                ribmgr_fini();
                addr_auth_destroy(normal.auth);
                log_err("Failed to initialize FRCT.");
                return -1;
        }

        ipcp_set_state(IPCP_OPERATIONAL);

        if (pthread_create(&normal.acceptor, NULL, flow_acceptor, NULL)) {
                ipcp_set_state(IPCP_INIT);
                fmgr_fini();
                dir_fini();
                ribmgr_fini();
                addr_auth_destroy(normal.auth);
                log_err("Failed to create acceptor thread.");
                return -1;
        }

        return 0;
}

void shutdown_components(void)
{
        pthread_cancel(normal.acceptor);
        pthread_join(normal.acceptor, NULL);

        frct_fini();

        fmgr_fini();

        dir_fini();

        ribmgr_fini();

        addr_auth_destroy(normal.auth);
}

static int normal_ipcp_enroll(char * dst_name)
{
        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("IPCP in wrong state.");
                return -1; /* -ENOTINIT */
        }

        if (rib_add(RIB_ROOT, MEMBERS_NAME)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("Failed to create members.");
                return -1;
        }

        /* Get boot state from peer */
        if (enroll_boot(dst_name)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("Failed to boot IPCP components.");
                return -1;
        }

        if (boot_components()) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("Failed to boot IPCP components.");
                return -1;
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        log_dbg("Enrolled with %s.", dst_name);

        return 0;
}

const struct ros {
        char * parent;
        char * child;
} ros[] = {
        /* GENERAL IPCP INFO */
        {RIB_ROOT, DIF_NAME},
        /* BOOT INFO */
        {RIB_ROOT, BOOT_NAME},
        /* OTHER RIB STRUCTURES */
        {RIB_ROOT, MEMBERS_NAME},
        /* DT COMPONENT */
        {BOOT_PATH, "dt"},

        {BOOT_PATH "/dt", "gam"},
        {BOOT_PATH "/dt/gam", "type"},
        {BOOT_PATH "/dt/gam", "cacep"},
        {BOOT_PATH "/dt", "const"},
        {BOOT_PATH "/dt/const", "addr_size"},
        {BOOT_PATH "/dt/const", "cep_id_size"},
        {BOOT_PATH "/dt/const", "pdu_length_size"},
        {BOOT_PATH "/dt/const", "seqno_size"},
        {BOOT_PATH "/dt/const", "has_ttl"},
        {BOOT_PATH "/dt/const", "has_chk"},
        {BOOT_PATH "/dt/const", "min_pdu_size"},
        {BOOT_PATH "/dt/const", "max_pdu_size"},

        /* RIB MGR COMPONENT */
        {BOOT_PATH, "rm"},

        {BOOT_PATH "/rm","gam"},
        {BOOT_PATH "/rm/gam", "type"},
        {BOOT_PATH "/rm/gam", "cacep"},

        /* ADDR AUTH COMPONENT */
        {BOOT_PATH, "addr_auth"},
        {BOOT_PATH "/addr_auth", "type"},
        {NULL, NULL}
};

int normal_rib_init(void)
{
        struct ros * r;

        for (r = (struct ros *) ros; r->parent; ++r) {
                if (rib_add(r->parent, r->child)) {
                        log_err("Failed to create %s/%s",
                                r->parent, r->child);
                        return -1;
                }
        }

        return 0;
}

static int normal_ipcp_bootstrap(struct dif_config * conf)
{
        /* FIXME: get CACEP policies from conf */
        enum pol_cacep pol = NO_AUTH;

        (void) pol;

        if (conf == NULL || conf->type != THIS_TYPE) {
                log_err("Bad DIF configuration.");
                return -EINVAL;
        }

        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("IPCP in wrong state.");
                return -1; /* -ENOTINIT */
        }

        if (normal_rib_init()) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("Failed to write initial structure to the RIB.");
                return -1;
        }

        if (rib_write(DIF_PATH,
                      conf->dif_name,
                      strlen(conf->dif_name) + 1) ||
            rib_write(BOOT_PATH "/dt/const/addr_size",
                      &conf->addr_size,
                      sizeof(conf->addr_size)) ||
            rib_write(BOOT_PATH "/dt/const/cep_id_size",
                      &conf->cep_id_size,
                      sizeof(conf->cep_id_size)) ||
            rib_write(BOOT_PATH "/dt/const/seqno_size",
                      &conf->seqno_size,
                      sizeof(conf->seqno_size)) ||
            rib_write(BOOT_PATH "/dt/const/has_ttl",
                      &conf->has_ttl,
                      sizeof(conf->has_ttl)) ||
            rib_write(BOOT_PATH "/dt/const/has_chk",
                      &conf->has_chk,
                      sizeof(conf->has_chk)) ||
            rib_write(BOOT_PATH "/dt/const/min_pdu_size",
                      &conf->min_pdu_size,
                      sizeof(conf->min_pdu_size)) ||
            rib_write(BOOT_PATH "/dt/const/max_pdu_size",
                      &conf->max_pdu_size,
                      sizeof(conf->max_pdu_size)) ||
            rib_write(BOOT_PATH "/dt/gam/type",
                      &conf->dt_gam_type,
                      sizeof(conf->dt_gam_type)) ||
            rib_write(BOOT_PATH "/rm/gam/type",
                      &conf->rm_gam_type,
                      sizeof(conf->rm_gam_type)) ||
            rib_write(BOOT_PATH "/rm/gam/cacep",
                      &pol,
                      sizeof(pol)) ||
            rib_write(BOOT_PATH "/dt/gam/cacep",
                      &pol,
                      sizeof(pol)) ||
            rib_write(BOOT_PATH "/addr_auth/type",
                      &conf->addr_auth_type,
                      sizeof(conf->addr_auth_type))) {
                log_err("Failed to write boot info to RIB.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        if (boot_components()) {
                log_err("Failed to boot IPCP components.");
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        log_dbg("Bootstrapped in DIF %s.", conf->dif_name);

        return 0;
}

static struct ipcp_ops normal_ops = {
        .ipcp_bootstrap       = normal_ipcp_bootstrap,
        .ipcp_enroll          = normal_ipcp_enroll,
        .ipcp_name_reg        = dir_name_reg,
        .ipcp_name_unreg      = dir_name_unreg,
        .ipcp_name_query      = dir_name_query,
        .ipcp_flow_alloc      = NULL, /* fmgr_np1_alloc, */
        .ipcp_flow_alloc_resp = NULL, /* fmgr_np1_alloc_resp, */
        .ipcp_flow_dealloc    = NULL, /* fmgr_np1_dealloc */
};

int main(int    argc,
         char * argv[])
{
        struct sigaction sig_act;
        sigset_t         sigset;

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

        if (ipcp_init(argc, argv, THIS_TYPE, &normal_ops) < 0) {
                log_err("Failed to create instance.");
                ipcp_create_r(getpid(), -1);
                exit(EXIT_FAILURE);
        }

        if (irm_bind_api(getpid(), ipcpi.name)) {
                log_err("Failed to bind AP name.");
                ipcp_create_r(getpid(), -1);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (rib_init()) {
                log_err("Failed to initialize RIB.");
                ipcp_create_r(getpid(), -1);
                irm_unbind_api(getpid(), ipcpi.name);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                ipcp_create_r(getpid(), -1);
                rib_fini();
                irm_unbind_api(getpid(), ipcpi.name);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        if (ipcp_create_r(getpid(), 0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                ipcp_shutdown();
                rib_fini();
                irm_unbind_api(getpid(), ipcpi.name);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN)
                shutdown_components();

        rib_fini();

        irm_unbind_api(getpid(), ipcpi.name);

        ipcp_fini();

        exit(EXIT_SUCCESS);
}
