/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Unicast IPC Process
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
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#define OUROBOROS_PREFIX "unicast-ipcp"
#define THIS_TYPE IPCP_UNICAST

#include <ouroboros/errno.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/notifier.h>
#include <ouroboros/random.h>
#include <ouroboros/rib.h>
#include <ouroboros/time_utils.h>

#include "common/connmgr.h"
#include "common/enroll.h"
#include "addr-auth.h"
#include "ca.h"
#include "dir.h"
#include "dt.h"
#include "fa.h"
#include "ipcp.h"

#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

struct ipcp ipcpi;

static int initialize_components(const struct ipcp_config * conf)
{
        strcpy(ipcpi.layer_name, conf->layer_info.name);
        ipcpi.dir_hash_algo = conf->layer_info.dir_hash_algo;

        assert(ipcp_dir_hash_len() != 0);

        if (addr_auth_init(conf->unicast.addr_auth_type,
                           &conf->unicast.dt.addr_size)) {
                log_err("Failed to init address authority.");
                goto fail_addr_auth;
        }

        ipcpi.dt_addr = addr_auth_address();
        if (ipcpi.dt_addr == 0) {
                log_err("Failed to get a valid address.");
                goto fail_addr_auth;
        }

        log_info("IPCP got address %" PRIu64 ".", ipcpi.dt_addr);

        if (ca_init(conf->unicast.cong_avoid)) {
                log_err("Failed to initialize congestion avoidance.");
                goto fail_ca;
        }

        if (dt_init(conf->unicast.dt)) {
                log_err("Failed to initialize data transfer component.");
                goto fail_dt;
        }

        if (fa_init()) {
                log_err("Failed to initialize flow allocator component.");
                goto fail_fa;
        }

        if (dir_init()) {
                log_err("Failed to initialize directory.");
                goto fail_dir;
        }

        ipcp_set_state(IPCP_INIT);

        return 0;

 fail_dir:
        fa_fini();
 fail_fa:
        dt_fini();
 fail_dt:
        ca_fini();
 fail_ca:
        addr_auth_fini();
 fail_addr_auth:
        return -1;
}

static void finalize_components(void)
{
        dir_fini();

        fa_fini();

        dt_fini();

        ca_fini();

        addr_auth_fini();
}

static int start_components(void)
{
        if (dt_start() < 0) {
                log_err("Failed to start data transfer.");
                goto fail_dt_start;
        }

        if (fa_start() < 0) {
                log_err("Failed to start flow allocator.");
                goto fail_fa_start;
        }

        if (enroll_start() < 0) {
                log_err("Failed to start enrollment.");
                goto fail_enroll_start;
        }

        if (connmgr_start() < 0) {
                log_err("Failed to start AP connection manager.");
                goto fail_connmgr_start;
        }

        return 0;

 fail_connmgr_start:
        enroll_stop();
 fail_enroll_start:
        fa_stop();
 fail_fa_start:
        dt_stop();
 fail_dt_start:
        ipcp_set_state(IPCP_INIT);
        return -1;
}

static void stop_components(void)
{
        connmgr_stop();

        enroll_stop();

        fa_stop();

        dt_stop();

        ipcp_set_state(IPCP_INIT);
}

static int bootstrap_components(void)
{
        if (dir_bootstrap()) {
                log_err("Failed to bootstrap directory.");
                return -1;
        }

        return 0;
}

static int unicast_ipcp_enroll(const char *        dst,
                               struct layer_info * info)
{
        struct conn conn;
        uint8_t     id[ENROLL_ID_LEN];

        if (random_buffer(id, ENROLL_ID_LEN) < 0) {
                log_err("Failed to generate enrollment ID.");
                goto fail_id;
        }

        log_info_id(id, "Requesting enrollment.");

        if (connmgr_alloc(COMPID_ENROLL, dst, NULL, &conn) < 0) {
                log_err_id(id, "Failed to get connection.");
                goto fail_id;
        }

        /* Get boot state from peer. */
        if (enroll_boot(&conn, id) < 0) {
                log_err_id(id, "Failed to get boot information.");
                goto fail_enroll_boot;
        }

        if (initialize_components(enroll_get_conf()) < 0) {
                log_err_id(id, "Failed to initialize components.");
                goto fail_enroll_boot;
        }

        if (start_components() < 0) {
                log_err_id(id, "Failed to start components.");
                goto fail_start_comp;
        }

        if (enroll_ack(&conn, id, 0) < 0)
                log_err_id(id, "Failed to confirm enrollment.");

        if (connmgr_dealloc(COMPID_ENROLL, &conn) < 0)
                log_warn_id(id, "Failed to dealloc enrollment flow.");

        log_info_id(id, "Enrolled with %s.", dst);

        info->dir_hash_algo = ipcpi.dir_hash_algo;
        strcpy(info->name, ipcpi.layer_name);

        return 0;

 fail_start_comp:
        finalize_components();
 fail_enroll_boot:
        connmgr_dealloc(COMPID_ENROLL, &conn);
 fail_id:
        return -1;
}

static int unicast_ipcp_bootstrap(const struct ipcp_config * conf)
{
        assert(conf);
        assert(conf->type == THIS_TYPE);

        enroll_bootstrap(conf);

        if (initialize_components(conf) < 0) {
                log_err("Failed to init IPCP components.");
                goto fail_init;
        }

        if (start_components() < 0) {
                log_err("Failed to init IPCP components.");
                goto fail_start;
        }

        if (bootstrap_components() < 0) {
                log_err("Failed to bootstrap IPCP components.");
                goto fail_bootstrap;
        }

        return 0;

 fail_bootstrap:
        stop_components();
 fail_start:
        finalize_components();
 fail_init:
        return -1;
}

static int unicast_ipcp_query(const uint8_t * dst)
{
        return dir_query(dst) ? 0 : -1;
}

static struct ipcp_ops unicast_ops = {
        .ipcp_bootstrap       = unicast_ipcp_bootstrap,
        .ipcp_enroll          = unicast_ipcp_enroll,
        .ipcp_connect         = connmgr_ipcp_connect,
        .ipcp_disconnect      = connmgr_ipcp_disconnect,
        .ipcp_reg             = dir_reg,
        .ipcp_unreg           = dir_unreg,
        .ipcp_query           = unicast_ipcp_query,
        .ipcp_flow_alloc      = fa_alloc,
        .ipcp_flow_join       = NULL,
        .ipcp_flow_alloc_resp = fa_alloc_resp,
        .ipcp_flow_dealloc    = fa_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, &unicast_ops, THIS_TYPE) < 0) {
                log_err("Failed to init IPCP.");
                goto fail_init;
        }

        if (notifier_init() < 0) {
                log_err("Failed to initialize notifier component.");
                goto fail_notifier_init;
        }

        if (connmgr_init() < 0) {
                log_err("Failed to initialize connection manager.");
                goto fail_connmgr_init;
        }

        if (enroll_init() < 0) {
                log_err("Failed to initialize enrollment component.");
                goto fail_enroll_init;
        }

        if (ipcp_start() < 0) {
                log_err("Failed to start IPCP.");
                goto fail_start;
        }

        ipcp_sigwait();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                stop_components();
                finalize_components();
        }

        ipcp_stop();

        enroll_fini();

        connmgr_fini();

        notifier_fini();

        ipcp_fini();

        exit(EXIT_SUCCESS);

 fail_start:
        enroll_fini();
 fail_enroll_init:
        connmgr_fini();
 fail_connmgr_init:
        notifier_fini();
 fail_notifier_init:
        ipcp_fini();
 fail_init:
        exit(EXIT_FAILURE);
}
