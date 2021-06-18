/*
 * Ouroboros - Copyright (C) 2016 - 2021
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
#include <ouroboros/hash.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/notifier.h>
#include <ouroboros/rib.h>
#include <ouroboros/time_utils.h>

#include "common/connmgr.h"
#include "common/enroll.h"
#include "addr_auth.h"
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
        ipcpi.layer_name = strdup(conf->layer_info.layer_name);
        if (ipcpi.layer_name == NULL) {
                log_err("Failed to set layer name.");
                goto fail_layer_name;
        }

        ipcpi.dir_hash_algo = conf->layer_info.dir_hash_algo;

        assert(ipcp_dir_hash_len() != 0);

        if (addr_auth_init(conf->addr_auth_type,
                           &conf->addr_size)) {
                log_err("Failed to init address authority.");
                goto fail_addr_auth;
        }

        ipcpi.dt_addr = addr_auth_address();
        if (ipcpi.dt_addr == 0) {
                log_err("Failed to get a valid address.");
                goto fail_addr_auth;
        }

        log_dbg("IPCP got address %" PRIu64 ".", ipcpi.dt_addr);

        if (ca_init(conf->cong_avoid)) {
                log_err("Failed to initialize congestion avoidance.");
                goto fail_ca;
        }

        if (dt_init(conf->routing_type,
                    conf->addr_size,
                    conf->eid_size,
                    conf->max_ttl)) {
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
        free(ipcpi.layer_name);
 fail_layer_name:
        return -1;
}

static void finalize_components(void)
{
        dir_fini();

        fa_fini();

        dt_fini();

        ca_fini();

        addr_auth_fini();

        free(ipcpi.layer_name);
}

static int start_components(void)
{
        assert(ipcp_get_state() == IPCP_INIT);

        ipcp_set_state(IPCP_OPERATIONAL);

        if (fa_start()) {
                log_err("Failed to start flow allocator.");
                goto fail_fa_start;
        }

        if (enroll_start()) {
                log_err("Failed to start enrollment.");
                goto fail_enroll_start;
        }

        if (connmgr_start()) {
                log_err("Failed to start AP connection manager.");
                goto fail_connmgr_start;
        }

        return 0;

 fail_connmgr_start:
        enroll_stop();
 fail_enroll_start:
        fa_stop();
 fail_fa_start:
        ipcp_set_state(IPCP_INIT);
        return -1;
}

static void stop_components(void)
{
        assert(ipcp_get_state() == IPCP_OPERATIONAL ||
               ipcp_get_state() == IPCP_SHUTDOWN);

        connmgr_stop();

        enroll_stop();

        fa_stop();

        ipcp_set_state(IPCP_INIT);
}

static int bootstrap_components(void)
{
        if (dir_bootstrap()) {
                log_err("Failed to bootstrap directory.");
                dt_stop();
                return -1;
        }

        return 0;
}

static int unicast_ipcp_enroll(const char *        dst,
                               struct layer_info * info)
{
        struct conn conn;

        if (connmgr_alloc(COMPID_ENROLL, dst, NULL, &conn)) {
                log_err("Failed to get connection.");
                goto fail_er_flow;
        }

        /* Get boot state from peer. */
        if (enroll_boot(&conn)) {
                log_err("Failed to get boot information.");
                goto fail_enroll_boot;
        }

        if (initialize_components(enroll_get_conf())) {
                log_err("Failed to initialize IPCP components.");
                goto fail_enroll_boot;
        }

        if (dt_start()) {
                log_err("Failed to initialize IPCP components.");
                goto fail_dt_start;
        }

        if (start_components()) {
                log_err("Failed to start components.");
                goto fail_start_comp;
        }

        if (enroll_done(&conn, 0))
                log_warn("Failed to confirm enrollment with peer.");

        if (connmgr_dealloc(COMPID_ENROLL, &conn))
                log_warn("Failed to deallocate enrollment flow.");

        log_info("Enrolled with %s.", dst);

        info->dir_hash_algo = ipcpi.dir_hash_algo;
        strcpy(info->layer_name, ipcpi.layer_name);

        return 0;

 fail_start_comp:
        dt_stop();
 fail_dt_start:
        finalize_components();
 fail_enroll_boot:
        connmgr_dealloc(COMPID_ENROLL, &conn);
 fail_er_flow:
        return -1;
}

static int unicast_ipcp_bootstrap(const struct ipcp_config * conf)
{
        assert(conf);
        assert(conf->type == THIS_TYPE);

        enroll_bootstrap(conf);

        if (initialize_components(conf)) {
                log_err("Failed to init IPCP components.");
                goto fail_init;
        }

        if (dt_start()) {
                log_err("Failed to initialize IPCP components.");
                goto fail_dt_start;
        };

        if (start_components()) {
                log_err("Failed to init IPCP components.");
                goto fail_start;
        }

        if (bootstrap_components()) {
                log_err("Failed to bootstrap IPCP components.");
                goto fail_bootstrap;
        }

        log_dbg("Bootstrapped in layer %s.", conf->layer_info.layer_name);

        return 0;

 fail_bootstrap:
        stop_components();
 fail_start:
        dt_stop();
 fail_dt_start:
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

        if (notifier_init()) {
                log_err("Failed to initialize notifier component.");
                goto fail_notifier_init;
        }

        if (connmgr_init()) {
                log_err("Failed to initialize connection manager.");
                goto fail_connmgr_init;
        }

        if (enroll_init()) {
                log_err("Failed to initialize enrollment component.");
                goto fail_enroll_init;
        }

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                goto fail_boot;
        }

        if (ipcp_create_r(0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                goto fail_create_r;
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                dt_stop();
                stop_components();
                finalize_components();
        }

        enroll_fini();

        connmgr_fini();

        notifier_fini();

        ipcp_fini();

        exit(EXIT_SUCCESS);

 fail_create_r:
        ipcp_shutdown();
 fail_boot:
        enroll_fini();
 fail_enroll_init:
        connmgr_fini();
 fail_connmgr_init:
        notifier_fini();
 fail_notifier_init:
       ipcp_fini();
 fail_init:
        ipcp_create_r(-1);
        exit(EXIT_FAILURE);
}
