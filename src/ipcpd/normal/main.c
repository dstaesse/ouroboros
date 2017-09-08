/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Normal IPC Process
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

#define _POSIX_C_SOURCE 200809L

#include "config.h"

#define OUROBOROS_PREFIX "normal-ipcp"

#include <ouroboros/endian.h>
#include <ouroboros/logs.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/irm.h>
#include <ouroboros/rib.h>
#include <ouroboros/hash.h>
#include <ouroboros/errno.h>

#include "addr_auth.h"
#include "connmgr.h"
#include "dir.h"
#include "enroll.h"
#include "fa.h"
#include "dt.h"
#include "ipcp.h"
#include "ribconfig.h"
#include "ribmgr.h"

#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#define THIS_TYPE IPCP_NORMAL

static int initialize_components(const struct ipcp_config * conf)
{
        if (rib_init()) {
                log_err("Failed to initialize RIB.");
                goto fail_rib_init;
        }

        ipcpi.dif_name = strdup(conf->dif_info.dif_name);
        if (ipcpi.dif_name == NULL) {
                log_err("Failed to set DIF name.");
                goto fail_dif_name;
        }

        ipcpi.dir_hash_algo = conf->dif_info.dir_hash_algo;

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

        if (ribmgr_init()) {
                log_err("Failed to initialize RIB manager.");
                goto fail_ribmgr;
        }

        if (dt_init(conf->routing_type,
                    conf->addr_size,
                    conf->fd_size,
                    conf->has_ttl)) {
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
        ribmgr_fini();
 fail_ribmgr:
        addr_auth_fini();
 fail_addr_auth:
        free(ipcpi.dif_name);
 fail_dif_name:
        rib_fini();
 fail_rib_init:
        return -1;
}

static void finalize_components(void)
{
        dir_fini();

        fa_fini();

        dt_fini();

        ribmgr_fini();

        addr_auth_fini();

        free(ipcpi.dif_name);

        rib_fini();
}

static int start_components(void)
{
        assert(ipcp_get_state() == IPCP_INIT);

        ipcp_set_state(IPCP_OPERATIONAL);

        if (ribmgr_start()) {
                log_err("Failed to start RIB manager.");
                goto fail_ribmgr_start;
        }

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
        ribmgr_stop();
 fail_ribmgr_start:
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

        ribmgr_stop();

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

static int enroll_components(uint64_t peer)
{
        if (dir_enroll(peer)) {
                log_err("Failed to enroll directory.");
                return -1;
        }

        return 0;
}

static int normal_ipcp_enroll(const char *      dst,
                              struct dif_info * info)
{
        struct conn er_conn;
        struct conn dt_conn;

        if (connmgr_alloc(AEID_ENROLL, dst, NULL, &er_conn)) {
                log_err("Failed to get connection.");
                goto fail_er_flow;
        }

        /* Get boot state from peer. */
        if (enroll_boot(&er_conn)) {
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

        if (connmgr_alloc(AEID_DT, dst, NULL, &dt_conn)) {
                log_err("Failed to create a data transfer flow.");
                goto fail_dt_flow;
        }

        if (start_components()) {
                log_err("Failed to start components.");
                goto fail_start_comp;
        }

        if (enroll_components(dt_conn.conn_info.addr)) {
                enroll_done(&er_conn, -1);
                log_err("Failed to enroll components.");
                goto fail_enroll_comp;
        }

        if (enroll_done(&er_conn, 0))
                log_warn("Failed to confirm enrollment with peer.");

        if (connmgr_dealloc(AEID_DT, &dt_conn))
                log_warn("Failed to deallocate data transfer flow.");

        if (connmgr_dealloc(AEID_ENROLL, &er_conn))
                log_warn("Failed to deallocate enrollment flow.");

        log_info("Enrolled with %s.", dst);

        info->dir_hash_algo = ipcpi.dir_hash_algo;
        strcpy(info->dif_name, ipcpi.dif_name);

        return 0;

 fail_enroll_comp:
        stop_components();
 fail_start_comp:
        connmgr_dealloc(AEID_DT, &dt_conn);
 fail_dt_flow:
        dt_stop();
 fail_dt_start:
        finalize_components();
 fail_enroll_boot:
        connmgr_dealloc(AEID_ENROLL, &er_conn);
 fail_er_flow:
        return -1;
}

static int normal_ipcp_bootstrap(const struct ipcp_config * conf)
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

        log_dbg("Bootstrapped in DIF %s.", conf->dif_info.dif_name);

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

static int normal_ipcp_query(const uint8_t * dst)
{
        return dir_query(dst) ? 0 : -1;
}

static struct ipcp_ops normal_ops = {
        .ipcp_bootstrap       = normal_ipcp_bootstrap,
        .ipcp_enroll          = normal_ipcp_enroll,
        .ipcp_connect         = connmgr_ipcp_connect,
        .ipcp_disconnect      = connmgr_ipcp_disconnect,
        .ipcp_reg             = dir_reg,
        .ipcp_unreg           = dir_unreg,
        .ipcp_query           = normal_ipcp_query,
        .ipcp_flow_alloc      = fa_alloc,
        .ipcp_flow_alloc_resp = fa_alloc_resp,
        .ipcp_flow_dealloc    = fa_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, THIS_TYPE, &normal_ops) < 0) {
                log_err("Failed to init IPCP.");
                goto fail_init;
        }

        if (irm_bind_api(getpid(), ipcpi.name)) {
                log_err("Failed to bind AP name.");
                goto fail_bind_api;
        }

        /* These components must be init at creation. */
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

        if (ipcp_create_r(getpid(), 0)) {
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

        irm_unbind_api(getpid(), ipcpi.name);

        ipcp_fini();

        exit(EXIT_SUCCESS);

 fail_create_r:
        ipcp_shutdown();
 fail_boot:
        enroll_fini();
 fail_enroll_init:
        connmgr_fini();
 fail_connmgr_init:
        irm_unbind_api(getpid(), ipcpi.name);
 fail_bind_api:
       ipcp_fini();
 fail_init:
        ipcp_create_r(getpid(), -1);
        exit(EXIT_FAILURE);
}
