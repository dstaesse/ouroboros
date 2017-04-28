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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "normal-ipcp"

#include <ouroboros/config.h>
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

static int boot_components(void)
{
        char buf[256];
        ssize_t len;
        enum pol_addr_auth pa;
        char path[RIB_MAX_PATH_LEN + 1];

        len = rib_read(BOOT_PATH "/general/dif_name", buf, 256);
        if (len < 0) {
                log_err("Failed to read DIF name: %zd.", len);
                return -1;
        }

        ipcpi.dif_name = strdup(buf);
        if (ipcpi.dif_name == NULL) {
                log_err("Failed to set DIF name.");
                return -1;
        }

        len = rib_read(BOOT_PATH "/general/dir_hash_algo",
                       &ipcpi.dir_hash_algo, sizeof(ipcpi.dir_hash_algo));
        if (len < 0) {
                log_err("Failed to read hash length: %zd.", len);
                goto fail_name;
        }

        ipcpi.dir_hash_algo = ntoh32(ipcpi.dir_hash_algo);

        assert(ipcp_dir_hash_len() != 0);

        if (rib_add(MEMBERS_PATH, ipcpi.name)) {
                log_err("Failed to add name to " MEMBERS_PATH);
                goto fail_name;
        }

        log_dbg("Starting components.");

        if (rib_read(BOOT_PATH "/addr_auth/type", &pa, sizeof(pa))
            != sizeof(pa)) {
                log_err("Failed to read policy for address authority.");
                goto fail_name;
        }

        if (addr_auth_init(pa)) {
                log_err("Failed to init address authority.");
                goto fail_name;
        }

        ipcpi.dt_addr = addr_auth_address();
        if (ipcpi.dt_addr == 0) {
                log_err("Failed to get a valid address.");
                goto fail_addr_auth;
        }

        path[0] = '\0';
        rib_path_append(rib_path_append(path, MEMBERS_NAME), ipcpi.name);
        if (rib_write(path, &ipcpi.dt_addr, sizeof(&ipcpi.dt_addr))) {
                log_err("Failed to write address to member object.");
                goto fail_addr_auth;
        }

        log_dbg("IPCP got address %" PRIu64 ".", ipcpi.dt_addr);

        log_dbg("Starting ribmgr.");

        if (dir_init()) {
                log_err("Failed to initialize directory.");
                goto fail_addr_auth;
        }

        if (ribmgr_init()) {
                log_err("Failed to initialize RIB manager.");
                goto fail_dir;
        }

        log_dbg("Ribmgr started.");

        if (frct_init()) {
                log_err("Failed to initialize FRCT.");
                goto fail_ribmgr;
        }

        if (fa_init()) {
                log_err("Failed to initialize flow allocator ae.");
                goto fail_frct;
        }

        if (dt_init()) {
                log_err("Failed to initialize data transfer ae.");
                goto fail_fa;
        }

        if (fa_start()) {
                log_err("Failed to start flow allocator.");
                goto fail_dt;
        }

        if (dt_start()) {
                log_err("Failed to start data transfer ae.");
                goto fail_fa_start;
        }

        if (enroll_start()) {
                log_err("Failed to start enroll.");
                goto fail_dt_start;
        }

        ipcp_set_state(IPCP_OPERATIONAL);

        if (connmgr_start()) {
                log_err("Failed to start AP connection manager.");
                goto fail_enroll;
        }

        return 0;

 fail_enroll:
        ipcp_set_state(IPCP_INIT);
        enroll_stop();
 fail_dt_start:
        dt_stop();
 fail_fa_start:
        fa_stop();
 fail_dt:
        dt_fini();
 fail_fa:
        fa_fini();
 fail_frct:
        frct_fini();
 fail_ribmgr:
        ribmgr_fini();
 fail_dir:
        dir_fini();
 fail_addr_auth:
        addr_auth_fini();
 fail_name:
        free(ipcpi.dif_name);

        return -1;
}

void shutdown_components(void)
{
        connmgr_stop();

        enroll_stop();

        dt_stop();

        fa_stop();

        dt_fini();

        fa_fini();

        frct_fini();

        ribmgr_fini();

        dir_fini();

        addr_auth_fini();

        free(ipcpi.dif_name);
}

static int normal_ipcp_enroll(const char *      dst,
                              struct dif_info * info)
{
        if (rib_add(RIB_ROOT, MEMBERS_NAME)) {
                log_err("Failed to create members.");
                return -1;
        }

        /* Get boot state from peer */
        if (enroll_boot(dst)) {
                log_err("Failed to boot IPCP components.");
                return -1;
        }

        if (boot_components()) {
                log_err("Failed to boot IPCP components.");
                return -1;
        }

        log_dbg("Enrolled with " HASH_FMT, HASH_VAL(dst));

        info->algo = ipcpi.dir_hash_algo;

        strcpy(info->dif_name, ipcpi.dif_name);

        return 0;
}

const struct ros {
        char * parent;
        char * child;
} ros[] = {
        /* BOOT INFO */
        {RIB_ROOT, BOOT_NAME},
        /* OTHER RIB STRUCTURES */
        {RIB_ROOT, MEMBERS_NAME},

        /* GENERAL IPCP INFO */
        {BOOT_PATH, "general"},

        {BOOT_PATH "/general", "dif_name"},
        {BOOT_PATH "/general", "dir_hash_algo"},

        /* DT COMPONENT */
        {BOOT_PATH, "dt"},

        {BOOT_PATH "/dt", "gam"},
        {BOOT_PATH "/dt/gam", "type"},
        {BOOT_PATH "/dt/gam", "cacep"},
        {BOOT_PATH "/dt", "const"},
        {BOOT_PATH "/dt/const", "addr_size"},
        {BOOT_PATH "/dt/const", "cep_id_size"},
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

static int normal_ipcp_bootstrap(const struct ipcp_config * conf)
{
        uint32_t hash_algo;

        assert(conf);
        assert(conf->type == THIS_TYPE);

        hash_algo = hton32((uint32_t) conf->dir_hash_algo);

        assert(ntoh32(hash_algo) != 0);

        if (normal_rib_init()) {
                log_err("Failed to write initial structure to the RIB.");
                return -1;
        }

        if (rib_write(BOOT_PATH "/general/dif_name",
                      conf->dif_name,
                      strlen(conf->dif_name) + 1) ||
            rib_write(BOOT_PATH "/general/dir_hash_algo",
                      &hash_algo,
                      sizeof(hash_algo)) ||
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
            rib_write(BOOT_PATH "/addr_auth/type",
                      &conf->addr_auth_type,
                      sizeof(conf->addr_auth_type))) {
                log_err("Failed to write boot info to RIB.");
                return -1;
        }

        if (boot_components()) {
                log_err("Failed to boot IPCP components.");
                return -1;
        }

        log_dbg("Bootstrapped in DIF %s.", conf->dif_name);

        return 0;
}

static struct ipcp_ops normal_ops = {
        .ipcp_bootstrap       = normal_ipcp_bootstrap,
        .ipcp_enroll          = normal_ipcp_enroll,
        .ipcp_reg             = dir_reg,
        .ipcp_unreg           = dir_unreg,
        .ipcp_query           = dir_query,
        .ipcp_flow_alloc      = fa_alloc,
        .ipcp_flow_alloc_resp = fa_alloc_resp,
        .ipcp_flow_dealloc    = fa_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, THIS_TYPE, &normal_ops) < 0) {
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

        if (connmgr_init()) {
                log_err("Failed to initialize connection manager.");
                ipcp_create_r(getpid(), -1);
                rib_fini();
                irm_unbind_api(getpid(), ipcpi.name);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (enroll_init()) {
                log_err("Failed to initialize enroll component.");
                ipcp_create_r(getpid(), -1);
                connmgr_fini();
                rib_fini();
                irm_unbind_api(getpid(), ipcpi.name);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }


        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                ipcp_create_r(getpid(), -1);
                enroll_fini();
                connmgr_fini();
                rib_fini();
                irm_unbind_api(getpid(), ipcpi.name);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (ipcp_create_r(getpid(), 0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                ipcp_shutdown();
                enroll_fini();
                connmgr_fini();
                rib_fini();
                irm_unbind_api(getpid(), ipcpi.name);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN)
                shutdown_components();

        enroll_fini();

        connmgr_fini();

        rib_fini();

        irm_unbind_api(getpid(), ipcpi.name);

        ipcp_fini();

        exit(EXIT_SUCCESS);
}
