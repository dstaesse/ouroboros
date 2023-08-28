/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Broadcast IPC Process
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

#define OUROBOROS_PREFIX "broadcast-ipcp"
#define THIS_TYPE IPCP_BROADCAST

#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/notifier.h>
#include <ouroboros/random.h>
#include <ouroboros/rib.h>
#include <ouroboros/time_utils.h>

#include "common/connmgr.h"
#include "common/enroll.h"
#include "dt.h"
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
        strcpy(ipcpi.layer_name, conf->layer_info.layer_name);
        ipcpi.dir_hash_algo = conf->layer_info.dir_hash_algo;

        assert(ipcp_dir_hash_len() != 0);

        if (dt_init() < 0) {
                log_err("Failed to initialize forwarding component.");
                return -1;
        }

        ipcp_set_state(IPCP_INIT);

        return 0;
}

static void finalize_components(void)
{
        dt_fini();
}

static int start_components(void)
{
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
        ipcp_set_state(IPCP_INIT);
        return -1;
}

static void stop_components(void)
{
        connmgr_stop();

        enroll_stop();
}

static int broadcast_ipcp_enroll(const char *        dst,
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
        strcpy(info->layer_name, ipcpi.layer_name);

        return 0;

 fail_start_comp:
        finalize_components();
 fail_enroll_boot:
        connmgr_dealloc(COMPID_ENROLL, &conn);
 fail_id:
        return -1;
}

static int broadcast_ipcp_bootstrap(const struct ipcp_config * conf)
{
        assert(conf);
        assert(conf->type == THIS_TYPE);
        ((struct ipcp_config *) conf)->layer_info.dir_hash_algo = HASH_SHA3_256;

        enroll_bootstrap(conf);

        if (initialize_components(conf)) {
                log_err("Failed to init IPCP components.");
                goto fail_init;
        }

        if (start_components()) {
                log_err("Failed to init IPCP components.");
                goto fail_start;
        }

        log_dbg("Bootstrapped in layer %s.", conf->layer_info.layer_name);

        return 0;

 fail_start:
        finalize_components();
 fail_init:
        return -1;
}

static int name_check(const uint8_t * dst)
{
        uint8_t * buf;
        size_t    len;
        int       ret;

        len = hash_len(ipcpi.dir_hash_algo);
        buf =  malloc(len);
        if (buf == NULL)
                return -ENOMEM;

        str_hash(ipcpi.dir_hash_algo, buf, ipcpi.layer_name);

        ret = memcmp(buf, dst, len);

        free(buf);

        return ret;
}

static int broadcast_ipcp_join(int             fd,
                               const uint8_t * dst,
                               qosspec_t       qs)
{
        struct conn conn;
        time_t      mpl = IPCP_BROADCAST_MPL;

        (void) qs;

        memset(&conn, 0, sizeof(conn));

        conn.flow_info.fd = fd;

        if (name_check(dst) != 0)
                return -1;

        notifier_event(NOTIFY_DT_CONN_ADD, &conn);

        ipcp_flow_alloc_reply(fd, 0, mpl, NULL, 0);

        return 0;
}

int broadcast_ipcp_dealloc(int fd)
{
        struct conn conn;

        memset(&conn, 0, sizeof(conn));

        conn.flow_info.fd = fd;

        notifier_event(NOTIFY_DT_CONN_DEL, &conn);

        flow_dealloc(fd);

        return 0;
}

static struct ipcp_ops broadcast_ops = {
        .ipcp_bootstrap       = broadcast_ipcp_bootstrap,
        .ipcp_enroll          = broadcast_ipcp_enroll,
        .ipcp_connect         = connmgr_ipcp_connect,
        .ipcp_disconnect      = connmgr_ipcp_disconnect,
        .ipcp_reg             = NULL,
        .ipcp_unreg           = NULL,
        .ipcp_query           = NULL,
        .ipcp_flow_alloc      = NULL,
        .ipcp_flow_join       = broadcast_ipcp_join,
        .ipcp_flow_alloc_resp = NULL,
        .ipcp_flow_dealloc    = broadcast_ipcp_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, &broadcast_ops, THIS_TYPE) < 0) {
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

        if (ipcp_start() < 0) {
                log_err("Failed to boot IPCP.");
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
