/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Data Transfer AE
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

#define OUROBOROS_PREFIX "dt-ae"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/rib.h>
#include <ouroboros/dev.h>

#include "dt.h"
#include "connmgr.h"
#include "ipcp.h"
#include "dt_pci.h"
#include "pff.h"
#include "neighbors.h"
#include "gam.h"
#include "routing.h"
#include "sdu_sched.h"
#include "frct.h"
#include "ae.h"
#include "ribconfig.h"
#include "fa.h"

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

struct {
        struct sdu_sched * sdu_sched;

        struct pff *       pff[QOS_CUBE_MAX];
        struct routing_i * routing[QOS_CUBE_MAX];

        struct gam *       gam;
        struct nbs *       nbs;
        struct ae *        ae;

        struct nb_notifier nb_notifier;
} dt;

static int dt_neighbor_event(enum nb_event event,
                             struct conn   conn)
{
        /* We are only interested in neighbors being added and removed. */
        switch (event) {
        case NEIGHBOR_ADDED:
                sdu_sched_add(dt.sdu_sched, conn.flow_info.fd);
                log_dbg("Added fd %d to SDU scheduler.", conn.flow_info.fd);
                break;
        case NEIGHBOR_REMOVED:
                sdu_sched_del(dt.sdu_sched, conn.flow_info.fd);
                log_dbg("Removed fd %d from SDU scheduler.", conn.flow_info.fd);
                break;
        default:
                break;
        }

        return 0;
}

static int sdu_handler(int                  fd,
                       qoscube_t            qc,
                       struct shm_du_buff * sdb)
{
        struct dt_pci dt_pci;

        memset(&dt_pci, 0, sizeof(dt_pci));

        dt_pci_des(sdb, &dt_pci);

        if (dt_pci.dst_addr != ipcpi.dt_addr) {
                if (dt_pci.ttl == 0) {
                        log_dbg("TTL was zero.");
                        ipcp_sdb_release(sdb);
                        return 0;
                }

                fd = pff_nhop(dt.pff[qc], dt_pci.dst_addr);
                if (fd < 0) {
                        log_err("No next hop for %" PRIu64, dt_pci.dst_addr);
                        ipcp_sdb_release(sdb);
                        return -1;
                }

                if (ipcp_flow_write(fd, sdb)) {
                        log_err("Failed to write SDU to fd %d.", fd);
                        ipcp_sdb_release(sdb);
                        return -1;
                }
        } else {
                dt_pci_shrink(sdb);

                switch (dt_pci.pdu_type) {
                case PDU_TYPE_FRCT:
                        if (frct_post_sdu(sdb)) {
                                ipcp_sdb_release(sdb);
                                return -1;
                        }
                        break;
                case PDU_TYPE_FA:
                        if (fa_post_sdu(sdb)) {
                                ipcp_sdb_release(sdb);
                                return -1;
                        }
                        break;
                default:
                        log_err("Unknown PDU type received.");
                        ipcp_sdb_release(sdb);
                        return -1;
                }
        }

        return 0;
}

int dt_init(void)
{
        int              i;
        int              j;
        struct conn_info info;

        if (dt_pci_init()) {
                log_err("Failed to init shm dt_pci.");
                return -1;
        }

        memset(&info, 0, sizeof(info));

        strcpy(info.ae_name, DT_AE);
        strcpy(info.protocol, FRCT_PROTO);
        info.pref_version = 1;
        info.pref_syntax = PROTO_FIXED;
        info.addr = ipcpi.dt_addr;

        dt.ae = connmgr_ae_create(info);
        if (dt.ae == NULL) {
                log_err("Failed to create AE struct.");
                return -1;
        }

        dt.nbs = nbs_create();
        if (dt.nbs == NULL) {
                log_err("Failed to create neighbors struct.");
                goto fail_connmgr;
        }

        dt.nb_notifier.notify_call = dt_neighbor_event;
        if (nbs_reg_notifier(dt.nbs, &dt.nb_notifier)) {
                log_err("Failed to register notifier.");
                goto fail_nbs;
        }

        if (routing_init(dt.nbs)) {
                log_err("Failed to init routing.");
                goto fail_nbs_notifier;
        }

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                dt.pff[i] = pff_create();
                if (dt.pff[i] == NULL) {
                        for (j = 0; j < i; ++j)
                                pff_destroy(dt.pff[j]);
                        goto fail_routing;
                }
        }

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                dt.routing[i] = routing_i_create(dt.pff[i]);
                if (dt.routing[i] == NULL) {
                        for (j = 0; j < i; ++j)
                                routing_i_destroy(dt.routing[j]);
                        goto fail_pff;
                }
        }

        return 0;
 fail_pff:
        for (i = 0; i < QOS_CUBE_MAX; ++i)
                pff_destroy(dt.pff[i]);
 fail_routing:
        routing_fini();
 fail_nbs_notifier:
        nbs_unreg_notifier(dt.nbs, &dt.nb_notifier);
 fail_nbs:
        nbs_destroy(dt.nbs);
 fail_connmgr:
        connmgr_ae_destroy(dt.ae);
        return -1;
}

void dt_fini(void)
{
        int i;

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                routing_i_destroy(dt.routing[i]);

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                pff_destroy(dt.pff[i]);

        routing_fini();

        nbs_unreg_notifier(dt.nbs, &dt.nb_notifier);

        nbs_destroy(dt.nbs);

        connmgr_ae_destroy(dt.ae);
}

int dt_start(void)
{
        enum pol_gam pg;

        if (rib_read(BOOT_PATH "/dt/gam/type", &pg, sizeof(pg))
            != sizeof(pg)) {
                log_err("Failed to read policy for ribmgr gam.");
                return -1;
        }

        dt.sdu_sched = sdu_sched_create(sdu_handler);
        if (dt.sdu_sched == NULL) {
                log_err("Failed to create N-1 SDU scheduler.");
                return -1;
        }

        dt.gam = gam_create(pg, dt.nbs, dt.ae);
        if (dt.gam == NULL) {
                log_err("Failed to init dt graph adjacency manager.");
                sdu_sched_destroy(dt.sdu_sched);
                return -1;
        }

        return 0;
}

void dt_stop(void)
{
        gam_destroy(dt.gam);

        sdu_sched_destroy(dt.sdu_sched);
}

int dt_write_sdu(uint64_t             dst_addr,
                 qoscube_t            qc,
                 uint8_t              pdu_type,
                 struct shm_du_buff * sdb)
{
        int           fd;
        struct dt_pci dt_pci;

        assert(sdb);

        fd = pff_nhop(dt.pff[qc], dst_addr);
        if (fd < 0) {
                log_err("Could not get nhop for addr %" PRIu64 ".", dst_addr);
                return -1;
        }

        dt_pci.dst_addr = dst_addr;
        dt_pci.qc = qc;
        dt_pci.pdu_type = pdu_type;

        if (dt_pci_ser(sdb, &dt_pci)) {
                log_err("Failed to serialize PDU.");
                return -1;
        }

        if (ipcp_flow_write(fd, sdb)) {
                log_err("Failed to write SDU to fd %d.", fd);
                return -1;
        }

        return 0;
}
