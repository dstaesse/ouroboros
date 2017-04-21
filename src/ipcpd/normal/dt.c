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
#include "shm_pci.h"
#include "pff.h"
#include "neighbors.h"
#include "gam.h"
#include "routing.h"
#include "sdu_sched.h"
#include "frct.h"
#include "ae.h"
#include "ribconfig.h"

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

struct {
        flow_set_t *       set[QOS_CUBE_MAX];
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
        qoscube_t cube;

        /* We are only interested in neighbors being added and removed. */
        switch (event) {
        case NEIGHBOR_ADDED:
                ipcp_flow_get_qoscube(conn.flow_info.fd, &cube);
                flow_set_add(dt.set[cube], conn.flow_info.fd);
                log_dbg("Added fd %d to flow set.", conn.flow_info.fd);
                break;
        case NEIGHBOR_REMOVED:
                ipcp_flow_get_qoscube(conn.flow_info.fd, &cube);
                flow_set_del(dt.set[cube], conn.flow_info.fd);
                log_dbg("Removed fd %d from flow set.", conn.flow_info.fd);
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
        struct pci pci;

        memset(&pci, 0, sizeof(pci));

        shm_pci_des(sdb, &pci);

        if (pci.dst_addr != ipcpi.dt_addr) {
                if (pci.ttl == 0) {
                        log_dbg("TTL was zero.");
                        ipcp_flow_del(sdb);
                        return 0;
                }

                pff_lock(dt.pff[qc]);

                fd = pff_nhop(dt.pff[qc], pci.dst_addr);
                if (fd < 0) {
                        pff_unlock(dt.pff[qc]);
                        log_err("No next hop for %" PRIu64, pci.dst_addr);
                        ipcp_flow_del(sdb);
                        return -1;
                }

                pff_unlock(dt.pff[qc]);

                if (ipcp_flow_write(fd, sdb)) {
                        log_err("Failed to write SDU to fd %d.", fd);
                        ipcp_flow_del(sdb);
                        return -1;
                }
        } else {
                shm_pci_shrink(sdb);

                if (frct_post_sdu(&pci, sdb)) {
                        log_err("Failed to hand PDU to FRCT.");
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

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                dt.set[i] = flow_set_create();
                if (dt.set[i] == NULL) {
                        goto fail_flows;
                        return -1;
                }
        }

        if (shm_pci_init()) {
                log_err("Failed to init shm pci.");
                goto fail_flows;
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
                goto fail_flows;
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
 fail_flows:
        for (i = 0; i < QOS_CUBE_MAX; ++i)
                flow_set_destroy(dt.set[i]);

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

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                flow_set_destroy(dt.set[i]);
}

int dt_start(void)
{
        enum pol_gam pg;

        if (rib_read(BOOT_PATH "/dt/gam/type", &pg, sizeof(pg))
            != sizeof(pg)) {
                log_err("Failed to read policy for ribmgr gam.");
                return -1;
        }

        dt.gam = gam_create(pg, dt.nbs, dt.ae);
        if (dt.gam == NULL) {
                log_err("Failed to init dt graph adjacency manager.");
                return -1;
        }

        dt.sdu_sched = sdu_sched_create(dt.set, sdu_handler);
        if (dt.sdu_sched == NULL) {
                log_err("Failed to create N-1 SDU scheduler.");
                gam_destroy(dt.gam);
                return -1;
        }

        return 0;
}

void dt_stop(void)
{
        sdu_sched_destroy(dt.sdu_sched);

        gam_destroy(dt.gam);
}

int dt_write_sdu(struct pci *         pci,
                 struct shm_du_buff * sdb)
{
        int fd;

        assert(pci);
        assert(sdb);

        pff_lock(dt.pff[pci->qos_id]);

        fd = pff_nhop(dt.pff[pci->qos_id], pci->dst_addr);
        if (fd < 0) {
                pff_unlock(dt.pff[pci->qos_id]);
                log_err("Could not get nhop for address %" PRIu64,
                        pci->dst_addr);
                ipcp_flow_del(sdb);
                return -1;
        }

        pff_unlock(dt.pff[pci->qos_id]);

        if (shm_pci_ser(sdb, pci)) {
                log_err("Failed to serialize PDU.");
                ipcp_flow_del(sdb);
                return -1;
        }

        if (ipcp_flow_write(fd, sdb)) {
                log_err("Failed to write SDU to fd %d.", fd);
                ipcp_flow_del(sdb);
                return -1;
        }

        return 0;
}

int dt_write_buf(struct pci * pci,
                 buffer_t *   buf)
{
        buffer_t * buffer;
        int        fd;

        assert(pci);
        assert(buf);
        assert(buf->data);

        pff_lock(dt.pff[pci->qos_id]);

        fd = pff_nhop(dt.pff[pci->qos_id], pci->dst_addr);
        if (fd < 0) {
                pff_unlock(dt.pff[pci->qos_id]);
                log_err("Could not get nhop for address %" PRIu64,
                        pci->dst_addr);
                return -1;
        }

        pff_unlock(dt.pff[pci->qos_id]);

        buffer = shm_pci_ser_buf(buf, pci);
        if (buffer == NULL) {
                log_err("Failed to serialize buffer.");
                return -1;
        }

        if (flow_write(fd, buffer->data, buffer->len) == -1) {
                log_err("Failed to write buffer to fd.");
                free(buffer);
                return -1;
        }

        free(buffer->data);
        free(buffer);

        return 0;
}
