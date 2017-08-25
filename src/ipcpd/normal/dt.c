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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200112L

#include "config.h"

#define OUROBOROS_PREFIX "dt-ae"

#include <ouroboros/bitmap.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/rib.h>
#include <ouroboros/dev.h>

#include "connmgr.h"
#include "ipcp.h"
#include "dt.h"
#include "dt_pci.h"
#include "pff.h"
#include "neighbors.h"
#include "routing.h"
#include "sdu_sched.h"
#include "ae.h"
#include "ribconfig.h"
#include "fa.h"

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

struct ae_info {
        void   (* post_sdu)(void * ae, struct shm_du_buff * sdb);
        void * ae;
};

struct {
        struct sdu_sched * sdu_sched;

        struct pff *       pff[QOS_CUBE_MAX];
        struct routing_i * routing[QOS_CUBE_MAX];

        struct bmp *       res_fds;
        struct ae_info     aes[AP_RES_FDS];
        pthread_rwlock_t   lock;

        struct nbs *       nbs;
        struct ae *        ae;

        struct nb_notifier nb_notifier;

        pthread_t          listener;
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

                if (dt_pci.fd > AP_RES_FDS) {
                        if (ipcp_flow_write(dt_pci.fd, sdb)) {
                                ipcp_sdb_release(sdb);
                                return -1;
                        }
                        return 0;
                }

                if (dt.aes[dt_pci.fd].post_sdu == NULL) {
                        log_err("No registered AE on fd %d.", dt_pci.fd);
                        ipcp_sdb_release(sdb);
                        return -EPERM;
                }

                dt.aes[dt_pci.fd].post_sdu(dt.aes[dt_pci.fd].ae, sdb);

                return 0;
        }

        /* silence compiler */
        return 0;
}

static void * dt_conn_handle(void * o)
{
        struct conn conn;

        (void) o;

        while (true) {
                if (connmgr_wait(AEID_DT, &conn)) {
                        log_err("Failed to get next DT connection.");
                        continue;
                }

                log_dbg("Got new connection.");

                nbs_add(dt.nbs, conn);
        }

        return 0;
}

int dt_init(enum pol_routing pr,
            uint8_t          addr_size,
            uint8_t          fd_size,
            bool             has_ttl)
{
        int              i;
        int              j;
        struct conn_info info;

        memset(&info, 0, sizeof(info));

        strcpy(info.ae_name, DT_AE);
        strcpy(info.protocol, DT_PROTO);
        info.pref_version = 1;
        info.pref_syntax  = PROTO_FIXED;
        info.addr         = ipcpi.dt_addr;

        if (dt_pci_init(addr_size, fd_size, has_ttl)) {
                log_err("Failed to init shm dt_pci.");
                goto fail_pci_init;
        }

        dt.nbs = nbs_create();
        if (dt.nbs == NULL) {
                log_err("Failed to create neighbors struct.");
                goto fail_nbs;
        }

        dt.nb_notifier.notify_call = dt_neighbor_event;
        if (nbs_reg_notifier(dt.nbs, &dt.nb_notifier)) {
                log_err("Failed to register notifier.");
                goto fail_nbs_notifier;
        }

        if (connmgr_ae_init(AEID_DT, &info, dt.nbs)) {
                log_err("Failed to register with connmgr.");
                goto fail_connmgr_ae_init;
        };

        if (routing_init(pr, dt.nbs)) {
                log_err("Failed to init routing.");
                goto fail_routing;
        }

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                dt.pff[i] = pff_create();
                if (dt.pff[i] == NULL) {
                        for (j = 0; j < i; ++j)
                                pff_destroy(dt.pff[j]);
                        goto fail_pff;
                }
        }

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                dt.routing[i] = routing_i_create(dt.pff[i]);
                if (dt.routing[i] == NULL) {
                        for (j = 0; j < i; ++j)
                                routing_i_destroy(dt.routing[j]);
                        goto fail_routing_i;
                }
        }

        if (pthread_rwlock_init(&dt.lock, NULL)) {
                log_err("Failed to init rwlock.");
                goto fail_rwlock_init;
        }

        dt.res_fds = bmp_create(AP_RES_FDS, 0);
        if (dt.res_fds == NULL)
                goto fail_res_fds;

        return 0;

 fail_res_fds:
        pthread_rwlock_destroy(&dt.lock);
 fail_rwlock_init:
        for (j = 0; j < QOS_CUBE_MAX; ++j)
                routing_i_destroy(dt.routing[j]);
 fail_routing_i:
        connmgr_ae_fini(AEID_DT);
 fail_connmgr_ae_init:
        for (i = 0; i < QOS_CUBE_MAX; ++i)
                pff_destroy(dt.pff[i]);
 fail_pff:
        routing_fini();
 fail_routing:
        nbs_unreg_notifier(dt.nbs, &dt.nb_notifier);
 fail_nbs_notifier:
        nbs_destroy(dt.nbs);
 fail_nbs:
        dt_pci_fini();
 fail_pci_init:
        connmgr_ae_fini(AEID_DT);
        return -1;
}

void dt_fini(void)
{
        int i;

        bmp_destroy(dt.res_fds);

        pthread_rwlock_destroy(&dt.lock);

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                routing_i_destroy(dt.routing[i]);

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                pff_destroy(dt.pff[i]);

        routing_fini();

        nbs_unreg_notifier(dt.nbs, &dt.nb_notifier);

        nbs_destroy(dt.nbs);

        connmgr_ae_fini(AEID_DT);
}

int dt_start(void)
{
        dt.sdu_sched = sdu_sched_create(sdu_handler);
        if (dt.sdu_sched == NULL) {
                log_err("Failed to create N-1 SDU scheduler.");
                return -1;
        }

        if (pthread_create(&dt.listener, NULL, dt_conn_handle, NULL)) {
                log_err("Failed to create listener thread.");
                sdu_sched_destroy(dt.sdu_sched);
                return -1;
        }

        return 0;
}

void dt_stop(void)
{
        pthread_cancel(dt.listener);
        pthread_join(dt.listener, NULL);
        sdu_sched_destroy(dt.sdu_sched);
}

int dt_reg_ae(void * ae,
              void (* func)(void * func, struct shm_du_buff *))
{
        int res_fd;

        assert(func);

        pthread_rwlock_wrlock(&dt.lock);

        res_fd = bmp_allocate(dt.res_fds);
        if (!bmp_is_id_valid(dt.res_fds, res_fd)) {
                log_warn("Reserved fds depleted.");
                pthread_rwlock_unlock(&dt.lock);
                return -EBADF;
        }

        assert(dt.aes[res_fd].post_sdu == NULL);
        assert(dt.aes[res_fd].ae == NULL);

        dt.aes[res_fd].post_sdu = func;
        dt.aes[res_fd].ae = ae;

        pthread_rwlock_unlock(&dt.lock);

        return res_fd;
}

int dt_write_sdu(uint64_t             dst_addr,
                 qoscube_t            qc,
                 int                  np1_fd,
                 struct shm_du_buff * sdb)
{
        int           fd;
        struct dt_pci dt_pci;

        assert(sdb);
        assert(dst_addr != ipcpi.dt_addr);

        fd = pff_nhop(dt.pff[qc], dst_addr);
        if (fd < 0) {
                log_dbg("Could not get nhop for addr %" PRIu64 ".", dst_addr);
                return -1;
        }

        dt_pci.dst_addr = dst_addr;
        dt_pci.qc       = qc;
        dt_pci.fd       = np1_fd;

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
