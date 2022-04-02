/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Data Transfer Component
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
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"

#define DT               "dt"
#define OUROBOROS_PREFIX DT

#include <ouroboros/bitmap.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/notifier.h>
#include <ouroboros/rib.h>
#ifdef IPCP_FLOW_STATS
#include <ouroboros/fccntl.h>
#endif

#include "common/comp.h"
#include "common/connmgr.h"
#include "ca.h"
#include "ipcp.h"
#include "dt.h"
#include "pff.h"
#include "routing.h"
#include "psched.h"
#include "fa.h"

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#define QOS_BLOCK_LEN   672
#define RIB_FILE_STRLEN (189 + QOS_BLOCK_LEN * QOS_CUBE_MAX)
#define RIB_NAME_STRLEN 256

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

struct comp_info {
        void (* post_packet)(void * comp, struct shm_du_buff * sdb);
        void * comp;
        char * name;
};

/* Fixed field lengths */
#define TTL_LEN 1
#define QOS_LEN 1
#define ECN_LEN 1

struct dt_pci {
        uint64_t  dst_addr;
        qoscube_t qc;
        uint8_t   ttl;
        uint8_t   ecn;
        uint64_t  eid;
};

struct {
        uint8_t         addr_size;
        uint8_t         eid_size;
        size_t          head_size;

        /* Offsets */
        size_t          qc_o;
        size_t          ttl_o;
        size_t          ecn_o;
        size_t          eid_o;

        /* Initial TTL value */
        uint8_t         max_ttl;
} dt_pci_info;

static void dt_pci_ser(uint8_t *       head,
                       struct dt_pci * dt_pci)
{
        uint8_t ttl = dt_pci_info.max_ttl;

        assert(head);
        assert(dt_pci);

        /* FIXME: Add check and operations for Big Endian machines. */
        memcpy(head, &dt_pci->dst_addr, dt_pci_info.addr_size);
        memcpy(head + dt_pci_info.qc_o, &dt_pci->qc, QOS_LEN);
        memcpy(head + dt_pci_info.ttl_o, &ttl, TTL_LEN);
        memcpy(head + dt_pci_info.ecn_o, &dt_pci->ecn, ECN_LEN);
        memcpy(head + dt_pci_info.eid_o, &dt_pci->eid, dt_pci_info.eid_size);

}

static void dt_pci_des(uint8_t *       head,
                       struct dt_pci * dt_pci)
{
        assert(head);
        assert(dt_pci);

        /* Decrease TTL */
        --*(head + dt_pci_info.ttl_o);

        /* FIXME: Add check and operations for Big Endian machines. */
        memcpy(&dt_pci->dst_addr, head, dt_pci_info.addr_size);
        memcpy(&dt_pci->qc, head + dt_pci_info.qc_o, QOS_LEN);
        memcpy(&dt_pci->ttl, head + dt_pci_info.ttl_o, TTL_LEN);
        memcpy(&dt_pci->ecn, head + dt_pci_info.ecn_o, ECN_LEN);
        memcpy(&dt_pci->eid, head + dt_pci_info.eid_o, dt_pci_info.eid_size);
}

static void dt_pci_shrink(struct shm_du_buff * sdb)
{
        assert(sdb);

        shm_du_buff_head_release(sdb, dt_pci_info.head_size);
}

struct {
        struct psched *    psched;

        struct pff *       pff[QOS_CUBE_MAX];
        struct routing_i * routing[QOS_CUBE_MAX];
#ifdef IPCP_FLOW_STATS
        struct {
                time_t          stamp;
                uint64_t        addr;
                size_t          snd_pkt[QOS_CUBE_MAX];
                size_t          rcv_pkt[QOS_CUBE_MAX];
                size_t          snd_bytes[QOS_CUBE_MAX];
                size_t          rcv_bytes[QOS_CUBE_MAX];
                size_t          lcl_r_pkt[QOS_CUBE_MAX];
                size_t          lcl_r_bytes[QOS_CUBE_MAX];
                size_t          lcl_w_pkt[QOS_CUBE_MAX];
                size_t          lcl_w_bytes[QOS_CUBE_MAX];
                size_t          r_drp_pkt[QOS_CUBE_MAX];
                size_t          r_drp_bytes[QOS_CUBE_MAX];
                size_t          w_drp_pkt[QOS_CUBE_MAX];
                size_t          w_drp_bytes[QOS_CUBE_MAX];
                size_t          f_nhp_pkt[QOS_CUBE_MAX];
                size_t          f_nhp_bytes[QOS_CUBE_MAX];
                pthread_mutex_t lock;
        } stat[PROG_MAX_FLOWS];

        size_t             n_flows;
#endif
        struct bmp *       res_fds;
        struct comp_info   comps[PROG_RES_FDS];
        pthread_rwlock_t   lock;

        pthread_t          listener;
} dt;

static int dt_rib_read(const char * path,
                       char *       buf,
                       size_t       len)
{
#ifdef IPCP_FLOW_STATS
        int         fd;
        int         i;
        char        str[QOS_BLOCK_LEN + 1];
        char        addrstr[20];
        char *      entry;
        char        tmstr[20];
        size_t      rxqlen = 0;
        size_t      txqlen = 0;
        struct tm * tm;

        /* NOTE: we may need stronger checks. */
        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        fd = atoi(entry);

        if (len < RIB_FILE_STRLEN)
                return 0;

        buf[0] = '\0';

        pthread_mutex_lock(&dt.stat[fd].lock);

        if (dt.stat[fd].stamp == 0) {
                pthread_mutex_unlock(&dt.stat[fd].lock);
                return 0;
        }

        if (dt.stat[fd].addr == ipcpi.dt_addr)
                sprintf(addrstr, "%s", dt.comps[fd].name);
        else
                sprintf(addrstr, "%" PRIu64, dt.stat[fd].addr);

        tm = localtime(&dt.stat[fd].stamp);
        strftime(tmstr, sizeof(tmstr), "%F %T", tm);

        if (fd >= PROG_RES_FDS) {
                fccntl(fd, FLOWGRXQLEN, &rxqlen);
                fccntl(fd, FLOWGTXQLEN, &txqlen);
        }

        sprintf(buf,
                "Flow established at:      %20s\n"
                "Endpoint address:         %20s\n"
                "Queued packets (rx):      %20zu\n"
                "Queued packets (tx):      %20zu\n\n",
                tmstr, addrstr, rxqlen, txqlen);
        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                sprintf(str,
                        "Qos cube %3d:\n"
                        " sent (packets):          %20zu\n"
                        " sent (bytes):            %20zu\n"
                        " rcvd (packets):          %20zu\n"
                        " rcvd (bytes):            %20zu\n"
                        " local sent (packets):    %20zu\n"
                        " local sent (bytes):      %20zu\n"
                        " local rcvd (packets):    %20zu\n"
                        " local rcvd (bytes):      %20zu\n"
                        " dropped ttl (packets):   %20zu\n"
                        " dropped ttl (bytes):     %20zu\n"
                        " failed writes (packets): %20zu\n"
                        " failed writes (bytes):   %20zu\n"
                        " failed nhop (packets):   %20zu\n"
                        " failed nhop (bytes):     %20zu\n",
                        i,
                        dt.stat[fd].snd_pkt[i],
                        dt.stat[fd].snd_bytes[i],
                        dt.stat[fd].rcv_pkt[i],
                        dt.stat[fd].rcv_bytes[i],
                        dt.stat[fd].lcl_w_pkt[i],
                        dt.stat[fd].lcl_w_bytes[i],
                        dt.stat[fd].lcl_r_pkt[i],
                        dt.stat[fd].lcl_r_bytes[i],
                        dt.stat[fd].r_drp_pkt[i],
                        dt.stat[fd].r_drp_bytes[i],
                        dt.stat[fd].w_drp_pkt[i],
                        dt.stat[fd].w_drp_bytes[i],
                        dt.stat[fd].f_nhp_pkt[i],
                        dt.stat[fd].f_nhp_bytes[i]
                        );
                strcat(buf, str);
        }

        pthread_mutex_unlock(&dt.stat[fd].lock);

        return RIB_FILE_STRLEN;
#else
        (void) path;
        (void) buf;
        (void) len;
        return 0;
#endif
}

static int dt_rib_readdir(char *** buf)
{
#ifdef IPCP_FLOW_STATS
        char   entry[RIB_PATH_LEN + 1];
        size_t i;
        int    idx = 0;

        pthread_rwlock_rdlock(&dt.lock);

        if (dt.n_flows < 1) {
                pthread_rwlock_unlock(&dt.lock);
                return 0;
        }

        *buf = malloc(sizeof(**buf) * dt.n_flows);
        if (*buf == NULL) {
                pthread_rwlock_unlock(&dt.lock);
                return -ENOMEM;
        }

        for (i = 0; i < PROG_MAX_FLOWS; ++i) {
                pthread_mutex_lock(&dt.stat[i].lock);

                if (dt.stat[i].stamp == 0) {
                        pthread_mutex_unlock(&dt.stat[i].lock);
                        /* Optimization: skip unused res_fds. */
                        if (i < PROG_RES_FDS)
                                i = PROG_RES_FDS;
                        continue;
                }

                sprintf(entry, "%zu", i);

                (*buf)[idx] = malloc(strlen(entry) + 1);
                if ((*buf)[idx] == NULL) {
                        while (idx-- > 0)
                                free((*buf)[idx]);
                        free(*buf);
                        pthread_mutex_unlock(&dt.stat[i].lock);
                        pthread_rwlock_unlock(&dt.lock);
                        return -ENOMEM;
                }

                strcpy((*buf)[idx++], entry);

                pthread_mutex_unlock(&dt.stat[i].lock);
        }
        assert((size_t) idx == dt.n_flows);

        pthread_rwlock_unlock(&dt.lock);

        return idx;
#else
        (void) buf;
        return 0;
#endif
}

static int dt_rib_getattr(const char *      path,
                          struct rib_attr * attr)
{
#ifdef IPCP_FLOW_STATS
        int    fd;
        char * entry;

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        fd = atoi(entry);

        pthread_mutex_lock(&dt.stat[fd].lock);

        if (dt.stat[fd].stamp != -1) {
                attr->size  = RIB_FILE_STRLEN;
                attr->mtime = dt.stat[fd].stamp;
        } else {
                attr->size  = 0;
                attr->mtime = 0;
        }

        pthread_mutex_unlock(&dt.stat[fd].lock);
#else
        (void) path;
        (void) attr;
#endif
        return 0;
}

static struct rib_ops r_ops = {
        .read    = dt_rib_read,
        .readdir = dt_rib_readdir,
        .getattr = dt_rib_getattr
};

#ifdef IPCP_FLOW_STATS
static void stat_used(int      fd,
                      uint64_t addr)
{
        struct timespec now;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_mutex_lock(&dt.stat[fd].lock);

        memset(&dt.stat[fd], 0, sizeof(dt.stat[fd]));

        dt.stat[fd].stamp = (addr != INVALID_ADDR) ? now.tv_sec : 0;
        dt.stat[fd].addr = addr;

        pthread_mutex_unlock(&dt.stat[fd].lock);

        pthread_rwlock_wrlock(&dt.lock);

        (addr != INVALID_ADDR) ? ++dt.n_flows : --dt.n_flows;

        pthread_rwlock_unlock(&dt.lock);
}
#endif

static void handle_event(void *       self,
                         int          event,
                         const void * o)
{
        struct conn * c;

        (void) self;

        c = (struct conn *) o;

        switch (event) {
        case NOTIFY_DT_CONN_ADD:
#ifdef IPCP_FLOW_STATS
                stat_used(c->flow_info.fd, c->conn_info.addr);
#endif
                psched_add(dt.psched, c->flow_info.fd);
                log_dbg("Added fd %d to packet scheduler.", c->flow_info.fd);
                break;
        case NOTIFY_DT_CONN_DEL:
#ifdef IPCP_FLOW_STATS
                stat_used(c->flow_info.fd, INVALID_ADDR);
#endif
                psched_del(dt.psched, c->flow_info.fd);
                log_dbg("Removed fd %d from "
                        "packet scheduler.", c->flow_info.fd);
                break;
        default:
                break;
        }
}

static void packet_handler(int                  fd,
                           qoscube_t            qc,
                           struct shm_du_buff * sdb)
{
        struct dt_pci dt_pci;
        int           ret;
        int           ofd;
        uint8_t *     head;
        size_t        len;

        len = shm_du_buff_len(sdb);

#ifndef IPCP_FLOW_STATS
        (void)        fd;
#else
        pthread_mutex_lock(&dt.stat[fd].lock);

        ++dt.stat[fd].rcv_pkt[qc];
        dt.stat[fd].rcv_bytes[qc] += len;

        pthread_mutex_unlock(&dt.stat[fd].lock);
#endif
        memset(&dt_pci, 0, sizeof(dt_pci));

        head = shm_du_buff_head(sdb);

        dt_pci_des(head, &dt_pci);
        if (dt_pci.dst_addr != ipcpi.dt_addr) {
                if (dt_pci.ttl == 0) {
                        log_dbg("TTL was zero.");
                        ipcp_sdb_release(sdb);
#ifdef IPCP_FLOW_STATS
                        pthread_mutex_lock(&dt.stat[fd].lock);

                        ++dt.stat[fd].r_drp_pkt[qc];
                        dt.stat[fd].r_drp_bytes[qc] += len;

                        pthread_mutex_unlock(&dt.stat[fd].lock);
#endif
                        return;
                }

                /* FIXME: Use qoscube from PCI instead of incoming flow. */
                ofd = pff_nhop(dt.pff[qc], dt_pci.dst_addr);
                if (ofd < 0) {
                        log_dbg("No next hop for %" PRIu64 ".",
                                dt_pci.dst_addr);
                        ipcp_sdb_release(sdb);
#ifdef IPCP_FLOW_STATS
                        pthread_mutex_lock(&dt.stat[fd].lock);

                        ++dt.stat[fd].f_nhp_pkt[qc];
                        dt.stat[fd].f_nhp_bytes[qc] += len;

                        pthread_mutex_unlock(&dt.stat[fd].lock);
#endif
                        return;
                }

                (void) ca_calc_ecn(ofd, head + dt_pci_info.ecn_o, qc, len);

                ret = ipcp_flow_write(ofd, sdb);
                if (ret < 0) {
                        log_dbg("Failed to write packet to fd %d.", ofd);
                        if (ret == -EFLOWDOWN)
                                notifier_event(NOTIFY_DT_FLOW_DOWN, &ofd);
                        ipcp_sdb_release(sdb);
#ifdef IPCP_FLOW_STATS
                        pthread_mutex_lock(&dt.stat[ofd].lock);

                        ++dt.stat[ofd].w_drp_pkt[qc];
                        dt.stat[ofd].w_drp_bytes[qc] += len;

                        pthread_mutex_unlock(&dt.stat[ofd].lock);
#endif
                        return;
                }
#ifdef IPCP_FLOW_STATS
                pthread_mutex_lock(&dt.stat[ofd].lock);

                ++dt.stat[ofd].snd_pkt[qc];
                dt.stat[ofd].snd_bytes[qc] += len;

                pthread_mutex_unlock(&dt.stat[ofd].lock);
#endif
        } else {
                dt_pci_shrink(sdb);
                if (dt_pci.eid >= PROG_RES_FDS) {
                        uint8_t ecn = *(head + dt_pci_info.ecn_o);
                        fa_np1_rcv(dt_pci.eid, ecn, sdb);
                        return;
                }

                if (dt.comps[dt_pci.eid].post_packet == NULL) {
                        log_err("No registered component on eid %" PRIu64 ".",
                                dt_pci.eid);
                        ipcp_sdb_release(sdb);
                        return;
                }
#ifdef IPCP_FLOW_STATS
                pthread_mutex_lock(&dt.stat[fd].lock);

                ++dt.stat[fd].lcl_r_pkt[qc];
                dt.stat[fd].lcl_r_bytes[qc] += len;

                pthread_mutex_unlock(&dt.stat[fd].lock);
                pthread_mutex_lock(&dt.stat[dt_pci.eid].lock);

                ++dt.stat[dt_pci.eid].snd_pkt[qc];
                dt.stat[dt_pci.eid].snd_bytes[qc] += len;

                pthread_mutex_unlock(&dt.stat[dt_pci.eid].lock);
#endif
                dt.comps[dt_pci.eid].post_packet(dt.comps[dt_pci.eid].comp,
                                                 sdb);
        }
}

static void * dt_conn_handle(void * o)
{
        struct conn conn;

        (void) o;

        while (true) {
                if (connmgr_wait(COMPID_DT, &conn)) {
                        log_err("Failed to get next DT connection.");
                        continue;
                }

                /* NOTE: connection acceptance policy could be here. */

                notifier_event(NOTIFY_DT_CONN_ADD, &conn);
        }

        return 0;
}

int dt_init(enum pol_routing pr,
            uint8_t          addr_size,
            uint8_t          eid_size,
            uint8_t          max_ttl)
{
        int              i;
        int              j;
        char             dtstr[RIB_NAME_STRLEN + 1];
        int              pp;
        struct conn_info info;

        memset(&info, 0, sizeof(info));

        strcpy(info.comp_name, DT_COMP);
        strcpy(info.protocol, DT_PROTO);
        info.pref_version = 1;
        info.pref_syntax  = PROTO_FIXED;
        info.addr         = ipcpi.dt_addr;

        if (eid_size != 8) { /* only support 64 bits from now */
                log_warn("Invalid EID size. Only 64 bit is supported.");
                eid_size = 8;
        }

        dt_pci_info.addr_size = addr_size;
        dt_pci_info.eid_size  = eid_size;
        dt_pci_info.max_ttl   = max_ttl;

        dt_pci_info.qc_o      = dt_pci_info.addr_size;
        dt_pci_info.ttl_o     = dt_pci_info.qc_o + QOS_LEN;
        dt_pci_info.ecn_o     = dt_pci_info.ttl_o + TTL_LEN;
        dt_pci_info.eid_o     = dt_pci_info.ecn_o + ECN_LEN;
        dt_pci_info.head_size = dt_pci_info.eid_o + dt_pci_info.eid_size;

        if (notifier_reg(handle_event, NULL)) {
                log_err("Failed to register with notifier.");
                goto fail_notifier_reg;
        }

        if (connmgr_comp_init(COMPID_DT, &info)) {
                log_err("Failed to register with connmgr.");
                goto fail_connmgr_comp_init;
        }

        pp = routing_init(pr);
        if (pp < 0) {
                log_err("Failed to init routing.");
                goto fail_routing;
        }

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                dt.pff[i] = pff_create(pp);
                if (dt.pff[i] == NULL) {
                        log_err("Failed to create a PFF.");
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

        dt.res_fds = bmp_create(PROG_RES_FDS, 0);
        if (dt.res_fds == NULL)
                goto fail_res_fds;
#ifdef IPCP_FLOW_STATS
        memset(dt.stat, 0, sizeof(dt.stat));

        for (i = 0; i < PROG_MAX_FLOWS; ++i)
                if (pthread_mutex_init(&dt.stat[i].lock, NULL)) {
                        for (j = 0; j < i; ++j)
                                pthread_mutex_destroy(&dt.stat[j].lock);
                        goto fail_stat_lock;
                }

        dt.n_flows = 0;
#endif
        sprintf(dtstr, "%s.%" PRIu64, DT, ipcpi.dt_addr);
        if (rib_reg(dtstr, &r_ops))
                goto fail_rib_reg;

        return 0;

 fail_rib_reg:
#ifdef IPCP_FLOW_STATS
        for (i = 0; i < PROG_MAX_FLOWS; ++i)
                pthread_mutex_destroy(&dt.stat[i].lock);
 fail_stat_lock:
#endif
        bmp_destroy(dt.res_fds);
 fail_res_fds:
        pthread_rwlock_destroy(&dt.lock);
 fail_rwlock_init:
        for (j = 0; j < QOS_CUBE_MAX; ++j)
                routing_i_destroy(dt.routing[j]);
 fail_routing_i:
        for (i = 0; i < QOS_CUBE_MAX; ++i)
                pff_destroy(dt.pff[i]);
 fail_pff:
        routing_fini();
 fail_routing:
        connmgr_comp_fini(COMPID_DT);
 fail_connmgr_comp_init:
        notifier_unreg(&handle_event);
 fail_notifier_reg:
        return -1;
}

void dt_fini(void)
{
        char dtstr[RIB_NAME_STRLEN + 1];
        int i;

        sprintf(dtstr, "%s.%" PRIu64, DT, ipcpi.dt_addr);
        rib_unreg(dtstr);
#ifdef IPCP_FLOW_STATS
        for (i = 0; i < PROG_MAX_FLOWS; ++i)
                pthread_mutex_destroy(&dt.stat[i].lock);
#endif
        bmp_destroy(dt.res_fds);

        pthread_rwlock_destroy(&dt.lock);

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                routing_i_destroy(dt.routing[i]);

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                pff_destroy(dt.pff[i]);

        routing_fini();

        connmgr_comp_fini(COMPID_DT);

        notifier_unreg(&handle_event);
}

int dt_start(void)
{
        dt.psched = psched_create(packet_handler, ipcp_flow_read);
        if (dt.psched == NULL) {
                log_err("Failed to create N-1 packet scheduler.");
                return -1;
        }

        if (pthread_create(&dt.listener, NULL, dt_conn_handle, NULL)) {
                log_err("Failed to create listener thread.");
                psched_destroy(dt.psched);
                return -1;
        }

        return 0;
}

void dt_stop(void)
{
        pthread_cancel(dt.listener);
        pthread_join(dt.listener, NULL);
        psched_destroy(dt.psched);
}

int dt_reg_comp(void * comp,
                void (* func)(void * func, struct shm_du_buff *),
                char * name)
{
        int eid;

        assert(func);

        pthread_rwlock_wrlock(&dt.lock);

        eid = bmp_allocate(dt.res_fds);
        if (!bmp_is_id_valid(dt.res_fds, eid)) {
                log_warn("Reserved EIDs depleted.");
                pthread_rwlock_unlock(&dt.lock);
                return -EBADF;
        }

        assert(dt.comps[eid].post_packet == NULL);
        assert(dt.comps[eid].comp == NULL);
        assert(dt.comps[eid].name == NULL);

        dt.comps[eid].post_packet = func;
        dt.comps[eid].comp        = comp;
        dt.comps[eid].name        = name;

        pthread_rwlock_unlock(&dt.lock);
#ifdef IPCP_FLOW_STATS
        stat_used(eid, ipcpi.dt_addr);
#endif
        return eid;
}

int dt_write_packet(uint64_t             dst_addr,
                    qoscube_t            qc,
                    uint64_t             eid,
                    struct shm_du_buff * sdb)
{
        struct dt_pci dt_pci;
        int           fd;
        int           ret;
        uint8_t *     head;
        size_t        len;

        assert(sdb);
        assert(dst_addr != ipcpi.dt_addr);

        len = shm_du_buff_len(sdb);

#ifdef IPCP_FLOW_STATS
        if (eid < PROG_RES_FDS) {
                pthread_mutex_lock(&dt.stat[eid].lock);

                ++dt.stat[eid].lcl_r_pkt[qc];
                dt.stat[eid].lcl_r_bytes[qc] += len;

                pthread_mutex_unlock(&dt.stat[eid].lock);
        }
#endif
        fd = pff_nhop(dt.pff[qc], dst_addr);
        if (fd < 0) {
                log_dbg("Could not get nhop for addr %" PRIu64 ".", dst_addr);
#ifdef IPCP_FLOW_STATS
                if (eid < PROG_RES_FDS) {
                        pthread_mutex_lock(&dt.stat[eid].lock);

                        ++dt.stat[eid].lcl_r_pkt[qc];
                        dt.stat[eid].lcl_r_bytes[qc] += len;

                        pthread_mutex_unlock(&dt.stat[eid].lock);
                }
#endif
                return -EPERM;
        }

        head = shm_du_buff_head_alloc(sdb, dt_pci_info.head_size);
        if (head == NULL) {
                log_dbg("Failed to allocate DT header.");
                goto fail_write;
        }

        len = shm_du_buff_len(sdb);

        dt_pci.dst_addr = dst_addr;
        dt_pci.qc       = qc;
        dt_pci.eid      = eid;
        dt_pci.ecn      = 0;

        (void) ca_calc_ecn(fd, &dt_pci.ecn, qc, len);

        dt_pci_ser(head, &dt_pci);

        ret = ipcp_flow_write(fd, sdb);
        if (ret < 0) {
                log_dbg("Failed to write packet to fd %d.", fd);
                if (ret == -EFLOWDOWN)
                        notifier_event(NOTIFY_DT_FLOW_DOWN, &fd);
                goto fail_write;
        }
#ifdef IPCP_FLOW_STATS
        pthread_mutex_lock(&dt.stat[fd].lock);

        if (dt_pci.eid < PROG_RES_FDS) {
                ++dt.stat[fd].lcl_w_pkt[qc];
                dt.stat[fd].lcl_w_bytes[qc] += len;
        }
        ++dt.stat[fd].snd_pkt[qc];
        dt.stat[fd].snd_bytes[qc] += len;

        pthread_mutex_unlock(&dt.stat[fd].lock);
#endif
        return 0;

 fail_write:
#ifdef IPCP_FLOW_STATS
        pthread_mutex_lock(&dt.stat[fd].lock);

        if (eid < PROG_RES_FDS) {
                ++dt.stat[fd].lcl_w_pkt[qc];
                dt.stat[fd].lcl_w_bytes[qc] += len;
        }
        ++dt.stat[fd].w_drp_pkt[qc];
        dt.stat[fd].w_drp_bytes[qc] += len;

        pthread_mutex_unlock(&dt.stat[fd].lock);
#endif
        return -1;
}
