/*
 * Ouroboros - Copyright (C) 2016 - 2026
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

#include <ouroboros/atomics.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/notifier.h>
#include <ouroboros/rib.h>
#ifdef IPCP_FLOW_STATS
#include <ouroboros/fccntl.h>
#endif

#include "addr-auth.h"
#include "common/comp.h"
#include "common/connmgr.h"
#include "ca.h"
#include "cap.h"
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
#define RIB_FILE_STRLEN (169 + RIB_TM_STRLEN + QOS_BLOCK_LEN * QOS_CUBE_MAX)
#define RIB_NAME_STRLEN 256

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

struct comp_info {
        void (* post_packet)(void * comp, struct ssm_pk_buff * spb);
        void * comp;
        char * name;
};

/* Fixed field lengths */
#define TTL_LEN 1
#define QOS_LEN 1
#define ECN_LEN 1
#define CAP_LEN 1

struct dt_pci {
        uint64_t  dst_addr;
        qoscube_t qc;
        uint8_t   ttl;
        uint8_t   ecn;
        uint8_t   cap;
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
        size_t          cap_o;
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
        memcpy(head + dt_pci_info.cap_o, &dt_pci->cap, CAP_LEN);
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
        memcpy(&dt_pci->cap, head + dt_pci_info.cap_o, CAP_LEN);
        memcpy(&dt_pci->eid, head + dt_pci_info.eid_o, dt_pci_info.eid_size);
}

static void dt_pci_shrink(struct ssm_pk_buff * spb)
{
        assert(spb);

        ssm_pk_buff_pop(spb, dt_pci_info.head_size);
}

struct {
        struct psched *    psched;

        uint64_t           addr;

        struct pff *       pff[QOS_CUBE_MAX];
        struct routing_i * routing[QOS_CUBE_MAX];
#ifdef IPCP_FLOW_STATS
        /* Flow stats use lock-free atomics; stamp is the validity flag. */
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
        } stat[PROC_MAX_FLOWS];

        size_t             n_flows;
#endif
        struct bmp *       res_fds;
        struct comp_info   comps[PROC_RES_FDS];
        pthread_rwlock_t   lock;

        pthread_t          listener;
} dt;

#ifdef IPCP_FLOW_STATS
#define dt_stat_inc(idx, name, qc, len) \
        do { \
                FETCH_ADD_RELAXED(&dt.stat[idx].name ## _pkt[qc], 1); \
                FETCH_ADD_RELAXED(&dt.stat[idx].name ## _bytes[qc], (len)); \
        } while (0)
#define dt_stat_load(idx, field, qc) LOAD_RELAXED(&dt.stat[idx].field[qc])

static int dt_rib_read(const char * path,
                       char *       buf,
                       size_t       len)
{
        int         fd;
        int         i;
        char        str[QOS_BLOCK_LEN + 1];
        char        addrstr[20];
        char *      entry;
        char        tmstr[RIB_TM_STRLEN];
        size_t      rxqlen = 0;
        size_t      txqlen = 0;
        time_t      stamp;
        uint64_t    addr;
        struct tm * tm;

        /* NOTE: we may need stronger checks. */
        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        fd = atoi(entry);

        if (len < RIB_FILE_STRLEN)
                return 0;

        buf[0] = '\0';

        stamp = LOAD_ACQUIRE(&dt.stat[fd].stamp);
        if (stamp == 0)
                return 0;

        addr = LOAD_RELAXED(&dt.stat[fd].addr);

        if (addr == dt.addr)
                sprintf(addrstr, "%s", dt.comps[fd].name);
        else
                sprintf(addrstr, ADDR_FMT32, ADDR_VAL32(&addr));

        tm = gmtime(&stamp);
        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);

        if (fd >= PROC_RES_FDS) {
                fccntl(fd, FLOWGRXQLEN, &rxqlen);
                fccntl(fd, FLOWGTXQLEN, &txqlen);
        }

        sprintf(buf,
                "Flow established at:      %.*s\n"
                "Endpoint address:         %20s\n"
                "Queued packets (rx):      %20zu\n"
                "Queued packets (tx):      %20zu\n\n",
                RIB_TM_STRLEN - 1, tmstr, addrstr, rxqlen, txqlen);
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
                        dt_stat_load(fd, snd_pkt, i),
                        dt_stat_load(fd, snd_bytes, i),
                        dt_stat_load(fd, rcv_pkt, i),
                        dt_stat_load(fd, rcv_bytes, i),
                        dt_stat_load(fd, lcl_w_pkt, i),
                        dt_stat_load(fd, lcl_w_bytes, i),
                        dt_stat_load(fd, lcl_r_pkt, i),
                        dt_stat_load(fd, lcl_r_bytes, i),
                        dt_stat_load(fd, r_drp_pkt, i),
                        dt_stat_load(fd, r_drp_bytes, i),
                        dt_stat_load(fd, w_drp_pkt, i),
                        dt_stat_load(fd, w_drp_bytes, i),
                        dt_stat_load(fd, f_nhp_pkt, i),
                        dt_stat_load(fd, f_nhp_bytes, i)
                        );
                strcat(buf, str);
        }

        return RIB_FILE_STRLEN;
}

static int dt_rib_readdir(char *** buf)
{
        char   entry[RIB_PATH_LEN + 1];
        size_t i;
        int    idx = 0;

        pthread_rwlock_rdlock(&dt.lock);

        if (dt.n_flows < 1) {
                *buf = NULL;
                goto no_flows;
        }

        *buf = malloc(sizeof(**buf) * dt.n_flows);
        if (*buf == NULL)
                goto fail_entries;

        for (i = 0; i < PROC_MAX_FLOWS && idx < (int) dt.n_flows; ++i) {
                if (LOAD_RELAXED(&dt.stat[i].stamp) == 0)
                        continue; /* n-1 flows start at PROC_RES_FDS */

                sprintf(entry, "%zu", i);

                (*buf)[idx] = malloc(strlen(entry) + 1);
                if ((*buf)[idx] == NULL)
                        goto fail_entry;

                strcpy((*buf)[idx++], entry);

        }
 no_flows:
        pthread_rwlock_unlock(&dt.lock);

        return idx;

 fail_entry:
        while (idx-- > 0)
                free((*buf)[idx]);

        free(*buf);
 fail_entries:
        pthread_rwlock_unlock(&dt.lock);
        return -ENOMEM;
}

static int dt_rib_getattr(const char *      path,
                          struct rib_attr * attr)
{
        int    fd;
        char * entry;
        time_t stamp;

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        fd = atoi(entry);

        stamp = LOAD_ACQUIRE(&dt.stat[fd].stamp);

        if (stamp != -1) {
                attr->size  = RIB_FILE_STRLEN;
                attr->mtime = stamp;
        } else {
                attr->size  = 0;
                attr->mtime = 0;
        }

        return 0;
}

static struct rib_ops r_ops = {
        .read    = dt_rib_read,
        .readdir = dt_rib_readdir,
        .getattr = dt_rib_getattr
};

static void stat_used(int      fd,
                      uint64_t addr)
{
        struct timespec now;
        int             i;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_wrlock(&dt.lock);

        STORE_RELEASE(&dt.stat[fd].stamp, 0);

        /* Don't memset: incremented without locks in fast path. */
        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                STORE_RELAXED(&dt.stat[fd].snd_pkt[i], 0);
                STORE_RELAXED(&dt.stat[fd].snd_bytes[i], 0);
                STORE_RELAXED(&dt.stat[fd].rcv_pkt[i], 0);
                STORE_RELAXED(&dt.stat[fd].rcv_bytes[i], 0);
                STORE_RELAXED(&dt.stat[fd].lcl_r_pkt[i], 0);
                STORE_RELAXED(&dt.stat[fd].lcl_r_bytes[i], 0);
                STORE_RELAXED(&dt.stat[fd].lcl_w_pkt[i], 0);
                STORE_RELAXED(&dt.stat[fd].lcl_w_bytes[i], 0);
                STORE_RELAXED(&dt.stat[fd].r_drp_pkt[i], 0);
                STORE_RELAXED(&dt.stat[fd].r_drp_bytes[i], 0);
                STORE_RELAXED(&dt.stat[fd].w_drp_pkt[i], 0);
                STORE_RELAXED(&dt.stat[fd].w_drp_bytes[i], 0);
                STORE_RELAXED(&dt.stat[fd].f_nhp_pkt[i], 0);
                STORE_RELAXED(&dt.stat[fd].f_nhp_bytes[i], 0);
        }

        STORE_RELAXED(&dt.stat[fd].addr, addr);

        if (addr != INVALID_ADDR) {
                STORE_RELEASE(&dt.stat[fd].stamp, now.tv_sec);
                ++dt.n_flows;
        } else {
                --dt.n_flows;
        }

        pthread_rwlock_unlock(&dt.lock);
}
#else
#define dt_stat_inc(idx, name, qc, len) ((void) 0)
#endif

static void handle_event(void *       self,
                         int          event,
                         const void * o)
{
        struct conn * c;
        int           fd;

        (void) self;

        c = (struct conn *) o;

        switch (event) {
        case NOTIFY_DT_CONN_ADD:
                fd = c->flow_info.fd;
#ifdef IPCP_FLOW_STATS
                stat_used(fd, c->conn_info.addr);
#endif
                if (ipcp_flow_cap_arm(fd) < 0)
                        log_warn("Failed to arm capacity estimator.");
                psched_add(dt.psched, fd);
                log_dbg("Added fd %d to packet scheduler.", fd);
                break;
        case NOTIFY_DT_CONN_DEL:
                fd = c->flow_info.fd;
#ifdef IPCP_FLOW_STATS
                stat_used(fd, INVALID_ADDR);
#endif
                psched_del(dt.psched, fd);
                log_dbg("Removed fd %d from packet scheduler.", fd);
                break;
        default:
                break;
        }
}

static time_t packet_handler(int                  fd,
                             qoscube_t            qc,
                             struct ssm_pk_buff * spb)
{
        struct dt_pci dt_pci;
        int           ret;
        int           ofd;
        uint8_t *     head;
        size_t        len;
        size_t        qlen;
        size_t        mlen;
        uint8_t       lcap;
        bool          marks;

        len = ssm_pk_buff_len(spb);

#ifndef IPCP_FLOW_STATS
        (void) fd;
#endif
        dt_stat_inc(fd, rcv, qc, len);

        memset(&dt_pci, 0, sizeof(dt_pci));

        head = ssm_pk_buff_head(spb);

        dt_pci_des(head, &dt_pci);
        if (dt_pci.dst_addr != dt.addr) {
                /* A non-transit IPCP only sources and sinks packets. */
                if (!(ipcp_get_flags() & IPCP_FLAG_TRANSIT)) {
                        log_dbg("Dropped transit packet: non-transit.");
                        ipcp_spb_release(spb);
                        dt_stat_inc(fd, r_drp, qc, len);
                        return 0;
                }

                if (dt_pci.ttl == 0) {
                        log_dbg("TTL was zero.");
                        ipcp_spb_release(spb);
                        dt_stat_inc(fd, r_drp, qc, len);
                        return 0;
                }

                /* FIXME: Use qoscube from PCI instead of incoming flow. */
                ofd = pff_nhop(dt.pff[qc], dt_pci.dst_addr);
                if (ofd < 0) {
                        log_dbg("No next hop for %" PRIu64 ".",
                                dt_pci.dst_addr);
                        ipcp_spb_release(spb);
                        dt_stat_inc(fd, f_nhp, qc, len);
                        return 0;
                }

                marks = ca_marks_ecn();
                qlen  = marks ? ipcp_flow_queued(ofd) : 0;
                mlen  = marks ? ipcp_flow_mean_len(ofd) : 0;
                lcap  = marks ? cap_enc(ipcp_flow_cap(ofd)) : 0;

                (void) ca_calc_ecn(qlen, head + dt_pci_info.ecn_o, qc, mlen);

                if (marks)
                        cap_stamp(head + dt_pci_info.cap_o, lcap);

                ret = ipcp_flow_write(ofd, spb);
                if (ret < 0) {
                        log_dbg("Failed to write packet to fd %d.", ofd);
                        if (ret == -EFLOWDOWN)
                                notifier_event(NOTIFY_DT_FLOW_DOWN, &ofd);
                        ipcp_spb_release(spb);
                        dt_stat_inc(ofd, w_drp, qc, len);
                        return 0;
                }

                dt_stat_inc(ofd, snd, qc, len);

                if (marks)
                        ipcp_flow_cap_update(ofd, qlen, len);
        } else {
                dt_pci_shrink(spb);
                if (dt_pci.eid >= PROC_RES_FDS) {
                        uint8_t ecn = *(head + dt_pci_info.ecn_o);
                        uint8_t cap = *(head + dt_pci_info.cap_o);
                        fa_np1_rcv(dt_pci.eid, ecn, cap, spb);
                        return 0;
                }

                if (dt.comps[dt_pci.eid].post_packet == NULL) {
                        log_err("No registered component on eid %" PRIu64 ".",
                                dt_pci.eid);
                        ipcp_spb_release(spb);
                        return 0;
                }
                dt_stat_inc(fd, lcl_r, qc, len);
                dt_stat_inc(dt_pci.eid, snd, qc, len);

                dt.comps[dt_pci.eid].post_packet(dt.comps[dt_pci.eid].comp,
                                                 spb);
        }

        return 0;
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

int dt_init(struct dt_config cfg)
{
        int              i;
        int              j;
#ifdef IPCP_FLOW_STATS
        char             dtstr[RIB_NAME_STRLEN + 1];
#endif
        enum pol_pff     pp;
        struct conn_info info;

        memset(&info, 0, sizeof(info));

        dt.addr = addr_auth_address();
        if (dt.addr == INVALID_ADDR) {
                log_err("Failed to get address");
                return -1;
        }

        strcpy(info.comp_name, DT_COMP);
        strcpy(info.protocol, DT_PROTO);
        info.pref_version = 1;
        info.pref_syntax  = PROTO_FIXED;
        info.addr         = dt.addr;

        if (cfg.eid_size != 8) { /* only support 64 bits from now */
                log_warn("Invalid EID size. Only 64 bit is supported.");
                cfg.eid_size = 8;
        }

        dt_pci_info.addr_size = cfg.addr_size;
        dt_pci_info.eid_size  = cfg.eid_size;
        dt_pci_info.max_ttl   = cfg.max_ttl;

        dt_pci_info.qc_o      = dt_pci_info.addr_size;
        dt_pci_info.ttl_o     = dt_pci_info.qc_o + QOS_LEN;
        dt_pci_info.ecn_o     = dt_pci_info.ttl_o + TTL_LEN;
        dt_pci_info.cap_o     = dt_pci_info.ecn_o + ECN_LEN;
        dt_pci_info.eid_o     = dt_pci_info.cap_o + CAP_LEN;
        dt_pci_info.head_size = dt_pci_info.eid_o + dt_pci_info.eid_size;

        if (connmgr_comp_init(COMPID_DT, &info) != 0) {
                log_err("Failed to register with connmgr.");
                goto fail_connmgr_comp_init;
        }

        if (routing_init(&cfg.routing, &pp) < 0) {
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

        dt.res_fds = bmp_create(PROC_RES_FDS, 0);
        if (dt.res_fds == NULL)
                goto fail_res_fds;
#ifdef IPCP_FLOW_STATS
        memset(dt.stat, 0, sizeof(dt.stat));

        dt.n_flows = 0;

        sprintf(dtstr, "%s." ADDR_FMT32, DT, ADDR_VAL32(&dt.addr));
        if (rib_reg(dtstr, &r_ops)) {
                log_err("Failed to register RIB.");
                goto fail_rib_reg;
        }
#endif

        return 0;

#ifdef IPCP_FLOW_STATS
 fail_rib_reg:
        bmp_destroy(dt.res_fds);
#endif
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
        return -1;
}

void dt_fini(void)
{
#ifdef IPCP_FLOW_STATS
        char dtstr[RIB_NAME_STRLEN + 1];
#endif
        int i;

#ifdef IPCP_FLOW_STATS
        sprintf(dtstr, "%s.%" PRIu64, DT, dt.addr);
        rib_unreg(dtstr);
#endif
        bmp_destroy(dt.res_fds);

        pthread_rwlock_destroy(&dt.lock);

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                routing_i_destroy(dt.routing[i]);

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                pff_destroy(dt.pff[i]);

        routing_fini();

        connmgr_comp_fini(COMPID_DT);
}

int dt_start(void)
{
        dt.psched = psched_create(packet_handler, ipcp_flow_read);
        if (dt.psched == NULL) {
                log_err("Failed to create N-1 packet scheduler.");
                goto fail_psched;
        }

        if (notifier_reg(handle_event, NULL)) {
                log_err("Failed to register with notifier.");
                goto fail_notifier_reg;
        }

        if (pthread_create(&dt.listener, NULL, dt_conn_handle, NULL)) {
                log_err("Failed to create listener thread.");
                goto fail_listener;
        }

        if (routing_start() < 0) {
                log_err("Failed to start routing.");
                goto fail_routing;
        }

        return 0;

 fail_routing:
        pthread_cancel(dt.listener);
        pthread_join(dt.listener, NULL);
 fail_listener:
        notifier_unreg(&handle_event);
 fail_notifier_reg:
        psched_destroy(dt.psched);
 fail_psched:
        return -1;
}

void dt_stop(void)
{
        routing_stop();

        pthread_cancel(dt.listener);
        pthread_join(dt.listener, NULL);

        notifier_unreg(&handle_event);

        psched_destroy(dt.psched);
}

int dt_reg_comp(void * comp,
                void (* func)(void * func, struct ssm_pk_buff *),
                char * name)
{
        int eid;

        assert(func != NULL);

        pthread_rwlock_wrlock(&dt.lock);

        eid = bmp_allocate(dt.res_fds);
        if (!bmp_is_id_valid(dt.res_fds, eid)) {
                log_err("Cannot allocate EID.");
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
        stat_used(eid, dt.addr);
#endif
        return eid;
}

void dt_unreg_comp(int eid)
{
        assert(eid >= 0 && eid < PROC_RES_FDS);

        pthread_rwlock_wrlock(&dt.lock);

        assert(dt.comps[eid].post_packet != NULL);

        dt.comps[eid].post_packet = NULL;
        dt.comps[eid].comp        = NULL;
        dt.comps[eid].name        = NULL;

        pthread_rwlock_unlock(&dt.lock);

        return;
}

int dt_write_packet(uint64_t             dst_addr,
                    qoscube_t            qc,
                    uint64_t             eid,
                    struct ssm_pk_buff * spb,
                    uint8_t *            ecn)
{
        struct dt_pci dt_pci;
        int           fd;
        int           ret;
        uint8_t *     head;
        size_t        len;
        size_t        qlen;
        size_t        mlen;
        uint8_t       lcap;
        bool          marks;

        assert(spb);
        assert(dst_addr != dt.addr);

#ifdef IPCP_FLOW_STATS
        len = ssm_pk_buff_len(spb);

        if (eid < PROC_RES_FDS)
                dt_stat_inc(eid, lcl_r, qc, len);
#endif
        fd = pff_nhop(dt.pff[qc], dst_addr);
        if (fd < 0) {
                log_dbg("Could not get nhop for " ADDR_FMT32 ".",
                        ADDR_VAL32(&dst_addr));
#ifdef IPCP_FLOW_STATS
                if (eid < PROC_RES_FDS)
                        dt_stat_inc(eid, lcl_r, qc, len);
#endif
                return -EPERM;
        }

        head = ssm_pk_buff_push(spb, dt_pci_info.head_size);
        if (head == NULL) {
                log_dbg("Failed to allocate DT header.");
                goto fail_write;
        }

        len = ssm_pk_buff_len(spb);

        dt_pci.dst_addr = dst_addr;
        dt_pci.qc       = qc;
        dt_pci.eid      = eid;
        dt_pci.ecn      = 0;
        dt_pci.cap      = 0;

        marks = ca_marks_ecn();
        qlen  = marks ? ipcp_flow_queued(fd) : 0;
        mlen  = marks ? ipcp_flow_mean_len(fd) : 0;
        lcap  = marks ? cap_enc(ipcp_flow_cap(fd)) : 0;

        (void) ca_calc_ecn(qlen, &dt_pci.ecn, qc, mlen);

        dt_pci.cap = lcap;

        if (ecn != NULL)
                *ecn = dt_pci.ecn;

        dt_pci_ser(head, &dt_pci);

        ret = ipcp_flow_write(fd, spb);
        if (ret < 0) {
                log_dbg("Failed to write packet to fd %d: %d.", fd, ret);
                if (ret == -EFLOWDOWN)
                        notifier_event(NOTIFY_DT_FLOW_DOWN, &fd);
                goto fail_write;
        }
#ifdef IPCP_FLOW_STATS
        if (dt_pci.eid < PROC_RES_FDS)
                dt_stat_inc(fd, lcl_w, qc, len);

        dt_stat_inc(fd, snd, qc, len);
#endif
        if (marks)
                ipcp_flow_cap_update(fd, qlen, len);

        return 0;

 fail_write:
#ifdef IPCP_FLOW_STATS
        if (eid < PROC_RES_FDS)
                dt_stat_inc(fd, lcl_w, qc, len);

        dt_stat_inc(fd, w_drp, qc, len);
#endif
        return -1;
}
