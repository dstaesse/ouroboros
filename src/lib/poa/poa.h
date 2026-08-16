/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Points of attachment (PoA) - internal API
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_POA_POA_H
#define OUROBOROS_LIB_POA_POA_H

#include <ouroboros/atomics.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/list.h>
#include <ouroboros/qos.h>
#include <ouroboros/rcu.h>
#include <ouroboros/ssm_flow_set.h>
#include <ouroboros/ssm_pool.h>
#include <ouroboros/ssm_rbuff.h>
#include <ouroboros/time.h>
#include <ouroboros/utils.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#define POA_MGMT_EID     0  /* reserved for the mgmt channel */

#define POA_FLOW_REQ     1
#define POA_FLOW_REPLY   2
#define POA_FLOW_UPDATE  3
#define POA_NAME_QUERY   4
#define POA_NAME_REPLY   5

#define POA_QUERY_HLEN   32 /* SHA3-256, the query hash algorithm */

/* Fits "udp6.<ip6>.<port>", the longest display/RIB entry name. */
#define POA_NAME_STRLEN  63

/* Management message; every transport frames it the same way. */
struct poa_mgmt_msg {
        uint8_t  code;
        uint8_t  resv[3];
        uint32_t s_eid;
        uint32_t d_eid;
        int32_t  response;
        uint64_t bandwidth;
        uint32_t delay;
        uint32_t loss;
        uint32_t ber;
        uint32_t max_gap;
        uint32_t timeout;
        uint8_t  availability;
        uint8_t  service;
        uint16_t data_len;
} __attribute__((packed));

struct poa;
struct poa_flow;

#ifdef PROC_FLOW_STATS
#define POA_STAT_BUMP(poa, field)   FETCH_ADD_RELAXED(&(poa)->stat.field, 1)
#define POA_STAT_ADD(poa, field, v) FETCH_ADD_RELAXED(&(poa)->stat.field, (v))
#define POA_STAT_SUB(poa, field, v) FETCH_SUB_RELAXED(&(poa)->stat.field, (v))
#define POA_STAT_LOAD(poa, field)   LOAD_RELAXED(&(poa)->stat.field)
#else
#define POA_STAT_BUMP(poa, field)   ((void) (poa))
#define POA_STAT_ADD(poa, field, v) ((void) (poa), (void) (v))
#define POA_STAT_SUB(poa, field, v) ((void) (poa), (void) (v))
#define POA_STAT_LOAD(poa, field)   ((void) (poa), (size_t) 0)
#endif

struct poa_stat {
        size_t n_flows;  /* gauge; the RIB reads it without poas.lock */
        size_t rx_pkts;  /* packets delivered to a flow               */
        size_t rx_bytes; /* payload bytes delivered                   */
        size_t tx_pkts;  /* packets handed to the transport           */
        size_t tx_bytes; /* payload bytes handed to the transport     */
        size_t mgmt_rx;  /* frames queued for the mgmt handler        */
        size_t mgmt_tx;  /* management frames sent                    */
        size_t bad_eid;  /* no flow on the EID a peer sent            */
        size_t dlv_fail; /* the rx ring above would not take it       */
        size_t buf_fail; /* no buffer to receive into                 */
        size_t rcv_fail; /* transport read failed; the reader exits   */
        size_t snd_fail; /* transport send failed                     */
        size_t qry_tx;   /* name queries broadcast                    */
        size_t qry_rx;   /* name queries received                     */
        size_t rep_tx;   /* name replies sent, query matched          */
        size_t rep_rx;   /* name replies received                     */
};

/* Spacing between transmit-depth samples; a depth costs a syscall. */
#define POA_QLEN_GATE   (100 * 1000) /* ns */


/* Transport operations; public poa_X() dispatches to ops->poa_X. */
struct poa_ops {
        /* Parse own arm of the spec; validate; fill local and priv. */
        int      (* poa_attach)(struct poa *            poa,
                                const struct poa_spec * spec);

        void     (* poa_detach)(struct poa * poa);

        int      (* poa_start)(struct poa * poa);

        void     (* poa_stop)(struct poa * poa);

        /* Full queue: -EAGAIN unless block; then wait, to abstime if set. */
        int      (* poa_send)(struct poa *            poa,
                              const struct poa_addr * dst,
                              uint32_t                eid,
                              struct ssm_pk_buff *    spb,
                              bool                    block,
                              const struct timespec * abstime);

        int      (* poa_send_mgmt)(struct poa *            poa,
                                   const struct poa_addr * dst,
                                   const uint8_t *         buf,
                                   size_t                  len);

        int      (* poa_query)(const char *            dst,
                               const struct timespec * timeo,
                               struct poa_addr *       addr);

        uint32_t (* poa_mtu)(struct poa *            poa,
                             const struct poa_addr * dst);

        /* Bytes queued in the transmit path of the PoA. */
        size_t   (* poa_qlen)(struct poa * poa);

        /* Depth from the queue itself; NULL infers it from qlen. */
        int      (* poa_qpkts)(struct poa * poa,
                               size_t *     pkts,
                               size_t *     byts);

        int      (* poa_rib)(struct poa * poa,
                             char *       buf,
                             size_t       len);

        /* Identity as a spec, e.g. for poa_list. */
        void     (* poa_spec)(const struct poa * poa,
                              struct poa_spec *  spec);

        /* Same identity as spec? Caller matched poa->type already. */
        bool     (* poa_has_id)(const struct poa *      poa,
                                const struct poa_spec * spec);

        /* Carries dst? Caller matched poa->type already. */
        bool     (* poa_match)(const struct poa *      poa,
                               const struct poa_addr * dst);

        /*
         * Flows ride the link this id names; NULL: no link events.
         * Ids are meaningful only to the backend whose monitor
         * produced them; a single backend owns the monitor.
         */
        bool     (* poa_link_match)(const struct poa * poa,
                                    int                id);

        /* Maximum packet lifetime in the transport, seconds. */
        time_t   mpl;
};
struct poa {
        struct list_head       next;

        enum poa_type          type;
        const struct poa_ops * ops;
        void *                 priv;

        struct poa_addr        local;   /* what peers dial us on */

        /* Display/RIB entry name for local, e.g. "udp4.<ip>.<port>". */
        char                   name[POA_NAME_STRLEN + 1];

        time_t                 mpl;

        /* Identifies the transmit queue the flows on this PoA share. */
        int                    qid;

        /* Mean sent packet size (bytes), EWMA over the send path. */
        size_t                 avg_len;
        /* Cost of one packet in the queue, in the transport's terms. */
        size_t                 avg_ovh;
        size_t                 n_tx;

        /* Last queue depth read, and when, in the transport's terms. */
        size_t                 q_cache;
        uint64_t               q_time;

        /* Queued management frames, capped; poas.mgmt_mtx guards. */
        size_t                 n_mgmt;

#ifdef PROC_FLOW_STATS
        struct poa_stat        stat;
#endif

        struct bmp *           eids;
        struct poa_flow **     eid_to_pf;
        size_t                 n_eids;

        struct list_head       flows;     /* live flows, for repeats */

        /* Keeps a flow and its ring alive under the receive path. */
        struct rcu_guard       guard;
};

/* poa/poa.c is part of the dev.c translation unit. */
int               poa_init(const char * name);

int               poa_start(void);

void              poa_stop(void);

void              poa_fini(void);

/* Also answer name queries for the layer once enrolled. */
int               poa_set_layer(const char * layer);

/* Hash of a name this process answers queries for? */
bool              poa_has_name(const uint8_t * hash);

int               poa_flow_tx(struct poa_flow *       pf,
                              struct ssm_pk_buff *    spb,
                              bool                    block,
                              const struct timespec * abstime);

size_t            poa_flow_qlen(const struct poa_flow * pf);

size_t            poa_flow_qpkts(const struct poa_flow * pf);

int               poa_flow_qid(const struct poa_flow * pf);

size_t            poa_flow_mean_len(const struct poa_flow * pf);

void              poa_flow_attach(struct poa_flow *  pf,
                                  int                flow_id,
                                  struct ssm_rbuff * rx_rb);

void              poa_flow_ready(struct poa_flow * pf);

void              poa_flow_detach(struct poa_flow * pf);

struct poa_flow * poa_flow_take_pending(int flow_id);

/* Addresses and management messages (poa/addr.c). */
int               poa_addr_cmp(const struct poa_addr * a,
                               const struct poa_addr * b);

/* Display/RIB entry name, e.g. "udp4.<ip>.<port>". */
int               poa_addr_name(const struct poa_addr * a,
                                char *                  buf,
                                size_t                  len);

void              poa_mgmt_msg_ser(struct poa_mgmt_msg * msg,
                                   uint8_t               code,
                                   uint32_t              s_eid,
                                   uint32_t              d_eid,
                                   qosspec_t             qs,
                                   int                   response,
                                   size_t                data_len);

void              poa_mgmt_msg_qos(const struct poa_mgmt_msg * msg,
                                   qosspec_t *                 qs);

/* Called by the transports. */
void              poa_rx_pkt(struct poa *         poa,
                             uint32_t             eid,
                             struct ssm_pk_buff * spb);

void              poa_rx_mgmt(struct poa *            poa,
                              const struct poa_addr * src,
                              const uint8_t *         buf,
                              size_t                  len);

/* Reserve a buffer for a received packet, with transport headroom. */
int               poa_spb_reserve(struct ssm_pk_buff ** spb,
                                  size_t                len);

void              poa_spb_release(struct ssm_pk_buff * spb);

/*
 * All flows on PoAs whose poa_link_match reports this link id go up
 * or down with it. Returns the number of flows whose state changed.
 */
size_t            poa_link_updown(int  id,
                                  bool up);

/*
 * Link monitor: one socket for the whole subsystem, opened by
 * poa_start(). Returns -1 where the transport has no monitor.
 */
int               poa_monitor_open(void);

/* Reads one batch of link events; cancellation point. */
void              poa_monitor_read(int fd);

/* Broadcast a mgmt frame on every PoA matching dst; # sent. */
int               poa_bcast_mgmt(const struct poa_addr * dst,
                                 const uint8_t *         buf,
                                 size_t                  len);

/* Transport op tables. */
extern const struct poa_ops udp_poa_ops;
extern const struct poa_ops eth_poa_ops;

/*
 * Waits for a descriptor to take another packet, up to abstime.
 * A NULL deadline waits indefinitely. Transports call this when
 * their send reports the transmit queue full.
 */
static __inline__ int poa_wait_out(int                     fd,
                                   const struct timespec * abstime)
{
        struct pollfd   pfd;
        struct timespec now;
        long            ms      = -1;
        bool            clamped = false;
        int             ret;

        if (abstime != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &now);

                if (ts_diff_ns(abstime, &now) <= 0)
                        return -ETIMEDOUT;

                ms = ts_diff_ms(abstime, &now) + 1; /* sub-ms must wait */
                if (ms > INT_MAX) { /* poll takes an int */
                        ms      = INT_MAX;
                        clamped = true;
                }
        }

        pfd.fd      = fd;
        pfd.events  = POLLOUT;
        pfd.revents = 0;

        ret = poll(&pfd, 1, (int) ms);
        if (ret < 0)
                return errno == EINTR ? 0 : -EIO;

        if (ret == 0)
                return clamped ? 0 : -ETIMEDOUT; /* clamped: retry */

        return 0;
}

#endif /* OUROBOROS_LIB_POA_POA_H */
