/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Points of attachment (PoA) - transport independent core
 *
 * Included by dev.c; uses dev.c statics (proc, flow_init, ...).
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

#define POA_MAX_EIDS     PROC_MAX_FLOWS
#define POA_ALLOC_TIMEO  10000 /* ms, overall FLOW_REQ deadline  */
#define POA_RETRY_TIMEO  300   /* ms, FLOW_REQ retransmit period */
/* Must fit a certificate chain: post-quantum ones are large. */
#define POA_MGMT_BUFSZ   POA_MGMT_FRAME_SIZE
#define POA_MGMT_QMAX    64   /* queued management frames per PoA */
#define POA_PEND_TIMEO   10   /* s, reap a request that never completes */
#define POA_SWEEP_TIMEO  1000 /* ms, sweep interval */
#define POA_SWEEP_MAX    16   /* requests reaped per sweep */
#define POA_DEFER_MAX    64   /* replies waiting for their flow id */

/* EWMA over 8 samples. */
#define POA_AVG_SHIFT    3
/* Queue cost is sampled every 64th packet: qlen is a syscall. */
#define POA_COST_MASK    63
/* Reuse a qlen read for this long; the mark moves on doublings. */

#define POA_RIB          "poa"
/* Fits the RIB labels below with 20-digit counters. */
#define POA_RIB_STRLEN   2048

enum poa_flow_state {
        POA_FLOW_NULL = 0,
        POA_FLOW_PENDING,
        POA_FLOW_ALLOCATED,
        POA_FLOW_DEAD
};

enum poa_state {
        POA_NULL = 0,
        POA_INIT,        /* poa_init(); this process may attach   */
        POA_RUNNING,     /* the threads are up                    */
        POA_OPERATIONAL  /* bootstrapped or enrolled in a layer   */
};

struct poa_flow {
        struct poa *        poa;

        int                 flow_id;
        uint32_t            eid;
        uint32_t            r_eid;
        struct poa_addr     r_addr;

        enum poa_flow_state state;

        struct ssm_rbuff *  rx_rb;

        struct list_head    pend;     /* on poa->pending while unanswered */
        struct timespec     t0;

        /* Our answer, kept to re-send when a request is repeated. */
        bool                answered;
        bool                answer_sent;

        /* Handed to a caller that will attach it; not the sweeper's. */
        bool                claimed;
        int                 answer;
        buffer_t            answer_data;

        /* Handshake rendezvous with the reader thread. */
        pthread_mutex_t     mtx;
        pthread_cond_t      cond;
        bool                replied;
        bool                pending;
        int                 response;
        buffer_t            resp_data;
};

/*
 * An answer can be ready before the flow it answers has an id, and
 * the caller must not be kept waiting for one: it answers to the IRMd,
 * which gives up long before we would.
 */
struct poa_deferred {
        struct list_head next;
        struct timespec  t0;
        int              flow_id;
        int              response;
        buffer_t         data;
};

struct poa_mgmt_frame {
        struct list_head next;
        struct poa *     poa;
        struct poa_addr  src;
        size_t           len;
        uint8_t          buf[POA_MGMT_BUFSZ];
};

/*
 * A detach is performed by the management thread, so that it cannot
 * run alongside the accept side. The caller waits for the result.
 */
struct poa_detach_req {
        struct list_head next;
        struct poa_spec  spec;
        int              result;
        bool             done;
};

static struct {
        struct list_head  list;

        struct poa_flow * id_to_pf[SYS_MAX_FLOWS];

        struct llist      deferred;

        pthread_mutex_t   mtx;   /* guards id_to_pf  */
        pthread_cond_t    cond;

        /* One management thread and one link monitor for all PoAs. */
        struct llist      mgmt_frames;
        struct list_head  detach;
        pthread_mutex_t   mgmt_mtx;
        pthread_cond_t    mgmt_cond; /* work for the handler   */
        pthread_cond_t    done_cond; /* a detach has completed */
        pthread_t         mgmt_handler;
        bool              mgmt_stop;

        pthread_t         monitor;
        int               mon_fd;

        enum poa_state    state;

        /* Hashes of the names this process answers queries for. */
        uint8_t           name_hash[POA_QUERY_HLEN];
        uint8_t           layer_hash[POA_QUERY_HLEN];

        pthread_rwlock_t  lock;  /* the PoAs and their flows */
} poas;

static int mgmt_send(struct poa *            poa,
                     const struct poa_addr * dst,
                     uint8_t                 code,
                     uint32_t                s_eid,
                     uint32_t                d_eid,
                     qosspec_t               qs,
                     int                     response,
                     const buffer_t *        data)
{
        uint8_t               buf[POA_MGMT_BUFSZ];
        struct poa_mgmt_msg * msg = (struct poa_mgmt_msg *) buf;
        size_t                len;

        len = sizeof(*msg);
        if (data != NULL && data->len > 0) {
                if (len + data->len > sizeof(buf))
                        return -EMSGSIZE;
                memcpy(buf + len, data->data, data->len);

                len += data->len;
        }

        poa_mgmt_msg_ser(msg, code, s_eid, d_eid, qs, response,
                         data != NULL ? data->len : 0);

        POA_STAT_BUMP(poa, mgmt_tx);

        return poa->ops->poa_send_mgmt(poa, dst, buf, len);
}

/* Caller holds poas.lock for writing. */
static struct poa_flow * pf_create(struct poa *            poa,
                                   const struct poa_addr * r_addr)
{
        struct poa_flow *  pf;
        pthread_condattr_t cattr;
        int                eid;

        pf = malloc(sizeof(*pf));
        if (pf == NULL)
                goto fail_malloc;

        memset(pf, 0, sizeof(*pf));

        if (pthread_mutex_init(&pf->mtx, NULL) != 0)
                goto fail_mtx;

        if (pthread_condattr_init(&cattr) != 0)
                goto fail_cond;
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&pf->cond, &cattr) != 0) {
                pthread_condattr_destroy(&cattr);
                goto fail_cond;
        }

        pthread_condattr_destroy(&cattr);

        eid = bmp_allocate(poa->eids);
        if (!bmp_is_id_valid(poa->eids, eid))
                goto fail_eid;

        pf->poa     = poa;
        pf->eid     = (uint32_t) eid;
        pf->flow_id = -1;
        pf->state   = POA_FLOW_PENDING;
        pf->r_addr  = *r_addr;

        clock_gettime(PTHREAD_COND_CLOCK, &pf->t0);

        rcu_wrlock(&poa->guard);

        rcu_publish(pf);
        rcu_assign(poa->eid_to_pf[eid], pf);

        rcu_wrunlock(&poa->guard);

        list_add_tail(&pf->pend, &poa->flows);

        POA_STAT_BUMP(poa, n_flows);

        return pf;

 fail_eid:
        pthread_cond_destroy(&pf->cond);
 fail_cond:
        pthread_mutex_destroy(&pf->mtx);
 fail_mtx:
        free(pf);
 fail_malloc:
        return NULL;
}

/* Caller holds poas.mtx. */
static void deferred_purge(int flow_id)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &poas.deferred.list) {
                struct poa_deferred * d;

                d = list_entry(p, struct poa_deferred, next);
                if (d->flow_id != flow_id)
                        continue;

                llist_del(&d->next, &poas.deferred);
                freebuf(d->data);
                free(d);
        }
}

/* The id may have moved to a newer flow; only its owner clears it. */
static void pf_destroy(struct poa_flow * pf)
{
        struct poa * poa = pf->poa;

        pthread_rwlock_wrlock(&poas.lock);

        rcu_wrlock(&poa->guard);

        rcu_assign(poa->eid_to_pf[pf->eid], NULL);
        rcu_assign(pf->rx_rb, NULL);

        rcu_wrunlock(&poa->guard);

        bmp_release(poa->eids, pf->eid);

        if (!list_is_empty(&pf->pend)) {
                list_del(&pf->pend);
                POA_STAT_SUB(poa, n_flows, 1);
        }

        pthread_rwlock_unlock(&poas.lock);

        pthread_mutex_lock(&poas.mtx);

        if (pf->flow_id >= 0 && poas.id_to_pf[pf->flow_id] == pf) {
                poas.id_to_pf[pf->flow_id] = NULL;

                deferred_purge(pf->flow_id);
        }

        pthread_mutex_unlock(&poas.mtx);

        rcu_reclaim(&poa->guard); /* a receive may still hold pf */

        freebuf(pf->resp_data);
        freebuf(pf->answer_data);

        pthread_cond_destroy(&pf->cond);
        pthread_mutex_destroy(&pf->mtx);

        free(pf);
}

/*
 * Keeps the answer for a repeat, then sends it. An accept must wait
 * until the flow can receive; a refusal needs no receiver.
 */
static int pf_answer(struct poa_flow * pf,
                     int               response,
                     const buffer_t *  data)
{
        int err;

        pthread_rwlock_wrlock(&poas.lock);

        freebuf(pf->answer_data);

        if (data != NULL && data->len > 0) {
                pf->answer_data.data = malloc(data->len);
                if (pf->answer_data.data != NULL) {
                        memcpy(pf->answer_data.data, data->data, data->len);

                        pf->answer_data.len = data->len;
                }
        }

        pf->answer   = response;
        pf->answered = true;
        if (response == 0 && pf->state != POA_FLOW_ALLOCATED) {
                pthread_rwlock_unlock(&poas.lock);
                return 0;
        }

        pf->answer_sent = true;

        pthread_rwlock_unlock(&poas.lock);

        err = mgmt_send(pf->poa, &pf->r_addr, POA_FLOW_REPLY, pf->eid,
                        pf->r_eid, qos_raw, response, data);

        if (err == -ETIMEDOUT || err == -EAGAIN)
                err = 0; /* stored; a repeat request resends it */

        return err;
}

/* Takes an answer left for a flow that had no id yet. */
static struct poa_deferred * deferred_take(int flow_id)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &poas.deferred.list) {
                struct poa_deferred * d;

                d = list_entry(p, struct poa_deferred, next);
                if (d->flow_id != flow_id)
                        continue;

                llist_del(&d->next, &poas.deferred);

                return d;
        }

        return NULL;
}

/* Publishes the flow_id so an answer can find this flow. */
static void pf_set_flow_id(struct poa_flow * pf,
                           int               flow_id)
{
        struct poa_deferred * d;

        pthread_mutex_lock(&poas.mtx);

        pf->flow_id          = flow_id;
        poas.id_to_pf[flow_id] = pf;

        d = deferred_take(flow_id);

        pthread_cond_broadcast(&poas.cond);

        pthread_mutex_unlock(&poas.mtx);

        if (d != NULL) {
                pf_answer(pf, d->response, &d->data);
                freebuf(d->data);
                free(d);
        }
}

/*
 * Between the request arriving and the accept returning, the flow has
 * an id but no fd yet; flow_init claims the PoA here.
 */
static void pf_set_pending(struct poa_flow * pf)
{
        pthread_mutex_lock(&poas.mtx);

        pf->pending = true;

        pthread_mutex_unlock(&poas.mtx);
}

static void pf_clr_pending(struct poa_flow * pf)
{
        pthread_mutex_lock(&poas.mtx);

        pf->pending = false;

        pthread_mutex_unlock(&poas.mtx);
}

/* A process that attaches no PoA has nothing pending. */
struct poa_flow * poa_flow_take_pending(int flow_id)
{
        struct poa_flow * pf;

        if (poas.state == POA_NULL)
                return NULL;

        if (flow_id < 0 || flow_id >= SYS_MAX_FLOWS)
                return NULL;

        pthread_mutex_lock(&poas.mtx);

        pf = poas.id_to_pf[flow_id];
        if (pf != NULL && pf->pending)
                pf->pending = false;
        else
                pf = NULL;

        pthread_mutex_unlock(&poas.mtx);

        return pf;
}

static struct poa_flow * pf_get(int flow_id)
{
        struct poa_flow * pf;

        if (flow_id < 0 || flow_id >= SYS_MAX_FLOWS)
                return NULL;

        pthread_mutex_lock(&poas.mtx);

        pf = poas.id_to_pf[flow_id];

        pthread_mutex_unlock(&poas.mtx);

        return pf;
}

#ifdef PROC_FLOW_STATS

/* Caller holds poas.lock. */
static struct poa * poa_by_rib_name(const char * name)
{
        struct list_head * p;

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (strcmp(poa->name, name) == 0)
                        return poa;
        }

        return NULL;
}

static int poa_rib_read(const char * path,
                        char *       buf,
                        size_t       len)
{
        struct poa * poa;
        const char * entry;
        size_t       qlen;
        size_t       avg;
        size_t       cost;
        int          size;
        int          ret;

        entry = strstr(path, RIB_SEPARATOR) + 1;

        if (len < POA_RIB_STRLEN)
                return -1;

        pthread_rwlock_rdlock(&poas.lock);

        poa = poa_by_rib_name(entry);
        if (poa == NULL)
                goto fail;

        qlen = poa->ops->poa_qlen(poa);
        avg  = poa->avg_len;
        cost = poa->avg_len + poa->avg_ovh;

        size = snprintf(buf, len,
                        "Active flows:              %zu\n"
                        "Packets received:          %zu\n"
                        "Bytes received:            %zu\n"
                        "Packets sent:              %zu\n"
                        "Bytes sent:                %zu\n"
                        "Management frames rcvd:    %zu\n"
                        "Management frames sent:    %zu\n"
                        "Bad EID packets:           %zu\n"
                        "Delivery (N+1) failures:   %zu\n"
                        "Buffer alloc failures:     %zu\n"
                        "Packet read failures:      %zu\n"
                        "Packet send failures:      %zu\n"
                        "Name queries sent:         %zu\n"
                        "Name queries received:     %zu\n"
                        "Name replies sent:         %zu\n"
                        "Name replies received:     %zu\n"
                        "Queued (transport):        %zu\n"
                        "Queued (packets):          %zu\n"
                        "Mean packet size (bytes):  %zu\n"
                        "Mean packet cost:          %zu\n",
                        POA_STAT_LOAD(poa, n_flows),
                        POA_STAT_LOAD(poa, rx_pkts),
                        POA_STAT_LOAD(poa, rx_bytes),
                        POA_STAT_LOAD(poa, tx_pkts),
                        POA_STAT_LOAD(poa, tx_bytes),
                        POA_STAT_LOAD(poa, mgmt_rx),
                        POA_STAT_LOAD(poa, mgmt_tx),
                        POA_STAT_LOAD(poa, bad_eid),
                        POA_STAT_LOAD(poa, dlv_fail),
                        POA_STAT_LOAD(poa, buf_fail),
                        POA_STAT_LOAD(poa, rcv_fail),
                        POA_STAT_LOAD(poa, snd_fail),
                        POA_STAT_LOAD(poa, qry_tx),
                        POA_STAT_LOAD(poa, qry_rx),
                        POA_STAT_LOAD(poa, rep_tx),
                        POA_STAT_LOAD(poa, rep_rx),
                        qlen, cost > 0 ? qlen / cost : 0, avg, cost);
        if (size < 0 || (size_t) size >= len)
                goto fail;

        if (poa->ops->poa_rib != NULL) {
                ret = poa->ops->poa_rib(poa, buf + size, len - size);
                if (ret < 0)
                        goto fail;

                size += ret;
        }

        pthread_rwlock_unlock(&poas.lock);

        return size;

 fail:
        pthread_rwlock_unlock(&poas.lock);

        return -1;
}

static int poa_rib_readdir(char *** buf)
{
        struct list_head * p;
        size_t             n = 0;
        int                idx = 0;

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list)
                ++n;

        if (n == 0) {
                *buf = NULL;
                goto no_poas;
        }

        *buf = malloc(sizeof(**buf) * n);
        if (*buf == NULL)
                goto fail_entries;

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                (*buf)[idx] = malloc(strlen(poa->name) + 1);
                if ((*buf)[idx] == NULL)
                        goto fail_entry;

                strcpy((*buf)[idx++], poa->name);
        }
 no_poas:
        pthread_rwlock_unlock(&poas.lock);

        return idx;

 fail_entry:
        while (idx-- > 0)
                free((*buf)[idx]);

        free(*buf);
 fail_entries:
        pthread_rwlock_unlock(&poas.lock);

        return -ENOMEM;
}

static int poa_rib_getattr(const char *      path,
                           struct rib_attr * attr)
{
        (void) path;

        attr->size  = POA_RIB_STRLEN;
        attr->mtime = 0;

        return 0;
}

static struct rib_ops poa_r_ops = {
        .read    = poa_rib_read,
        .readdir = poa_rib_readdir,
        .getattr = poa_rib_getattr
};

#endif /* PROC_FLOW_STATS */

int poa_init(const char * name)
{
        pthread_condattr_t cattr;

        assert(name != NULL);

        memset(&poas, 0, sizeof(poas));

        str_hash(HASH_SHA3_256, poas.name_hash, name);

        poas.mon_fd = -1;
        if (pthread_mutex_init(&poas.mtx, NULL) != 0)
                goto fail_mtx;

        if (pthread_cond_init(&poas.cond, NULL) != 0)
                goto fail_cond;

        if (pthread_mutex_init(&poas.mgmt_mtx, NULL) != 0)
                goto fail_mgmt_mtx;

        if (pthread_condattr_init(&cattr) != 0)
                goto fail_cattr;
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&poas.mgmt_cond, &cattr) != 0) {
                pthread_condattr_destroy(&cattr);
                goto fail_cattr;
        }

        pthread_condattr_destroy(&cattr);

        if (pthread_cond_init(&poas.done_cond, NULL) != 0)
                goto fail_done_cond;

        if (pthread_rwlock_init(&poas.lock, NULL) != 0)
                goto fail_lock;

        list_head_init(&poas.list);
        llist_init(&poas.deferred);
        llist_init(&poas.mgmt_frames);
        list_head_init(&poas.detach);

        poas.state = POA_INIT;

#ifdef PROC_FLOW_STATS
        if (rib_reg(POA_RIB, &poa_r_ops) < 0)
                goto fail_rib;
#endif
        return 0;

#ifdef PROC_FLOW_STATS
 fail_rib:
        pthread_rwlock_destroy(&poas.lock);
#endif

 fail_lock:
        pthread_cond_destroy(&poas.done_cond);
 fail_done_cond:
        pthread_cond_destroy(&poas.mgmt_cond);
 fail_cattr:
        pthread_mutex_destroy(&poas.mgmt_mtx);
 fail_mgmt_mtx:
        pthread_cond_destroy(&poas.cond);
 fail_cond:
        pthread_mutex_destroy(&poas.mtx);
 fail_mtx:
        return -1;
}

int poa_set_layer(const char * layer)
{
        if (layer == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&poas.lock);

        str_hash(HASH_SHA3_256, poas.layer_hash, layer);

        poas.state = POA_OPERATIONAL;

        pthread_rwlock_unlock(&poas.lock);

        return 0;
}

bool poa_has_name(const uint8_t * hash)
{
        bool match = false;

        pthread_rwlock_rdlock(&poas.lock);

        if (poas.state >= POA_INIT)
                match = memcmp(hash, poas.name_hash, POA_QUERY_HLEN) == 0;

        if (!match && poas.state >= POA_OPERATIONAL)
                match = memcmp(hash, poas.layer_hash, POA_QUERY_HLEN) == 0;

        pthread_rwlock_unlock(&poas.lock);

        return match;
}

int poa_spb_reserve(struct ssm_pk_buff ** spb,
                    size_t                len)
{
        return ssm_pool_alloc_b(proc.pool, len, NULL, spb, NULL) < 0 ? -1 : 0;
}

void poa_spb_release(struct ssm_pk_buff * spb)
{
        ssm_pool_remove(proc.pool, ssm_pk_buff_get_off(spb));
}

void poa_rx_pkt(struct poa *         poa,
                uint32_t             eid,
                struct ssm_pk_buff * spb)
{
        struct poa_flow *  pf;
        struct ssm_rbuff * rx_rb;
        size_t             len;

        len = ssm_pk_buff_len(spb); /* the ring write takes it over */

        if (eid >= poa->n_eids) {
                POA_STAT_BUMP(poa, bad_eid);
                poa_spb_release(spb);
                return;
        }

        rcu_rdlock(&poa->guard);

        pf = rcu_deref(poa->eid_to_pf[eid]);

        rcu_consume(pf);

        if (pf == NULL)
                goto fail_eid;

        rx_rb = rcu_deref(pf->rx_rb);

        rcu_consume(rx_rb);

        if (rx_rb == NULL)
                goto fail_eid;

        if (ssm_rbuff_write(rx_rb, ssm_pk_buff_get_off(spb)) < 0) {
                POA_STAT_BUMP(poa, dlv_fail);
                rcu_rdunlock(&poa->guard);
                poa_spb_release(spb);
                return;
        }

        POA_STAT_BUMP(poa, rx_pkts);
        POA_STAT_ADD(poa, rx_bytes, len);

        ssm_flow_set_notify(proc.fqset, pf->flow_id, FLOW_PKT);

        rcu_rdunlock(&poa->guard);

        return;

 fail_eid:
        POA_STAT_BUMP(poa, bad_eid);

        rcu_rdunlock(&poa->guard);

        poa_spb_release(spb);
}

static int poa_flow_req_arr(struct poa_flow * pf,
                            qosspec_t         qs,
                            uint32_t          mtu,
                            const buffer_t *  data)
{
        struct flow_info flow;
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        buffer_t         out = BUF_INIT;
        int              err;

        memset(&flow, 0, sizeof(flow));

        flow.n_pid   = getpid();
        flow.n_1_pid = getpid();
        flow.qs      = qs;
        flow.mpl     = pf->poa->mpl;
        flow.mtu     = mtu;
        if (ipcp_poa_flow_req_arr__irm_req_ser(&msg, &flow, data) < 0)
                return -ENOMEM;

        pf_set_pending(pf);

        err = send_recv_msg(&msg);
        if (err < 0)
                goto fail;

        err = poa_flow__irm_result_des(&msg, &flow, &out);
        if (err < 0)
                goto fail;

        freebuf(out);

        if (flow.id < 0 || flow.id >= SYS_MAX_FLOWS) {
                err = -EBADF;
                goto fail;
        }

        pf_set_flow_id(pf, flow.id);

        return 0;
 fail:
        pf_clr_pending(pf);
        return err;
}

static void handle_flow_req(struct poa *                poa,
                            const struct poa_addr *     src,
                            const struct poa_mgmt_msg * msg,
                            const uint8_t *             data,
                            size_t                      data_len)
{
        struct list_head * p;
        struct poa_flow *  pf     = NULL;
        qosspec_t          qs;
        buffer_t           buf;
        buffer_t           answer_data = BUF_INIT;
        uint32_t           r_eid;
        uint32_t           mtu;
        uint32_t           eid    = 0;
        int                answer = 0;
        bool               found  = false;
        bool               served = false;

        r_eid = ntoh32(msg->s_eid);

        poa_mgmt_msg_qos(msg, &qs);

        pthread_rwlock_wrlock(&poas.lock);

        list_for_each(p, &poa->flows) {
                pf = list_entry(p, struct poa_flow, pend);
                if (pf->r_eid != r_eid || poa_addr_cmp(&pf->r_addr, src) != 0)
                        continue;

                answer = pf->answer;
                eid    = pf->eid;
                served = true;

                found = pf->answer_sent;
                if (found && pf->answer_data.len > 0) {
                        answer_data.data = malloc(pf->answer_data.len);
                        if (answer_data.data != NULL) {
                                memcpy(answer_data.data, pf->answer_data.data,
                                       pf->answer_data.len);
                                answer_data.len = pf->answer_data.len;
                        }
                }
                break;
        }

        if (!served) {
                pf = pf_create(poa, src);
                if (pf != NULL)
                        pf->r_eid = r_eid;
        }

        pthread_rwlock_unlock(&poas.lock);

        if (found) {
                mgmt_send(poa, src, POA_FLOW_REPLY, eid, r_eid, qos_raw, answer,
                          answer_data.len > 0 ? &answer_data : NULL);
                freebuf(answer_data);
        }

        if (served || pf == NULL)
                return;

        buf.len  = data_len;
        buf.data = (uint8_t *) data;
        mtu      = poa->ops->poa_mtu(poa, src);
        if (poa_flow_req_arr(pf, qs, mtu, &buf) < 0) {
                mgmt_send(poa, src, POA_FLOW_REPLY, pf->eid, r_eid, qos_raw,
                          -1, NULL);
                pf_destroy(pf);
        }
}

static void handle_flow_reply(struct poa *                poa,
                              const struct poa_addr *     src,
                              const struct poa_mgmt_msg * msg,
                              const uint8_t *             data,
                              size_t                      data_len)
{
        struct poa_flow * pf;
        uint32_t          eid;

        eid = ntoh32(msg->d_eid);

        pthread_rwlock_rdlock(&poas.lock);

        pf = eid < poa->n_eids ? poa->eid_to_pf[eid] : NULL;
        if (pf == NULL || pf->state != POA_FLOW_PENDING) {
                pthread_rwlock_unlock(&poas.lock);
                return;
        }

        if (poa_addr_cmp(&pf->r_addr, src) != 0) {
                pthread_rwlock_unlock(&poas.lock);
                return;
        }

        pthread_mutex_lock(&pf->mtx);

        if (pf->replied) {
                pthread_mutex_unlock(&pf->mtx);
                pthread_rwlock_unlock(&poas.lock);
                return;
        }

        if (data_len > 0) {
                pf->resp_data.data = malloc(data_len);
                if (pf->resp_data.data != NULL) {
                        memcpy(pf->resp_data.data, data, data_len);

                        pf->resp_data.len = data_len;
                }
        }

        pf->r_eid    = ntoh32(msg->s_eid);
        pf->response = ntoh32(msg->response);
        pf->replied  = true;

        pthread_cond_broadcast(&pf->cond);

        pthread_mutex_unlock(&pf->mtx);

        pthread_rwlock_unlock(&poas.lock);
}

static void handle_flow_update(struct poa *                poa,
                               const struct poa_addr *     src,
                               const struct poa_mgmt_msg * msg,
                               const uint8_t *             data,
                               size_t                      data_len)
{
        struct poa_flow * pf;
        buffer_t          buf;
        uint32_t          eid;

        eid = ntoh32(msg->d_eid);

        pthread_rwlock_rdlock(&poas.lock);

        pf = eid < poa->n_eids ? poa->eid_to_pf[eid] : NULL;
        if (pf == NULL || pf->state != POA_FLOW_ALLOCATED) {
                pthread_rwlock_unlock(&poas.lock);
                return;
        }

        if (poa_addr_cmp(&pf->r_addr, src) != 0) {
                pthread_rwlock_unlock(&poas.lock);
                return;
        }

        eid = (uint32_t) pf->flow_id;

        pthread_rwlock_unlock(&poas.lock);

        buf.len  = data_len;
        buf.data = (uint8_t *) data;

        ipcp_flow_update_arr((int) eid, &buf);
}

static void mgmt_frame_handle(struct poa_mgmt_frame * frame)
{
        const struct poa_mgmt_msg * msg;
        const uint8_t *             data;
        size_t                      data_len;

        msg = (const struct poa_mgmt_msg *) frame->buf;
        if (frame->len < sizeof(*msg))
                return;

        data_len = ntoh16(msg->data_len);
        if (data_len > frame->len - sizeof(*msg))
                return;

        data = frame->buf + sizeof(*msg);

        switch (msg->code) {
        case POA_FLOW_REQ:
                handle_flow_req(frame->poa, &frame->src, msg, data, data_len);
                break;
        case POA_FLOW_REPLY:
                handle_flow_reply(frame->poa, &frame->src, msg, data, data_len);
                break;
        case POA_FLOW_UPDATE:
                handle_flow_update(frame->poa, &frame->src, msg, data,
                                   data_len);
                break;
        default:
                break;
        }
}

static bool pf_steal(struct poa_flow * pf)
{
        bool stolen = false;

        pthread_mutex_lock(&poas.mtx);

        if (pf->pending) {
                pf->pending = false;
                poas.id_to_pf[pf->flow_id] = NULL;

                deferred_purge(pf->flow_id);

                stolen = true;
        }

        pthread_mutex_unlock(&poas.mtx);

        return stolen;
}

static void sweep_pending(void)
{
        struct poa_flow *  dead[POA_SWEEP_MAX];
        struct list_head * p;
        struct list_head * q;
        struct timespec    now;
        size_t             n = 0;
        size_t             i;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                list_for_each(q, &poa->flows) {
                        struct poa_flow * pf;

                        if (n == POA_SWEEP_MAX)
                                break;

                        pf = list_entry(q, struct poa_flow, pend);
                        if (pf->state != POA_FLOW_PENDING || pf->claimed)
                                continue;

                        if (now.tv_sec - pf->t0.tv_sec < POA_PEND_TIMEO)
                                continue;

                        if (pf->flow_id >= 0 && !pf_steal(pf))
                                continue;

                        dead[n++] = pf;
                }

                if (n == POA_SWEEP_MAX)
                        break;
        }

        pthread_rwlock_unlock(&poas.lock);

        for (i = 0; i < n; ++i)
                pf_destroy(dead[i]);

        pthread_mutex_lock(&poas.mtx);

        list_for_each_safe(p, q, &poas.deferred.list) {
                struct poa_deferred * d;

                d = list_entry(p, struct poa_deferred, next);
                if (now.tv_sec - d->t0.tv_sec < POA_PEND_TIMEO)
                        continue;

                llist_del(&d->next, &poas.deferred);
                freebuf(d->data);
                free(d);
        }

        pthread_mutex_unlock(&poas.mtx);
}

void poa_rx_mgmt(struct poa *            poa,
                 const struct poa_addr * src,
                 const uint8_t *         buf,
                 size_t                  len)
{
        struct poa_mgmt_frame * frame;

        if (len < sizeof(struct poa_mgmt_msg) || len > POA_MGMT_BUFSZ)
                return;

        POA_STAT_BUMP(poa, mgmt_rx);

        frame = malloc(offsetof(struct poa_mgmt_frame, buf) + len);
        if (frame == NULL)
                return;

        frame->poa = poa;
        frame->src = *src;
        frame->len = len;

        memcpy(frame->buf, buf, len);

        pthread_mutex_lock(&poas.mgmt_mtx);

        if (poa->n_mgmt >= POA_MGMT_QMAX) {
                pthread_mutex_unlock(&poas.mgmt_mtx);
                free(frame);
                return;
        }

        ++poa->n_mgmt;

        llist_add_tail(&frame->next, &poas.mgmt_frames);

        pthread_cond_signal(&poas.mgmt_cond);

        pthread_mutex_unlock(&poas.mgmt_mtx);
}

static void mgmt_frames_purge(const struct poa * poa)
{
        struct list_head * p;
        struct list_head * h;

        pthread_mutex_lock(&poas.mgmt_mtx);

        list_for_each_safe(p, h, &poas.mgmt_frames.list) {
                struct poa_mgmt_frame * frame;

                frame = list_entry(p, struct poa_mgmt_frame, next);
                if (frame->poa != poa)
                        continue;

                --frame->poa->n_mgmt;

                llist_del(&frame->next, &poas.mgmt_frames);

                free(frame);
        }

        pthread_mutex_unlock(&poas.mgmt_mtx);
}

static bool poa_has_id(const struct poa *      poa,
                       const struct poa_spec * spec)
{
        if (poa->type != spec->type)
                return false;

        return poa->ops->poa_has_id(poa, spec);
}

/*
 * The PoA carrying dst, as the transport judges it. -EPERM if none
 * matches, -EINVAL if several do. Caller holds poas.lock.
 */
static int poa_lookup(const struct poa_addr * dst,
                      struct poa **           out)
{
        struct list_head * p;
        struct poa *       found = NULL;

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (poa->type != dst->type)
                        continue;

                if (!poa->ops->poa_match(poa, dst))
                        continue;

                if (found != NULL) /* nothing given, two candidates */
                        return -EINVAL;

                found = poa;
        }

        if (found == NULL)
                return -EPERM;

        *out = found;

        return 0;
}

/* Sends are deadlined, bounding the lock hold on a full queue. */
int poa_bcast_mgmt(const struct poa_addr * dst,
                   const uint8_t *         buf,
                   size_t                  len)
{
        struct list_head * p;
        int                n = 0;

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (poa->type != dst->type)
                        continue;

                if (!poa->ops->poa_match(poa, dst))
                        continue;

                if (poa->ops->poa_send_mgmt(poa, dst, buf, len) < 0)
                        continue;

                /* All management broadcasts are name queries. */
                POA_STAT_BUMP(poa, qry_tx);
                ++n;
        }

        pthread_rwlock_unlock(&poas.lock);

        return n;
}

static bool deadline_is_malformed(const struct timespec * timeo)
{
        if (timeo == NULL)
                return false;

        if (timeo->tv_sec < 0 || timeo->tv_nsec < 0)
                return true;

        return timeo->tv_nsec >= BILLION;
}

/*
 * Complete addr for dst on any backend that can query. The ops are
 * collected under poas.lock but called outside it: a query blocks up
 * to its deadline and takes the lock again to broadcast. The tables
 * are static, so nothing dangles; a struct poa cannot be carried
 * across the unlock. The deadline applies per backend.
 */
int poa_query(const char *            dst,
              const struct timespec * timeo,
              struct poa_addr *       addr)
{
        const struct poa_ops * cand[POA_MAX_POAS];
        enum poa_type          type[POA_MAX_POAS];
        struct list_head *     p;
        size_t                 n = 0;
        size_t                 i;
        int                    err = -ENOTSUP;

        if (dst == NULL || addr == NULL)
                return -EINVAL;

        if (deadline_is_malformed(timeo))
                return -EINVAL;

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (poa->ops->poa_query == NULL)
                        continue;

                for (i = 0; i < n && cand[i] != poa->ops; i++)
                        ;
                if (i < n)
                        continue;

                /* One type per backend: eth. Revisit if that changes. */
                cand[n]   = poa->ops;
                type[n++] = poa->type;
        }

        pthread_rwlock_unlock(&poas.lock);

        for (i = 0; i < n; i++) {
                memset(addr, 0, sizeof(*addr));

                addr->type = type[i];

                err = cand[i]->poa_query(dst, timeo, addr);
                if (err == 0)
                        return 0;
        }

        return err;
}

static int poa_check(const struct poa_addr * dst)
{
        struct poa * poa;
        int          err;

        pthread_rwlock_rdlock(&poas.lock);

        err = poa_lookup(dst, &poa);

        pthread_rwlock_unlock(&poas.lock);

        return err;
}

static int poa_alloc(const struct poa_addr * dst,
                     qosspec_t               qs,
                     const buffer_t *        req,
                     buffer_t *              resp,
                     struct poa_flow **      pf_out,
                     uint32_t *              mtu,
                     const struct timespec * timeo)
{
        struct timespec   dflt  = TIMESPEC_INIT_MS(POA_ALLOC_TIMEO);
        struct timespec   rintv = TIMESPEC_INIT_MS(POA_RETRY_TIMEO);
        struct poa_flow * pf;
        struct poa *      poa;
        struct timespec   abstime;
        struct timespec   now;
        struct timespec   retry;
        int               err;

        pthread_rwlock_wrlock(&poas.lock);

        err = poa_lookup(dst, &poa);
        if (err < 0) {
                pthread_rwlock_unlock(&poas.lock);
                return err;
        }

        pf = pf_create(poa, dst);
        if (pf == NULL) {
                pthread_rwlock_unlock(&poas.lock);
                return -ENOMEM;
        }

        pf->claimed = true;

        pthread_rwlock_unlock(&poas.lock);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, timeo != NULL ? timeo : &dflt, &abstime);

        pthread_mutex_lock(&pf->mtx);

        while (!pf->replied) {
                pthread_mutex_unlock(&pf->mtx);

                err = mgmt_send(poa, dst, POA_FLOW_REQ, pf->eid, 0, qs, 0, req);

                pthread_mutex_lock(&pf->mtx);

                if (err < 0 && err != -ETIMEDOUT && err != -EAGAIN) {
                        err = -EIO;
                        goto fail;
                }

                if (pf->replied)
                        break;

                clock_gettime(PTHREAD_COND_CLOCK, &now);
                ts_add(&now, &rintv, &retry);

                if (ts_diff_ns(&retry, &abstime) > 0)
                        retry = abstime;

                pthread_cond_timedwait(&pf->cond, &pf->mtx, &retry);

                if (pf->replied)
                        break;

                clock_gettime(PTHREAD_COND_CLOCK, &now);

                if (ts_diff_ns(&now, &abstime) >= 0) {
                        err = -ETIMEDOUT;
                        goto fail;
                }
        }

        if (pf->response != 0) {
                err = -ECONNREFUSED;
                goto fail;
        }

        *resp              = pf->resp_data;
        pf->resp_data.len  = 0;
        pf->resp_data.data = NULL;

        pthread_mutex_unlock(&pf->mtx);

        *mtu    = poa->ops->poa_mtu(poa, dst);
        *pf_out = pf;

        return 0;

 fail:
        pthread_mutex_unlock(&pf->mtx);
        pf_destroy(pf);
        return err;
}

static void poa_alloc_fail(struct poa_flow * pf)
{
        pf_destroy(pf);
}

void poa_flow_attach(struct poa_flow *  pf,
                     int                flow_id,
                     struct ssm_rbuff * rx_rb)
{
        struct poa * poa = pf->poa;

        if (pf->flow_id != flow_id)
                pf_set_flow_id(pf, flow_id);

        pthread_rwlock_wrlock(&poas.lock);

        pf->state = POA_FLOW_ALLOCATED;

        rcu_wrlock(&poa->guard);

        rcu_publish(rx_rb);
        rcu_assign(pf->rx_rb, rx_rb);

        rcu_wrunlock(&poa->guard);

        pthread_rwlock_unlock(&poas.lock);
}

void poa_flow_detach(struct poa_flow * pf)
{
        struct poa * poa = pf->poa;

        pthread_rwlock_wrlock(&poas.lock);

        pf->state = POA_FLOW_DEAD;

        rcu_wrlock(&poa->guard);

        rcu_assign(pf->rx_rb, NULL);

        rcu_wrunlock(&poa->guard);

        pthread_rwlock_unlock(&poas.lock);

        pf_destroy(pf);
}

static size_t flows_updown(struct poa * poa,
                           bool         up)
{
        struct list_head * p;
        size_t             n = 0;

        list_for_each(p, &poa->flows) {
                struct poa_flow * pf;
                struct flow *     flow;

                pf = list_entry(p, struct poa_flow, pend);
                if (pf->state != POA_FLOW_ALLOCATED || pf->flow_id < 0)
                        continue;

                flow = &proc.flows[proc.id_to_fd[pf->flow_id].fd];
                if (flow->info.id != pf->flow_id)
                        continue;

                if (((flow->oflags & FLOWFDOWN) != 0) != !up)
                        ++n;

                if (up) {
                        flow->oflags &= ~FLOWFDOWN;

                        ssm_rbuff_clr_bits(flow->rx_rb, RB_FLOWDOWN);
                } else {
                        flow->oflags |= FLOWFDOWN;

                        ssm_rbuff_set_bits(flow->rx_rb, RB_FLOWDOWN);
                }

                ssm_flow_set_notify(proc.fqset, pf->flow_id,
                                    up ? FLOW_UP : FLOW_DOWN);
        }

        return n;
}

size_t poa_link_updown(int  id,
                       bool up)
{
        struct list_head * p;
        size_t             n = 0;

        pthread_rwlock_wrlock(&proc.lock);
        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (poa->ops->poa_link_match == NULL)
                        continue;

                if (!poa->ops->poa_link_match(poa, id))
                        continue;

                n += flows_updown(poa, up);
        }

        pthread_rwlock_unlock(&poas.lock);
        pthread_rwlock_unlock(&proc.lock);

        return n;
}

static size_t poa_ewma(size_t avg,
                       size_t sz)
{
        if (avg == 0)
                return sz;

        avg = avg + (sz >> POA_AVG_SHIFT) - (avg >> POA_AVG_SHIFT);

        return avg == 0 ? 1 : avg;
}

static void poa_avg_len_update(struct poa * poa,
                               size_t       sz)
{
        STORE_RELAXED(&poa->avg_len, poa_ewma(LOAD_RELAXED(&poa->avg_len), sz));
}

static size_t poa_qlen(struct poa * poa)
{
        struct timespec now;
        uint64_t        ns;
        size_t          qlen;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        ns = TS_TO_UINT64(now);
        if (ns - LOAD_RELAXED(&poa->q_time) < POA_QLEN_GATE)
                return LOAD_RELAXED(&poa->q_cache);

        qlen = poa->ops->poa_qlen(poa);

        STORE_RELAXED(&poa->q_cache, qlen);
        STORE_RELAXED(&poa->q_time, ns);

        return qlen;
}

static void poa_cost_sample(struct poa * poa,
                            size_t       before,
                            size_t       len)
{
        size_t after;

        after = poa->ops->poa_qlen(poa);
        if (after <= before)
                return;   /* drained; nothing to learn */

        after -= before;
        if (after < len || after > (len << 2) + 1024)
                return;

        STORE_RELAXED(&poa->avg_ovh,
                      poa_ewma(LOAD_RELAXED(&poa->avg_ovh), after - len));
}

int poa_flow_tx(struct poa_flow *       pf,
                struct ssm_pk_buff *    spb,
                bool                    block,
                const struct timespec * abstime)
{
        struct poa * poa    = pf->poa;
        size_t       len    = ssm_pk_buff_len(spb);
        size_t       before = 0;
        bool         sample;
        int          ret;

        sample = (LOAD_RELAXED(&poa->n_tx) & POA_COST_MASK) == 0;
        if (sample)
                before = poa->ops->poa_qlen(poa);

        ret = poa->ops->poa_send(poa, &pf->r_addr, pf->r_eid, spb, block,
                                 abstime);
        if (ret < 0) { /* the caller releases the buffer */
                POA_STAT_BUMP(poa, snd_fail);
                return ret;
        }

        POA_STAT_BUMP(poa, tx_pkts);
        POA_STAT_ADD(poa, tx_bytes, len);

        FETCH_ADD_RELAXED(&poa->n_tx, 1);

        poa_avg_len_update(poa, len);

        if (sample)
                poa_cost_sample(poa, before, len);

        poa_spb_release(spb);

        return 0;
}

size_t poa_flow_qlen(const struct poa_flow * pf)
{
        struct poa * poa = pf->poa;
        uint64_t     bytes;
        size_t       cost;
        size_t       pkts;
        size_t       byts;

        if (poa->ops->poa_qpkts != NULL &&
            poa->ops->poa_qpkts(poa, &pkts, &byts) == 0)
                return byts;

        cost = LOAD_RELAXED(&poa->avg_len) + LOAD_RELAXED(&poa->avg_ovh);
        if (LOAD_RELAXED(&poa->avg_ovh) == 0 || cost == 0)
                return poa_qlen(poa); /* overstated beats false empty */

        bytes = (uint64_t) poa_qlen(poa) * LOAD_RELAXED(&poa->avg_len);

        return (size_t) (bytes / cost);
}

size_t poa_flow_qpkts(const struct poa_flow * pf)
{
        struct poa * poa = pf->poa;
        size_t       cost;
        size_t       pkts;
        size_t       byts;

        if (poa->ops->poa_qpkts != NULL &&
            poa->ops->poa_qpkts(poa, &pkts, &byts) == 0)
                return pkts;

        cost = LOAD_RELAXED(&poa->avg_len) + LOAD_RELAXED(&poa->avg_ovh);
        if (LOAD_RELAXED(&poa->avg_ovh) == 0 || cost == 0)
                return 0;

        return poa_qlen(poa) / cost;
}

size_t poa_flow_mean_len(const struct poa_flow * pf)
{
        return LOAD_RELAXED(&pf->poa->avg_len);
}

struct cap_est * poa_flow_cap_est(struct poa_flow * pf)
{
        return &pf->poa->cap;
}

void poa_flow_ready(struct poa_flow * pf)
{
        buffer_t data;
        int      answer;

        if (pf == NULL)
                return;

        clrbuf(data);

        pthread_rwlock_wrlock(&poas.lock);

        if (!pf->answered || pf->answer_sent) {
                pthread_rwlock_unlock(&poas.lock);
                return;
        }

        answer = pf->answer;

        if (pf->answer_data.len > 0) {
                data.data = malloc(pf->answer_data.len);
                if (data.data != NULL) {
                        memcpy(data.data, pf->answer_data.data,
                               pf->answer_data.len);
                        data.len = pf->answer_data.len;
                }
        }

        pf->answer_sent = true;

        pthread_rwlock_unlock(&poas.lock);

        mgmt_send(pf->poa, &pf->r_addr, POA_FLOW_REPLY, pf->eid,
                  pf->r_eid, qos_raw, answer, &data);

        freebuf(data);
}

int poa_flow_alloc_resp(int              flow_id,
                        int              response,
                        const buffer_t * data)
{
        struct poa_deferred * d;
        struct poa_flow *     pf;

        if (flow_id < 0 || flow_id >= SYS_MAX_FLOWS)
                return -EPERM;

        pthread_mutex_lock(&poas.mtx);

        pf = poas.id_to_pf[flow_id];
        if (pf != NULL) {
                pthread_mutex_unlock(&poas.mtx);
                return pf_answer(pf, response, data);
        }

        if (poas.deferred.len >= POA_DEFER_MAX) {
                pthread_mutex_unlock(&poas.mtx);
                return -ENOMEM;
        }

        d = malloc(sizeof(*d));
        if (d == NULL) {
                pthread_mutex_unlock(&poas.mtx);
                return -ENOMEM;
        }

        memset(d, 0, sizeof(*d));

        clock_gettime(PTHREAD_COND_CLOCK, &d->t0);

        d->flow_id  = flow_id;
        d->response = response;

        if (data != NULL && data->len > 0) {
                d->data.data = malloc(data->len);
                if (d->data.data == NULL) {
                        free(d);
                        pthread_mutex_unlock(&poas.mtx);
                        return -ENOMEM;
                }
                memcpy(d->data.data, data->data, data->len);

                d->data.len = data->len;
        }

        llist_add_tail(&d->next, &poas.deferred);

        pthread_mutex_unlock(&poas.mtx);

        return 0;
}

int poa_flow_update(int              flow_id,
                    const buffer_t * data)
{
        struct poa_flow * pf;

        pf = pf_get(flow_id);
        if (pf == NULL)
                return -EPERM;

        return mgmt_send(pf->poa, &pf->r_addr, POA_FLOW_UPDATE, pf->eid,
                         pf->r_eid, qos_raw, 0, data);
}

/* The PoA state is released when the flow itself is torn down. */
int poa_flow_dealloc(int flow_id)
{
        (void) flow_id;

        return 0;
}

/* PoA id 0 = management channel. */
static struct poa * poa_create(enum poa_type          type,
                               const struct poa_ops * ops,
                               size_t                 n_eids)
{
        struct poa * poa;

        poa = malloc(sizeof(*poa));
        if (poa == NULL)
                goto fail_malloc;

        memset(poa, 0, sizeof(*poa));

        poa->eid_to_pf = malloc(sizeof(*poa->eid_to_pf) * n_eids);
        if (poa->eid_to_pf == NULL)
                goto fail_map;

        memset(poa->eid_to_pf, 0, sizeof(*poa->eid_to_pf) * n_eids);

        poa->eids = bmp_create(n_eids - 1, 1);
        if (poa->eids == NULL)
                goto fail_bmp;

        if (rcu_guard_init(&poa->guard) != 0)
                goto fail_guard;

        list_head_init(&poa->next);
        list_head_init(&poa->flows);

        poa->type   = type;
        poa->ops    = ops;
        poa->mpl    = ops->mpl;
        poa->n_eids = n_eids;

        return poa;

 fail_guard:
        bmp_destroy(poa->eids);
 fail_bmp:
        free(poa->eid_to_pf);
 fail_map:
        free(poa);
 fail_malloc:
        return NULL;
}

static void poa_destroy(struct poa * poa)
{
        rcu_guard_fini(&poa->guard);

        bmp_destroy(poa->eids);

        free(poa->eid_to_pf);
        free(poa);
}

static void poa_teardown(struct poa * poa)
{
        if (poas.state >= POA_RUNNING)
                poa->ops->poa_stop(poa);

        mgmt_frames_purge(poa);

        poa->ops->poa_detach(poa);

        poa_destroy(poa);
}

static void poa_detach_all(void)
{
        pthread_rwlock_wrlock(&poas.lock);

        while (!list_is_empty(&poas.list)) {
                struct poa * poa;

                poa = list_first_entry(&poas.list, struct poa, next);

                list_del(&poa->next);

                pthread_rwlock_unlock(&poas.lock);

                poa_teardown(poa);

                pthread_rwlock_wrlock(&poas.lock);
        }

        pthread_rwlock_unlock(&poas.lock);
}

static int poa_do_detach(const struct poa_detach_req * req)
{
        struct list_head * p;
        struct poa *       found = NULL;

        pthread_rwlock_wrlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (!poa_has_id(poa, &req->spec))
                        continue;

                found = poa;
                break;
        }

        if (found == NULL) {
                pthread_rwlock_unlock(&poas.lock);
                return -ENOENT;
        }

        if (!list_is_empty(&found->flows)) {
                pthread_rwlock_unlock(&poas.lock);
                return -EBUSY;
        }

        list_del(&found->next);

        pthread_rwlock_unlock(&poas.lock);

        poa_teardown(found);

        return 0;
}

static int poa_del(const struct poa_spec * spec)
{
        struct poa_detach_req req;
        int                   cs;
        int                   ret;

        memset(&req, 0, sizeof(req));

        req.spec = *spec;

        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);

        if (poas.state < POA_RUNNING) { /* set before workers run */
                ret = poa_do_detach(&req);
                goto out;
        }

        pthread_mutex_lock(&poas.mgmt_mtx);

        if (poas.mgmt_stop) { /* stopped: poa_fini reaps these */
                pthread_mutex_unlock(&poas.mgmt_mtx);

                ret = -EBUSY;
                goto out;
        }

        list_add_tail(&req.next, &poas.detach);

        pthread_cond_signal(&poas.mgmt_cond);

        while (!req.done)
                pthread_cond_wait(&poas.done_cond, &poas.mgmt_mtx);

        pthread_mutex_unlock(&poas.mgmt_mtx);

        ret = req.result;
 out:
        pthread_setcancelstate(cs, NULL);

        return ret;
}

static __inline__ bool mgmt_idle(void)
{
        if (poas.mgmt_stop)
                return false;

        if (!llist_is_empty(&poas.mgmt_frames))
                return false;

        return list_is_empty(&poas.detach);
}

static void detach_run(void)
{
        while (!list_is_empty(&poas.detach)) {
                struct poa_detach_req * req;

                req = list_first_entry(&poas.detach, struct poa_detach_req,
                                       next);
                list_del(&req->next);

                pthread_mutex_unlock(&poas.mgmt_mtx);

                req->result = poa_do_detach(req);

                pthread_mutex_lock(&poas.mgmt_mtx);

                req->done = true;

                pthread_cond_broadcast(&poas.done_cond);
        }
}

static void * mgmt_handler(void * o)
{
        struct timespec intv = TIMESPEC_INIT_MS(POA_SWEEP_TIMEO);

        (void) o;

        while (true) {
                struct poa_mgmt_frame * frame;
                struct timespec         abstime;

                pthread_mutex_lock(&poas.mgmt_mtx);

                detach_run();

                while (mgmt_idle()) {
                        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                        ts_add(&abstime, &intv, &abstime);

                        if (pthread_cond_timedwait(&poas.mgmt_cond,
                                                   &poas.mgmt_mtx,
                                                   &abstime) == ETIMEDOUT) {
                                pthread_mutex_unlock(&poas.mgmt_mtx);
                                sweep_pending();
                                pthread_mutex_lock(&poas.mgmt_mtx);
                        }
                }

                if (poas.mgmt_stop) {
                        detach_run(); /* nobody else serves these */

                        pthread_mutex_unlock(&poas.mgmt_mtx);
                        break;
                }

                if (llist_is_empty(&poas.mgmt_frames)) {
                        pthread_mutex_unlock(&poas.mgmt_mtx);
                        continue;
                }

                frame = llist_first_entry(&poas.mgmt_frames,
                                          struct poa_mgmt_frame, next);
                llist_del(&frame->next, &poas.mgmt_frames);

                --frame->poa->n_mgmt;

                pthread_mutex_unlock(&poas.mgmt_mtx);

                mgmt_frame_handle(frame);

                free(frame);
        }

        return (void *) 0;
}

#ifndef HAVE_ETH
/* Only the Ethernet transport reports link events. */
int poa_monitor_open(void)
{
        return -1;
}

void poa_monitor_read(int fd)
{
        (void) fd;
}
#endif

static void * poa_monitor(void * o)
{
        (void) o;

        while (true)
                poa_monitor_read(poas.mon_fd);

        return (void *) 0;
}

static int monitor_start(void)
{
        poas.mon_fd = poa_monitor_open();
        if (poas.mon_fd < 0)
                return 0;

        if (pthread_create(&poas.monitor, NULL, poa_monitor, NULL) == 0)
                return 0;

        close(poas.mon_fd);

        poas.mon_fd = -1;

        return -1;
}

static void monitor_stop(void)
{
        if (poas.mon_fd < 0)
                return;

        pthread_cancel(poas.monitor);
        pthread_join(poas.monitor, NULL);

        close(poas.mon_fd);

        poas.mon_fd = -1;
}

int poa_start(void)
{
        struct list_head * p;
        struct list_head * h;

        if (poas.state == POA_NULL)
                return 0;

        if (pthread_create(&poas.mgmt_handler, NULL, mgmt_handler, NULL) != 0)
                goto fail_mgmt;

        if (monitor_start() < 0)
                goto fail_monitor;

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (poa->ops->poa_start(poa) < 0)
                        goto fail_reader;
        }

        poas.state = POA_RUNNING;

        pthread_rwlock_unlock(&poas.lock);

        return 0;

 fail_reader:
        list_for_each(h, &poas.list) {
                struct poa * poa = list_entry(h, struct poa, next);

                if (h == p)
                        break;

                poa->ops->poa_stop(poa);
        }

        pthread_rwlock_unlock(&poas.lock);

        monitor_stop();
 fail_monitor:
        pthread_mutex_lock(&poas.mgmt_mtx);

        poas.mgmt_stop = true;

        pthread_cond_broadcast(&poas.mgmt_cond);
        pthread_mutex_unlock(&poas.mgmt_mtx);

        pthread_join(poas.mgmt_handler, NULL);
 fail_mgmt:
        return -1;
}

void poa_stop(void)
{
        struct list_head * p;

        if (poas.state < POA_RUNNING)
                return;

        pthread_mutex_lock(&poas.mgmt_mtx);

        poas.mgmt_stop = true;

        pthread_cond_broadcast(&poas.mgmt_cond);
        pthread_mutex_unlock(&poas.mgmt_mtx);

        pthread_join(poas.mgmt_handler, NULL);

        monitor_stop();

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                poa->ops->poa_stop(poa);
        }

        pthread_rwlock_unlock(&poas.lock);

        poas.state = POA_INIT;
}

void poa_fini(void)
{
        if (poas.state == POA_NULL)
                return;

        poa_stop();

        poas.state = POA_NULL;

        poa_detach_all();

#ifdef PROC_FLOW_STATS
        rib_unreg(POA_RIB);
#endif

        pthread_rwlock_destroy(&poas.lock);
        pthread_cond_destroy(&poas.done_cond);
        pthread_cond_destroy(&poas.mgmt_cond);
        pthread_mutex_destroy(&poas.mgmt_mtx);
        pthread_cond_destroy(&poas.cond);
        pthread_mutex_destroy(&poas.mtx);
}

static size_t poa_count(void)
{
        struct list_head * p;
        size_t             n = 0;

        list_for_each(p, &poas.list)
                n++;

        return n;
}

static int poa_add(const struct poa_spec * spec,
                   const struct poa_ops *  ops,
                   size_t                  n_eids)
{
        struct list_head * p;
        struct poa *       poa;
        int                err;

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                poa = list_entry(p, struct poa, next);
                if (poa_has_id(poa, spec)) {
                        pthread_rwlock_unlock(&poas.lock);
                        return -EPERM;
                }
        }

        pthread_rwlock_unlock(&poas.lock);

        poa = poa_create(spec->type, ops, n_eids);
        if (poa == NULL)
                return -ENOMEM;

        err = poa->ops->poa_attach(poa, spec);
        if (err < 0)
                goto fail_bind;

        err = poa_addr_name(&poa->local, poa->name, sizeof(poa->name));
        if (err < 0)
                goto fail_start;

        err = -1;

        pthread_rwlock_wrlock(&poas.lock);

        if (poa_count() >= POA_MAX_POAS) {
                pthread_rwlock_unlock(&poas.lock);
                goto fail_start;
        }

        if (poas.state >= POA_RUNNING && poa->ops->poa_start(poa) < 0) {
                pthread_rwlock_unlock(&poas.lock);
                goto fail_start;
        }

        list_add_tail(&poa->next, &poas.list);

        pthread_rwlock_unlock(&poas.lock);

        return 0;

 fail_start:
        poa->ops->poa_detach(poa);
 fail_bind:
        poa_destroy(poa);
        return err;
}

/* The single place a type is bound to its transport. */
int poa_attach(const struct poa_spec * poa)
{
        if (poa == NULL)
                return -EINVAL;

        switch (poa->type) {
        case POA_UDP4:
                /* FALLTHRU */
        case POA_UDP6:
                return poa_add(poa, &udp_poa_ops, POA_MAX_EIDS);
        case POA_ETH:
#ifdef HAVE_ETH
                return poa_add(poa, &eth_poa_ops, POA_MAX_EIDS);
#else
                return -ENOTSUP;
#endif
        default:
                return -ENOTSUP;
        }
}

int poa_detach(const struct poa_spec * poa)
{
        if (poa == NULL)
                return -EINVAL;

        return poa_del(poa);
}

ssize_t poa_list(struct poa_spec * specs,
                 size_t            max)
{
        struct list_head * p;
        size_t             n = 0;

        if (specs == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (n++ >= max)
                        continue;

                memset(specs, 0, sizeof(*specs));

                poa->ops->poa_spec(poa, specs);

                specs++;
        }

        pthread_rwlock_unlock(&poas.lock);

        return (ssize_t) n;
}

/*
 * Complete peer for dst on the backend serving its type. The ops are
 * borrowed under poas.lock and called outside it (see poa_query); if
 * every PoA of the type detaches in between, the query's broadcast
 * reaches nothing and reports -EPERM, as the lookup would.
 */
static int poa_peer_resolve(const char *      dst,
                            struct poa_addr * peer)
{
        const struct poa_ops * ops = NULL;
        struct list_head *     p;

        pthread_rwlock_rdlock(&poas.lock);

        list_for_each(p, &poas.list) {
                struct poa * poa = list_entry(p, struct poa, next);

                if (poa->type == peer->type) {
                        ops = poa->ops;
                        break;
                }
        }

        pthread_rwlock_unlock(&poas.lock);

        if (ops == NULL) /* nothing could carry the flow */
                return -EPERM;

        if (ops->poa_query == NULL) /* these addresses arrive complete */
                return 0;

        return ops->poa_query(dst, NULL, peer);
}

/*
 * Three steps: the IRMd creates the flow and prepares the key exchange,
 * the PoA handshakes with the peer, the IRMd completes the
 * exchange and hands us the key.
 */
int poa_flow_alloc(const char *            dst,
                   const struct poa_addr * addr,
                   qosspec_t *             qs,
                   const struct timespec * timeo)
{
        struct flow_info  flow;
        struct poa_flow * pf;
        struct poa_addr   peer;
        struct crypt_sk   crypt;
        struct timespec   t0;
        struct timespec   t1;
        uint8_t           key[SYMMKEYSZ];
        uint8_t           buf[SOCK_BUF_SIZE];
        buffer_t          msg = {SOCK_BUF_SIZE, buf};
        buffer_t          req;
        buffer_t          resp;
        uint32_t          mtu = 0;
        int               err;

        if (addr == NULL)
                return -EINVAL;

        if (qs != NULL && qs->service == SVC_STREAM && qs->loss != 0)
                return -EINVAL;

        peer = *addr;

        err = poa_peer_resolve(dst, &peer);
        if (err < 0)
                return err;

        addr = &peer;

        err = poa_check(addr);
        if (err < 0)
                return err;

        memset(&flow, 0, sizeof(flow));

        flow.n_pid   = getpid();
        flow.n_1_pid = getpid();
        flow.qs      = qs == NULL ? qos_raw : *qs;
        if (poa_flow_alloc__irm_req_ser(&msg, &flow, dst) < 0)
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        clrbuf(req);
        clrbuf(resp);

        err = poa_flow__irm_result_des(&msg, &flow, &req);
        if (err < 0)
                return err;

        clock_gettime(PTHREAD_COND_CLOCK, &t0);

        err = poa_alloc(addr, flow.qs, &req, &resp, &pf, &mtu, timeo);

        freebuf(req);

        if (err < 0)
                goto fail_alloc;

        clock_gettime(PTHREAD_COND_CLOCK, &t1);

        flow.mtu = mtu;
        flow.mpl = pf->poa->mpl;
        msg.len  = SOCK_BUF_SIZE;
        msg.data = buf;
        if (poa_flow_alloc_r__irm_req_ser(&msg, &flow, &resp, 0) < 0) {
                err = -ENOMEM;
                goto fail_resp;
        }

        freebuf(resp);

        err = send_recv_msg(&msg);
        if (err < 0)
                goto fail_msg;

        crypt.key   = key;
        crypt.epoch = 0;
        crypt.role  = CRYPT_ROLE_INIT;

        err = flow__irm_result_des(&msg, &flow, &crypt);
        if (err < 0)
                goto fail_msg;

        err = flow_init(&flow, &crypt, ts_diff_ns(&t1, &t0), pf);

        crypt_secure_clear(key, SYMMKEYSZ);

        if (err < 0)
                goto fail_msg;

        if (qs != NULL)
                *qs = flow.qs;

        return err;

 fail_resp:
        freebuf(resp);
 fail_msg:
        poa_alloc_fail(pf);
        return err;
 fail_alloc:
        msg.len  = SOCK_BUF_SIZE;
        msg.data = buf;
        if (poa_flow_alloc_r__irm_req_ser(&msg, &flow, NULL, err) == 0)
                send_recv_msg(&msg);

        return err;
}

