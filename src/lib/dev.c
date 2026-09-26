/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * API for applications
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"
#include "cap.h"
#include "ssm.h"
#include "poa/poa.h"

#define OUROBOROS_PREFIX "libouroboros"

#include <ouroboros/atomics.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/cep.h>
#include <ouroboros/crc16.h>
#include <ouroboros/crypt.h>
#include <ouroboros/dev.h>
#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/flow.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/hash.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/list.h>
#include <ouroboros/local-dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/np1_flow.h>
#include <ouroboros/pthread.h>
#include <ouroboros/random.h>
#ifdef PROC_FLOW_STATS
#include <ouroboros/rib.h>
#endif
#include <ouroboros/serdes-irm.h>
#include <ouroboros/sockets.h>
#include <ouroboros/ssm_flow_set.h>
#include <ouroboros/ssm_pool.h>
#include <ouroboros/ssm_rbuff.h>
#include <ouroboros/time.h>
#include <ouroboros/tw.h>
#include <ouroboros/utils.h>

#include <assert.h>
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

#define NO_PART   -1
#define DONE_PART -2

#define CRCLEN    (sizeof(uint32_t))
#define FLOW_AVG_SHIFT 3
#define SECMEMSZ  16384
#define MSGBUFSZ  2048

struct fmap {
        int             fd;
        enum flow_state state;
};

struct flow {
        struct flow_info      info;

        struct ssm_rbuff *    rx_rb;
        struct ssm_rbuff *    tx_rb;
        struct ssm_flow_set * set;

        uint16_t              oflags;
        ssize_t               part_idx;

        struct crypt_ctx *    crypt;
        int                   headsz;         /* Selector                   */
        int                   tailsz;         /* Tag + CRC                  */

        struct timespec       rk_grace;       /* TX-promote deadline       */
        struct timespec       rk_attempt;     /* Last re-key attempt       */
        bool                  rk_wm_inflight; /* Re-key trigger in flight  */
        uint32_t              rk_wm_ctr;      /* Throttles the consult     */
        bool                  rk_initiator;   /* OAP initiator this re-key */

        struct timespec       snd_act;
        struct timespec       rcv_act;

        bool                  snd_timesout;
        bool                  rcv_timesout;
        struct timespec       snd_timeo;
        struct timespec       rcv_timeo;

        struct frcti *        frcti;

        /* Mean written packet size (bytes), EWMA over the send path. */
        size_t                mean_len;

        struct poa_flow *     poa;   /* NULL for shared memory flows */

        /* Egress capacity estimator; armed by the IPCP, else NULL. */
        struct cap_est *      cap;
};

struct flow_set {
        size_t           idx;
        pthread_rwlock_t lock;
};

struct fqueue {
        struct flowevent fqueue[SSM_RBUFF_SIZE]; /* Safe copy from shm. */
        size_t           fqsize;
        size_t           next;
};

struct {
        struct ssm_pool *     pool;
        struct ssm_flow_set * fqset;

        struct bmp *          fds;
        struct bmp *          fqueues;

        struct flow *         flows;
        struct fmap *         id_to_fd;

        uint32_t              max_rtt; /* IPCPs: declared layer RTT (ms) */

        pthread_mutex_t       mtx;
        pthread_cond_t        cond;

        pthread_rwlock_t      lock;
} proc;

static void flow_destroy(struct fmap * p)
{
        pthread_mutex_lock(&proc.mtx);

        if (p->state == FLOW_DESTROY) {
                pthread_mutex_unlock(&proc.mtx);
                return;
        }

        if (p->state == FLOW_ALLOC_PENDING)
                p->state = FLOW_DESTROY;
        else
                p->state = FLOW_NULL;

        pthread_cond_signal(&proc.cond);

        pthread_cleanup_push(__cleanup_mutex_unlock, &proc.mtx);

        while (p->state != FLOW_NULL)
                pthread_cond_wait(&proc.cond, &proc.mtx);

        p->fd    = -1;
        p->state = FLOW_INIT;

        pthread_cleanup_pop(true);
}

static void flow_set_state(struct fmap *   p,
                           enum flow_state state)
{
        pthread_mutex_lock(&proc.mtx);

        if (p->state == FLOW_DESTROY) {
                pthread_mutex_unlock(&proc.mtx);
                return;
        }

        p->state = state;
        pthread_cond_broadcast(&proc.cond);

        pthread_mutex_unlock(&proc.mtx);
}

static enum flow_state flow_wait_assign(int flow_id)
{
        enum flow_state state;
        struct fmap *   p;

        p = &proc.id_to_fd[flow_id];

        pthread_mutex_lock(&proc.mtx);

        if (p->state == FLOW_ALLOCATED) {
                pthread_mutex_unlock(&proc.mtx);
                return FLOW_ALLOCATED;
        }

        if (p->state == FLOW_INIT)
                p->state = FLOW_ALLOC_PENDING;

        pthread_cleanup_push(__cleanup_mutex_unlock, &proc.mtx);

        while (p->state == FLOW_ALLOC_PENDING)
                pthread_cond_wait(&proc.cond, &proc.mtx);

        if (p->state == FLOW_DESTROY) {
                p->state = FLOW_NULL;
                pthread_cond_broadcast(&proc.cond);
        }

        state = p->state;

        pthread_cleanup_pop(true);

        assert(state != FLOW_INIT);

        return state;
}

static int proc_announce(const struct proc_info * proc)
{
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        int              err;

        if (proc_announce__irm_req_ser(&msg, proc) < 0)
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        return irm__irm_result_des(&msg);
}

/* IRMd cleans up on failure. */
static void proc_exit(void)
{
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};

        if (proc_exit__irm_req_ser(&msg) < 0)
                return;

        send_recv_msg(&msg);
}

static int spb_encrypt(struct flow *        flow,
                       struct ssm_pk_buff * spb)
{
        buffer_t  in;
        buffer_t  out;
        uint8_t * head;
        uint8_t * tail;

        if (flow->crypt == NULL)
                return 0;

        in.data = ssm_pk_buff_head(spb);
        in.len  = ssm_pk_buff_len(spb);

        if (crypt_encrypt(flow->crypt, in, &out) < 0)
                return -ECRYPT;

        head = ssm_pk_buff_push(spb, flow->headsz);
        if (head == NULL)
                goto fail_alloc;

        tail = ssm_pk_buff_push_tail(spb, flow->tailsz);
        if (tail == NULL)
                goto fail_alloc;

        memcpy(head, out.data, out.len);

        freebuf(out);

        return 0;
 fail_alloc:
        freebuf(out);

        return -ECRYPT;
}

static int spb_decrypt(struct flow *        flow,
                       struct ssm_pk_buff * spb)
{
        buffer_t  in;
        buffer_t  out;
        uint8_t * head;

        if (flow->crypt == NULL)
                return 0;

        in.data = ssm_pk_buff_head(spb);
        in.len  = ssm_pk_buff_len(spb);

        if (crypt_decrypt(flow->crypt, in, &out) < 0)
                return -ECRYPT;

        head = ssm_pk_buff_pop(spb, flow->headsz) + flow->headsz;
        ssm_pk_buff_pop_tail(spb, flow->tailsz);

        memcpy(head, out.data, out.len);

        freebuf(out);

        return 0;
}

/* tw_move under proc.lock rdlock; gates teardown vs in-flight fires. */
static void tw_move_safe(void)
{
        pthread_rwlock_rdlock(&proc.lock);

        pthread_cleanup_push(__cleanup_rwlock_unlock, &proc.lock);

        tw_move();

        pthread_cleanup_pop(1);
}

static int crc_add(struct ssm_pk_buff * spb,
                   size_t               head_skip)
{
        uint8_t * head;
        uint8_t * tail;

        tail = ssm_pk_buff_push_tail(spb, CRCLEN);
        if (tail == NULL)
                return -ENOMEM;

        head = ssm_pk_buff_head(spb) + head_skip;

        mem_hash(HASH_CRC32, tail, head, tail - head);

        return 0;
}

static int crc_check(struct ssm_pk_buff * spb,
                     size_t               head_skip)
{
        uint32_t  crc;
        uint8_t * head;
        uint8_t * tail;

        if (ssm_pk_buff_len(spb) < head_skip + CRCLEN)
                return 1;

        head = ssm_pk_buff_head(spb) + head_skip;
        tail = ssm_pk_buff_pop_tail(spb, CRCLEN);

        mem_hash(HASH_CRC32, &crc, head, tail - head);

        return !(crc == *((uint32_t *) tail));
}

/* FRCT included here so it can use proc and dev.c statics directly. */
#include "frct.c"

/* Decrypt before any check so the plaintext is authoritative. */
static bool invalid_pkt(struct flow *        flow,
                        struct ssm_pk_buff * spb)
{
        const struct frct_pci * pci;
        uint16_t                flags;
        size_t                  pci_total;

        if (spb == NULL || ssm_pk_buff_len(spb) == 0)
                return true;

        if (spb_decrypt(flow, spb) < 0)
                return true;

        if (flow->frcti == NULL) {
                if (flow->info.qs.ber == 0 && crc_check(spb, 0) != 0)
                        return true;
                return false;
        }

        if (ssm_pk_buff_len(spb) < FRCT_PCILEN)
                return true;

        pci   = (const struct frct_pci *) ssm_pk_buff_head(spb);
        flags = ntoh16(pci->flags);

        /* Untrusted flag read; mismatch on HCS will drop on corrupt. */
        if (flags & FRCT_DATA)
                pci_total = frcti_data_hdr_len(flow->frcti);
        else
                pci_total = frcti_ctrl_hdr_len(flow->frcti);

        if (ssm_pk_buff_len(spb) < pci_total)
                return true;

        if (frct_hcs_check(pci, flow->frcti) != 0)
                return true;

        /* HCS valid: CRC32 on SACK; or on DATA if ber = 0. */
        if (flags & FRCT_SACK) {
                if (crc_check(spb, pci_total) != 0)
                        return true;

        } else if ((flags & FRCT_DATA) && flow->info.qs.ber == 0) {
                if (crc_check(spb, pci_total) != 0)
                        return true;
        }

        return false;
}

static bool deadline_passed(const struct timespec * abs)
{
        struct timespec now;

        if (abs == NULL)
                return false;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        return ts_diff_ns(&now, abs) >= 0;
}

/* Clamp the wait by min(dl, next tw expiry, now + TICTIME). */
static void compute_wait_deadline(const struct timespec * dl,
                                  struct timespec *       out)
{
        struct timespec now;
        struct timespec cap;
        struct timespec expiry;
        struct timespec tic = TIMESPEC_INIT_NS(TICTIME);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        ts_add(&now, &tic, &cap);

        tw_next_expiry(&expiry);

        *out = (ts_diff_ns(&cap, &expiry) < 0) ? expiry : cap;
        if (dl != NULL && ts_diff_ns(out, dl) > 0)
                *out = *dl;
}

static void flow_drain_rx_nb(struct flow * flow)
{
        ssize_t              idx;
        struct ssm_pk_buff * spb;
        struct ssm_rbuff *   rx_rb;
        struct frcti *       frcti;
#ifdef PROC_FLOW_STATS
        struct timespec      t_a;
        struct timespec      t_b;
#endif

        if (flow->frcti != NULL)
                STAT_BUMP(flow->frcti, drain_calls);

        while (true) {
                pthread_rwlock_rdlock(&proc.lock);

                rx_rb = flow->rx_rb;
                if (rx_rb == NULL) {
                        pthread_rwlock_unlock(&proc.lock);
                        return;
                }

                idx = ssm_rbuff_read(rx_rb);
                if (idx < 0) {
                        pthread_rwlock_unlock(&proc.lock);
                        return;
                }

                spb = ssm_pool_get(proc.pool, idx);
                if (invalid_pkt(flow, spb)) {
                        ssm_pool_remove(proc.pool, idx);
                        pthread_rwlock_unlock(&proc.lock);
                        continue;
                }

                frcti = flow->frcti;
                if (frcti != NULL) {
#ifdef PROC_FLOW_STATS
                        clock_gettime(CLOCK_MONOTONIC, &t_a);
                        FRCTI_RCV(frcti, spb);
                        clock_gettime(CLOCK_MONOTONIC, &t_b);
                        STAT_ADD(frcti, rcv_proc_ns,
                                 (size_t) ts_diff_ns(&t_b, &t_a));
#else
                        FRCTI_RCV(frcti, spb);
#endif
                } else {
                        ssm_pool_remove(proc.pool, idx);
                }

                pthread_rwlock_unlock(&proc.lock);

                /* Per-packet so the delayed-ACK fires on time in a burst. */
#ifdef PROC_FLOW_STATS
                clock_gettime(CLOCK_MONOTONIC, &t_a);
                tw_move_safe();
                clock_gettime(CLOCK_MONOTONIC, &t_b);
                if (frcti != NULL)
                        STAT_ADD(frcti, tw_move_ns,
                                 (size_t) ts_diff_ns(&t_b, &t_a));
#else
                tw_move_safe();
#endif
        }
}

/* TX-promotion grace when the peer's install latency is unknown (raw). */
#define REKEY_GRACE_MS 1000

/* Last-resort promote within N node-keys of exhaustion (< watermark). */
#define REKEY_PROMOTE_FLOOR 1

/* Throttle re-key retries so a failed attempt can't storm the IRMd. */
#define REKEY_BACKOFF_NS (250 * MILLION)

/* proc.lock (rd) only guards teardown; crypt_rekey self-synchronises. */
static void flow_rekey(struct flow * flow)
{
        struct flow_info info;
        struct crypt_sk  sk;
        struct timespec  now;
        struct timespec  intv;
        time_t           ms;
        uint8_t          key[SYMMKEYSZ];
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        bool             has_key;
        bool             initiator = false;

        pthread_rwlock_rdlock(&proc.lock);
        if (flow->info.id < 0 || flow->crypt == NULL) {
                pthread_rwlock_unlock(&proc.lock);
                return;
        }

        /* Back off so a failed attempt can't storm the IRMd per syscall. */
        clock_gettime(PTHREAD_COND_CLOCK, &now);
        if (ts_diff_ns(&now, &flow->rk_attempt) < REKEY_BACKOFF_NS) {
                pthread_rwlock_unlock(&proc.lock);
                return;
        }

        flow->rk_attempt = now;
        info = flow->info;
        pthread_rwlock_unlock(&proc.lock);

        if (flow_update__irm_req_ser(&msg, &info, false) < 0)
                return;

        if (send_recv_msg(&msg) < 0)
                return;

        sk.key = key;
        if (flow_rekey__irm_result_des(&msg, &sk, &has_key, &initiator) < 0)
                return;

        if (!has_key)
                return;

        pthread_rwlock_rdlock(&proc.lock);
        if (flow->info.id == info.id && flow->crypt != NULL) {
                if (crypt_rekey(flow->crypt, &sk) == 0) {
                        flow->rk_initiator = initiator;
                        /* Hold TX on the old epoch until the peer installs. */
                        ms = flow->info.mpl > 0 ? flow->info.mpl * 3
                                                : REKEY_GRACE_MS;
                        intv.tv_sec  = ms / 1000;
                        intv.tv_nsec = (ms % 1000) * MILLION;
                        clock_gettime(PTHREAD_COND_CLOCK, &now);
                        ts_add(&now, &intv, &flow->rk_grace);
                }
                /* Re-arm the watermark even if the install was a no-op. */
                STORE_RELAXED(&flow->rk_wm_inflight, false);
        }
        pthread_rwlock_unlock(&proc.lock);

        crypt_secure_clear(key, SYMMKEYSZ);
}

/* A clamp-timeout means tw work is due, not the caller deadline. */
static int flow_rx_one(struct flow *     flow,
                       struct timespec * abs)
{
        struct timespec      wait_abs;
        struct ssm_pk_buff * spb;
        struct ssm_rbuff *   rx_rb;
        ssize_t              idx;

        while (true) {
                compute_wait_deadline(abs, &wait_abs);

                /* rdlock gates flow_fini; FLOWDOWN preempts the block. */
                pthread_rwlock_rdlock(&proc.lock);

                rx_rb = flow->rx_rb;
                if (rx_rb == NULL) {
                        pthread_rwlock_unlock(&proc.lock);
                        return -EFLOWDOWN;
                }

                /* Pull a parked re-key before re-blocking (idle reader). */
                if (flow->crypt != NULL
                    && (ssm_rbuff_get_flags(rx_rb) & RB_REKEY)) {
                        pthread_rwlock_unlock(&proc.lock);
                        flow_rekey(flow);
                        continue;
                }

                pthread_cleanup_push(__cleanup_rwlock_unlock, &proc.lock);

                idx = ssm_rbuff_read_b(rx_rb, &wait_abs);

                pthread_cleanup_pop(false);

                if (idx == -ETIMEDOUT) {
                        pthread_rwlock_unlock(&proc.lock);
                        if (deadline_passed(abs))
                                return -ETIMEDOUT;
                        tw_move_safe();
                        continue;
                }
                if (idx < 0) {
                        pthread_rwlock_unlock(&proc.lock);
                        return idx;
                }

                spb = ssm_pool_get(proc.pool, idx);
                if (invalid_pkt(flow, spb)) {
                        ssm_pool_remove(proc.pool, idx);
                        pthread_rwlock_unlock(&proc.lock);
                        continue;
                }

                if (flow->frcti != NULL)
                        FRCTI_RCV(flow->frcti, spb);
                else
                        ssm_pool_remove(proc.pool, idx);

                pthread_rwlock_unlock(&proc.lock);

                tw_move_safe();
                return 0;
        }
}

/* 0 = window open; -EAGAIN = !block and would block; else flow_rx_one rc. */
static __inline__ int flow_wait_window(struct flow *     flow,
                                       size_t            n,
                                       bool              block,
                                       struct timespec * dl)
{
        int rc;

        while (true) {
                flow_drain_rx_nb(flow);
                if (FRCTI_IS_WINDOW_OPEN_N(flow->frcti, n))
                        return 0;
                if (!block)
                        return -EAGAIN;
                rc = flow_rx_one(flow, dl);
                if (rc < 0)
                        return rc;
        }
}

static void flow_clear(int fd)
{
        memset(&proc.flows[fd], 0, sizeof(proc.flows[fd]));

        proc.flows[fd].info.id  = -1;
        proc.flows[fd].part_idx = NO_PART;
}

/* Order before flow_fini's wrlock, which blocks on rdlock holders. */
static void flow_quiesce(int fd)
{
        struct ssm_rbuff * rx_rb = proc.flows[fd].rx_rb;
        struct ssm_rbuff * tx_rb = proc.flows[fd].tx_rb;

        if (rx_rb != NULL)
                ssm_rbuff_set_flags(rx_rb, RB_FLOWDOWN);

        if (tx_rb != NULL)
                ssm_rbuff_set_flags(tx_rb, RB_FLOWDOWN);
}

static void do_flow_fini(int fd)
{
        assert(fd >= 0 && fd < PROC_MAX_FLOWS);

        if (proc.flows[fd].poa != NULL)
                poa_flow_detach(proc.flows[fd].poa);

        if (proc.flows[fd].frcti != NULL)
                frcti_destroy(proc.flows[fd].frcti);

        if (proc.flows[fd].part_idx >= 0)
                ssm_pool_remove(proc.pool, proc.flows[fd].part_idx);

        if (proc.flows[fd].info.id != -1) {
                flow_destroy(&proc.id_to_fd[proc.flows[fd].info.id]);
                bmp_release(proc.fds, fd);
        }

        if (proc.flows[fd].rx_rb != NULL)
                ssm_rbuff_close(proc.flows[fd].rx_rb);

        if (proc.flows[fd].tx_rb != NULL)
                ssm_rbuff_close(proc.flows[fd].tx_rb);

        if (proc.flows[fd].set != NULL) {
                ssm_flow_set_notify(proc.flows[fd].set,
                                    proc.flows[fd].info.id,
                                    FLOW_DEALLOC);
                ssm_flow_set_close(proc.flows[fd].set);
        }

        crypt_destroy_ctx(proc.flows[fd].crypt);

        free(proc.flows[fd].cap);

        flow_clear(fd);
}

static void flow_fini(int fd)
{
        flow_quiesce(fd);

        pthread_rwlock_wrlock(&proc.lock);

        do_flow_fini(fd);

        pthread_rwlock_unlock(&proc.lock);
}

#define IS_ENCRYPTED(crypt) ((crypt)->nid != NID_undef)
#define IS_ORDERED(info)    ((info)->qs.service != SVC_RAW)
#define IS_STREAM(info)     ((info)->qs.service == SVC_STREAM)

/* Raw MTU minus the wrapping (IV/Tag + optional CRC) dev.c adds. */
static __inline__ size_t flow_user_mtu(const struct flow * flow,
                                       size_t              raw)
{
        size_t hdr;

        hdr = flow->headsz + flow->tailsz;
        if (flow->info.qs.ber == 0 && flow->crypt == NULL)
                hdr += CRCLEN;

        return raw > hdr ? raw - hdr : 0;
}

/* A PoA flow transmits on its own socket; it has no tx ring. */
static int flow_init(struct flow_info * info,
                     struct crypt_sk *  sk,
                     time_t             rtt_hint,
                     struct poa_flow *  pf)
{
        struct timespec    now;
        struct timespec    txq;
        struct flow *      flow;
        struct ssm_rbuff * tx_rb = NULL;
        int                fd;
        int                err = -ENOMEM;

        if (info->id < 0 || info->id >= SYS_MAX_FLOWS)
                return -EBADF;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_wrlock(&proc.lock);

        fd = bmp_allocate(proc.fds);
        if (!bmp_is_id_valid(proc.fds, fd)) {
                err = -EBADF;
                goto fail_fds;
        }

        flow = &proc.flows[fd];

        flow->info = *info;

        flow->rx_rb = ssm_rbuff_open(info->n_pid, info->id);
        if (flow->rx_rb == NULL)
                goto fail_rx_rb;

        if (pf == NULL) {
                flow->tx_rb = ssm_rbuff_open(info->n_1_pid, info->id);
                if (flow->tx_rb == NULL)
                        goto fail_tx_rb;

                tx_rb = flow->tx_rb;

                flow->set = ssm_flow_set_open(info->n_1_pid);
                if (flow->set == NULL)
                        goto fail_set;
        }

        flow->oflags   = FLOWFDEFAULT;
        flow->part_idx = NO_PART;
        flow->snd_act  = now;
        flow->rcv_act  = now;
        flow->crypt    = NULL;
        flow->headsz   = 0;
        flow->tailsz   = 0;
        flow->poa      = pf;

        if (IS_ENCRYPTED(sk)) {
                flow->crypt = crypt_create_ctx(sk);
                if (flow->crypt == NULL) {
                        err = -ECRYPT;
                        goto fail_crypt;
                }
                flow->headsz = crypt_get_headsz(flow->crypt);
                flow->tailsz = crypt_get_tagsz(flow->crypt);
        }

        assert(flow->frcti == NULL);

        if (IS_ORDERED(&flow->info)) {
                uint32_t frct_mtu = flow_user_mtu(flow, info->mtu);

                flow->frcti = frcti_create(fd, DELT_A, DELT_R,
                                           info->mpl, rtt_hint, info->max_rtt,
                                           info->qs, frct_mtu);
                if (flow->frcti == NULL)
                        goto fail_frcti;
        }

        proc.id_to_fd[info->id].fd = fd;

        if (pf != NULL)
                poa_flow_attach(pf, info->id, flow->rx_rb);

        flow_set_state(&proc.id_to_fd[info->id], FLOW_ALLOCATED);

        pthread_rwlock_unlock(&proc.lock);

        if (tx_rb != NULL) {
                txq.tv_sec  = SSM_RBUFF_TXQ_DELAY / 1000;
                txq.tv_nsec = (SSM_RBUFF_TXQ_DELAY % 1000) * MILLION;

                ssm_rbuff_set_txq_target(tx_rb, &txq);
        }

        return fd;

 fail_frcti:
        crypt_destroy_ctx(flow->crypt);
 fail_crypt:
        if (flow->set != NULL)
                ssm_flow_set_close(flow->set);
 fail_set:
        if (flow->tx_rb != NULL)
                ssm_rbuff_close(flow->tx_rb);
 fail_tx_rb:
        ssm_rbuff_close(flow->rx_rb);
 fail_rx_rb:
        bmp_release(proc.fds, fd);
 fail_fds:
        pthread_rwlock_unlock(&proc.lock);
        return err;
}

static bool check_python(char * str)
{
        if (!strcmp(path_strip(str), "python") ||
            !strcmp(path_strip(str), "python2") ||
            !strcmp(path_strip(str), "python3"))
                return true;

        return false;
}

static void init(int     argc,
                 char ** argv,
                 char ** envp)
{
        struct proc_info     info;
        char *               prog = argv[0];
        int                  i;
        pthread_rwlockattr_t attr;
#ifdef PROC_FLOW_STATS
        char   procstr[32];
#endif
        (void) argc;
        (void) envp;

        if (check_python(argv[0]))
                prog = argv[1];

        prog = path_strip(prog);
        if (prog == NULL) {
                fprintf(stderr, "FATAL: Could not determine program name.\n");
                goto fail_prog;
        }

        memset(&info, 0, sizeof(info));
        info.pid = getpid();
        strncpy(info.prog, prog, PROG_NAME_SIZE);

        if (proc_announce(&info)) {
                fprintf(stderr, "FATAL: Could not announce to IRMd.\n");
                goto fail_prog;
        }

#ifdef HAVE_LIBGCRYPT
        if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
                if (!gcry_check_version(GCRYPT_VERSION)) {
                        fprintf(stderr, "FATAL: Could not get gcry version.\n");
                        goto fail_prog;
                }
                gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
                gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
#endif
        proc.fds = bmp_create(PROC_MAX_FLOWS - PROC_RES_FDS, PROC_RES_FDS);
        if (proc.fds == NULL) {
                fprintf(stderr, "FATAL: Could not create fd bitmap.\n");
                goto fail_fds;
        }

        proc.fqueues = bmp_create(PROC_MAX_FQUEUES, 0);
        if (proc.fqueues == NULL) {
                fprintf(stderr, "FATAL: Could not create fqueue bitmap.\n");
                goto fail_fqueues;
        }

        if (is_ouroboros_member_uid(getuid()))
                proc.pool = ssm_pool_open(0);
        else
                proc.pool = ssm_pool_open(getuid());

        if (proc.pool == NULL) {
                fprintf(stderr, "FATAL: Could not open packet buffer.\n");
                goto fail_rdrb;
        }

        proc.flows = malloc(sizeof(*proc.flows) * PROC_MAX_FLOWS);
        if (proc.flows == NULL) {
                fprintf(stderr, "FATAL: Could not malloc flows.\n");
                goto fail_flows;
        }

        for (i = 0; i < PROC_MAX_FLOWS; ++i)
                flow_clear(i);

        proc.id_to_fd = malloc(sizeof(*proc.id_to_fd) * SYS_MAX_FLOWS);
        if (proc.id_to_fd == NULL) {
                fprintf(stderr, "FATAL: Could not malloc id_to_fd.\n");
                goto fail_id_to_fd;
        }

        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                proc.id_to_fd[i].state = FLOW_INIT;

        if (pthread_mutex_init(&proc.mtx, NULL)) {
                fprintf(stderr, "FATAL: Could not init mutex.\n");
                goto fail_mtx;
        }

        if (pthread_cond_init(&proc.cond, NULL) < 0) {
                fprintf(stderr, "FATAL: Could not init condvar.\n");
                goto fail_cond;
        }

        /* Writer-preferred: FRCT readers must not starve flow accept. */
        if (pthread_rwlockattr_init(&attr) != 0) {
                fprintf(stderr, "FATAL: Could not init rwlock attributes.\n");
                goto fail_rwlock_attr;
        }
#if defined(__GLIBC__)
        pthread_rwlockattr_setkind_np(
                &attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
        if (pthread_rwlock_init(&proc.lock, &attr) != 0) {
                fprintf(stderr, "FATAL: Could not initialize flow lock.\n");
                goto fail_flow_lock;
        }

        proc.fqset = ssm_flow_set_open(getpid());
        if (proc.fqset == NULL) {
                fprintf(stderr, "FATAL: Could not open flow set.\n");
                goto fail_fqset;
        }

        if (tw_init() < 0) {
                fprintf(stderr, "FATAL: Could not initialize timerwheel.\n");
                goto fail_timerwheel;
        }

        if (crypt_secure_malloc_init(PROC_SECMEM_MAX) < 0) {
                fprintf(stderr, "FATAL: Could not init secure malloc.\n");
                goto fail_secmem;
        }

#if defined PROC_FLOW_STATS
        if (strstr(argv[0], "ipcpd") == NULL) {
                sprintf(procstr, "proc.%d", getpid());
                if (rib_init(procstr) < 0) {
                        fprintf(stderr, "FATAL: Could not initialize RIB.\n");
                        goto fail_rib_init;
                }
        }
#endif
        pthread_rwlockattr_destroy(&attr);

        return;

#if defined PROC_FLOW_STATS
 fail_rib_init:
        crypt_secure_malloc_fini();
#endif
 fail_secmem:
        tw_fini();
 fail_timerwheel:
        ssm_flow_set_close(proc.fqset);
 fail_fqset:
        pthread_rwlock_destroy(&proc.lock);
 fail_flow_lock:
        pthread_rwlockattr_destroy(&attr);
 fail_rwlock_attr:
        pthread_cond_destroy(&proc.cond);
 fail_cond:
        pthread_mutex_destroy(&proc.mtx);
 fail_mtx:
        free(proc.id_to_fd);
 fail_id_to_fd:
        free(proc.flows);
 fail_flows:
        ssm_pool_close(proc.pool);
 fail_rdrb:
        bmp_destroy(proc.fqueues);
 fail_fqueues:
        bmp_destroy(proc.fds);
 fail_fds:
        memset(&proc, 0, sizeof(proc));
 fail_prog:
        exit(EXIT_FAILURE);
}

static void fini(void)
{
        int  i;

        if (proc.fds == NULL)
                return;

        /* Wake all in-flight readers/writers BEFORE wrlock acquire. */
        for (i = 0; i < PROC_MAX_FLOWS; ++i)
                if (proc.flows[i].info.id != -1)
                        flow_quiesce(i);

        pthread_rwlock_wrlock(&proc.lock);

        for (i = 0; i < PROC_MAX_FLOWS; ++i) {
                struct flow * flow = &proc.flows[i];
                if (flow->info.id != -1) {
                        ssize_t idx;
                        while ((idx = ssm_rbuff_read(flow->rx_rb)) >= 0)
                                ssm_pool_remove(proc.pool, idx);
                        do_flow_fini(i);
                }
        }

        pthread_cond_destroy(&proc.cond);
        pthread_mutex_destroy(&proc.mtx);

        pthread_rwlock_unlock(&proc.lock);

#ifdef PROC_FLOW_STATS
        rib_fini();
#endif
        crypt_secure_malloc_fini();

        tw_fini();

        ssm_flow_set_close(proc.fqset);

        pthread_rwlock_destroy(&proc.lock);

        free(proc.flows);
        free(proc.id_to_fd);

        ssm_pool_close(proc.pool);

        bmp_destroy(proc.fds);
        bmp_destroy(proc.fqueues);

        proc_exit();

        memset(&proc, 0, sizeof(proc));
}

#if defined(__MACH__) && defined(__APPLE__)
#define INIT_SECTION "__DATA, __mod_init_func"
#define FINI_SECTION "__DATA, __mod_term_func"
#else
#define INIT_SECTION ".init_array"
#define FINI_SECTION ".fini_array"
#endif

__attribute__((section(INIT_SECTION))) __typeof__(init) * __init = init;
__attribute__((section(FINI_SECTION))) __typeof__(fini) * __fini = fini;

static int irm_flow_dealloc(int                     id,
                            const struct timespec * timeo)
{
        struct flow_info info;
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        int              err;

        memset(&info, 0, sizeof(info));

        info.id    = id;
        info.n_pid = getpid();
        if (flow_dealloc__irm_req_ser(&msg, &info, timeo) < 0)
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        return irm__irm_result_des(&msg);
}

/* Returns a flow the IRMd handed us that we could not set up. */
static void flow_release(int id)
{
        struct timespec timeo = TIMESPEC_INIT_S(0);

        if (id < 0 || id >= SYS_MAX_FLOWS)
                return;

        irm_flow_dealloc(id, &timeo);
}

/*
 * A PoA flow is announced by its peer before the accept; from the
 * reply on, the peer may transmit, so the flow must be able to
 * receive.
 */
int flow_accept(qosspec_t *             qs,
                const struct timespec * timeo)
{
        struct flow_info  flow;
        struct crypt_sk   crypt;
        uint8_t           buf[SOCK_BUF_SIZE];
        buffer_t          msg = {SOCK_BUF_SIZE, buf};
        uint8_t           key[SYMMKEYSZ];
        struct poa_flow * pf;
        int               fd;
        int               err;

#ifdef QOS_DISABLE_CRC
        if (qs != NULL)
                qs->ber = 1;
#endif
        /* STREAM cannot tolerate loss: drops create silent gaps. */
        if (qs != NULL && qs->service == SVC_STREAM && qs->loss != 0)
                return -EINVAL;

        memset(&flow, 0, sizeof(flow));

        flow.n_pid = getpid();
        flow.qs    = qs == NULL ? qos_raw : *qs;

        if (flow_accept__irm_req_ser(&msg, &flow, timeo))
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        crypt.key        = key;
        crypt.epoch      = 0;
        crypt.role       = CRYPT_ROLE_RESP;

        err = flow__irm_result_des(&msg, &flow, &crypt);
        if (err < 0)
                return err;

        err = poa_flow_take_pending(&flow, &pf);
        if (err < 0)
                goto fail_pending;

        fd = flow_init(&flow, &crypt, 0, pf);
        if (fd < 0) {
                err = fd;
                goto fail_init;
        }

        poa_flow_ready(pf);

        crypt_secure_clear(key, SYMMKEYSZ);

        if (qs != NULL)
                *qs = flow.qs;

        return fd;

 fail_init:
        if (pf != NULL)
                poa_flow_detach(pf);
 fail_pending:
        crypt_secure_clear(key, SYMMKEYSZ);
        flow_release(flow.id);
        return err;
}

int flow_alloc(const char *            dst,
               qosspec_t *             qs,
               const struct timespec * timeo)
{
        struct flow_info  flow;
        struct crypt_sk crypt;
        uint8_t           buf[SOCK_BUF_SIZE];
        buffer_t          msg = {SOCK_BUF_SIZE, buf};
        uint8_t           key[SYMMKEYSZ];
        int               fd;
        int               err;
        struct timespec   t0;
        struct timespec   t1;

#ifdef QOS_DISABLE_CRC
        if (qs != NULL)
                qs->ber = 1;
#endif
        /* STREAM cannot tolerate loss: drops create silent gaps. */
        if (qs != NULL && qs->service == SVC_STREAM && qs->loss != 0)
                return -EINVAL;

        memset(&flow, 0, sizeof(flow));

        flow.n_pid = getpid();
        flow.qs    = qs == NULL ? qos_raw : *qs;

        if (flow_alloc__irm_req_ser(&msg, &flow, dst, timeo))
                return -ENOMEM;

        clock_gettime(PTHREAD_COND_CLOCK, &t0);

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        clock_gettime(PTHREAD_COND_CLOCK, &t1);

        crypt.key        = key;
        crypt.epoch      = 0;
        crypt.role       = CRYPT_ROLE_INIT;

        err = flow__irm_result_des(&msg, &flow, &crypt);
        if (err < 0)
                return err;

        fd = flow_init(&flow, &crypt, ts_diff_ns(&t1, &t0), NULL);

        crypt_secure_clear(key, SYMMKEYSZ);

        if (qs != NULL)
                *qs = flow.qs;

        return fd;
}

int flow_join(const char *            dst,
              const struct timespec * timeo)
{
        struct flow_info  flow;
        struct crypt_sk crypt;
        uint8_t           buf[SOCK_BUF_SIZE];
        buffer_t          msg = {SOCK_BUF_SIZE, buf};
        uint8_t           key[SYMMKEYSZ];
        int               fd;
        int               err;

        memset(&flow, 0, sizeof(flow));

        flow.n_pid = getpid();
        flow.qs    = qos_np1;

        if (flow_join__irm_req_ser(&msg, &flow, dst, timeo))
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        crypt.key        = key;
        crypt.epoch      = 0;
        crypt.role       = CRYPT_ROLE_INIT;

        err = flow__irm_result_des(&msg, &flow, &crypt);
        if (err < 0)
                return err;

        fd = flow_init(&flow, &crypt, 0, NULL);

        crypt_secure_clear(key, SYMMKEYSZ);

        return fd;
}

#define PKT_BUF_LEN 2048
int flow_dealloc(int fd)
{
        struct flow_info info;
        uint8_t          pkt[PKT_BUF_LEN];
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        struct timespec  tic   = TIMESPEC_INIT_NS(TICTIME);
        struct timespec  timeo = TIMESPEC_INIT_S(0);
        struct flow *    flow;
        int              err;

        if (fd < 0 || fd >= PROC_MAX_FLOWS )
                return -EINVAL;

        memset(&info, 0, sizeof(info));

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTALLOC;
        }

        flow->oflags = FLOWFDEFAULT | FLOWFRNOPART;

        flow->rcv_timesout = true;
        flow->rcv_timeo = tic;

        pthread_rwlock_unlock(&proc.lock);

        frcti_set_draining(flow->frcti);

        flow_read(fd, buf, SOCK_BUF_SIZE);

        pthread_rwlock_rdlock(&proc.lock);

        while (FRCTI_LINGERING(flow->frcti)) {
                ssize_t ret;

                pthread_rwlock_unlock(&proc.lock);

                ret = flow_read(fd, pkt, PKT_BUF_LEN);

                pthread_rwlock_rdlock(&proc.lock);

                if (ret == -EFLOWDOWN)
                        break;
        }

        timeo.tv_sec = FRCTI_DEALLOC(flow->frcti);

        pthread_cleanup_push(__cleanup_rwlock_unlock, &proc.lock);

        if (flow->tx_rb != NULL)
                ssm_rbuff_fini(flow->tx_rb);

        pthread_cleanup_pop(true);

        info.id  = flow->info.id;
        info.n_pid = getpid();

        if (flow_dealloc__irm_req_ser(&msg, &info, &timeo) < 0) {
                err = -ENOMEM;
                goto out;
        }

        err = send_recv_msg(&msg);
        if (err < 0)
                goto out;

        err = irm__irm_result_des(&msg);

 out:
        flow_fini(fd);

        return err;
}

int ipcp_flow_dealloc(int fd)
{
        struct flow_info info;
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        struct flow *    flow;
        int              err;

        if (fd < 0 || fd >= PROC_MAX_FLOWS )
                return -EINVAL;

        flow = &proc.flows[fd];

        memset(&info, 0, sizeof(info));

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTALLOC;
        }

        info.id      = flow->info.id;
        info.n_1_pid = flow->info.n_1_pid;

        pthread_rwlock_unlock(&proc.lock);

        if (ipcp_flow_dealloc__irm_req_ser(&msg, &info) < 0) {
                err = -ENOMEM;
                goto out;
        }

        err = send_recv_msg(&msg);
        if (err < 0)
                goto out;

        err = irm__irm_result_des(&msg);

 out:
        flow_fini(fd);

        return err;
}

/* A settable delay is a normalised, non-negative timespec. */
static bool delay_is_valid(const struct timespec * ts)
{
        if (ts->tv_sec < 0 || ts->tv_nsec < 0)
                return false;

        if (ts->tv_nsec >= BILLION)
                return false;

        return TS_TO_UINT64(*ts) <= SSM_RBUFF_TXQ_MAX_DELAY;
}

int fccntl(int fd,
           int cmd,
           ...)
{
        uint32_t *        fflags;
        uint16_t *        cflags;
        uint16_t          csflags;
        va_list           l;
        struct timespec * timeo;
        qosspec_t *       qs;
        size_t *          qlen;
        struct flow *     flow;
        uint16_t          old_acc;
        uint16_t          new_acc;
        size_t            max;
        size_t *          maxp;
        size_t            rsz;
        size_t *          rszp;
        time_t            rto;
        time_t *          rtop;
        int               rc;
        bool              emit_eos = false;
        bool              set_txq  = false;

        if (fd < 0 || fd >= PROC_MAX_FLOWS)
                return -EBADF;

        flow = &proc.flows[fd];

        va_start(l, cmd);

        pthread_rwlock_wrlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                va_end(l);
                return -ENOTALLOC;
        }

        switch(cmd) {
        case FLOWSSNDTIMEO:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL) {
                        flow->snd_timesout = false;
                } else {
                        flow->snd_timesout = true;
                        flow->snd_timeo    = *timeo;
                }
                break;
        case FLOWGSNDTIMEO:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL)
                        goto einval;
                if (!flow->snd_timesout)
                        goto eperm;
                *timeo = flow->snd_timeo;
                break;
        case FLOWSRCVTIMEO:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL) {
                        flow->rcv_timesout = false;
                } else {
                        flow->rcv_timesout = true;
                        flow->rcv_timeo    = *timeo;
                }
                break;
        case FLOWGRCVTIMEO:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL)
                        goto einval;
                if (!flow->rcv_timesout)
                        goto eperm;
                *timeo = flow->rcv_timeo;
                break;
        case FLOWGQOSSPEC:
                qs = va_arg(l, qosspec_t *);
                if (qs == NULL)
                        goto einval;
                *qs = flow->info.qs;
                break;
        case FLOWGRXQLEN:
                qlen  = va_arg(l, size_t *);
                *qlen = ssm_rbuff_queued(flow->rx_rb);
                break;
        case FLOWGTXQLEN:
                qlen  = va_arg(l, size_t *);

                if (flow->poa != NULL)
                        *qlen = poa_flow_qpkts(flow->poa);
                else
                        *qlen = ssm_rbuff_queued(flow->tx_rb);
                break;
        case FLOWGMTU:
                maxp = va_arg(l, size_t *);
                if (maxp == NULL)
                        goto einval;
                *maxp = flow_user_mtu(flow, flow->info.mtu);
                break;
        case FLOWSTXQDLY:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL)
                        goto einval;

                if (flow->tx_rb == NULL)
                        goto eperm;

                if (!delay_is_valid(timeo))
                        goto einval;

                set_txq = true;
                break;
        case FLOWGTXQDLY:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL)
                        goto einval;

                if (flow->tx_rb == NULL)
                        goto eperm;
                ssm_rbuff_get_txq_target(flow->tx_rb, timeo);
                break;
        case FLOWSFLAGS:
                old_acc = flow->oflags & FLOWFACCMODE;
                flow->oflags = va_arg(l, uint32_t);
                new_acc = flow->oflags & FLOWFACCMODE;

                /* Defer EOS emit until after proc.lock is dropped: */
                /* frcti_fin_snd may block on shm-pool/tx-rb. */
                if (new_acc == FLOWFRDONLY
                    && old_acc != FLOWFRDONLY
                    && flow->frcti != NULL)
                        emit_eos = true;

                /* Our flow write-only -> peer's read-only; restore on RDWR. */
                if (flow->oflags & FLOWFWRONLY)
                        ssm_rbuff_clr_flags(flow->rx_rb, RB_WR);
                else
                        ssm_rbuff_set_flags(flow->rx_rb, RB_WR);

                if (flow->oflags & FLOWFDOWN) {
                        ssm_rbuff_set_flags(flow->rx_rb, RB_FLOWDOWN);
                        if (flow->tx_rb != NULL)
                                ssm_rbuff_set_flags(flow->tx_rb, RB_FLOWDOWN);
                        if (flow->set != NULL)
                                ssm_flow_set_notify(flow->set, flow->info.id,
                                                    FLOW_DOWN);
                } else {
                        ssm_rbuff_clr_flags(flow->rx_rb, RB_FLOWDOWN);
                        if (flow->tx_rb != NULL)
                                ssm_rbuff_clr_flags(flow->tx_rb, RB_FLOWDOWN);
                        if (flow->set != NULL)
                                ssm_flow_set_notify(flow->set, flow->info.id,
                                                    FLOW_UP);
                }

                break;
        case FLOWGFLAGS:
                fflags = va_arg(l, uint32_t *);
                if (fflags == NULL)
                        goto einval;
                *fflags = flow->oflags;
                break;
        case FRCTSFLAGS:
                csflags = (uint16_t) va_arg(l, uint32_t);
                if (flow->frcti == NULL)
                        goto eperm;
                frcti_setflags(flow->frcti, csflags);
                break;
        case FRCTGFLAGS:
                cflags = (uint16_t *) va_arg(l, uint32_t *);
                if (cflags == NULL)
                        goto einval;
                if (flow->frcti == NULL)
                        goto eperm;
                *cflags = frcti_getflags(flow->frcti);
                break;
        case FRCTSMAXSDU:
                max = va_arg(l, size_t);
                if (flow->frcti == NULL)
                        goto eperm;
                if (frcti_set_max_rcv_sdu(flow->frcti, max) < 0)
                        goto einval;
                break;
        case FRCTGMAXSDU:
                maxp = va_arg(l, size_t *);
                if (maxp == NULL)
                        goto einval;
                if (flow->frcti == NULL)
                        goto eperm;
                *maxp = frcti_get_max_rcv_sdu(flow->frcti);
                break;
        case FRCTSRRINGSZ:
                rsz = va_arg(l, size_t);
                if (flow->frcti == NULL)
                        goto eperm;
                rc = frcti_set_rcv_ring_sz(flow->frcti, rsz);
                if (rc < 0) {
                        pthread_rwlock_unlock(&proc.lock);
                        va_end(l);
                        return rc;
                }
                break;
        case FRCTGRRINGSZ:
                rszp = va_arg(l, size_t *);
                if (rszp == NULL)
                        goto einval;
                if (flow->frcti == NULL)
                        goto eperm;
                *rszp = frcti_get_rcv_ring_sz(flow->frcti);
                break;
        case FRCTSRTOMIN:
                if (flow->frcti == NULL)
                        goto eperm;
                rto = va_arg(l, time_t);
                rc  = frcti_set_rto_min(flow->frcti, rto);
                if (rc < 0) {
                        pthread_rwlock_unlock(&proc.lock);
                        va_end(l);
                        return rc;
                }
                break;
        case FRCTGRTOMIN:
                if (flow->frcti == NULL)
                        goto eperm;
                rtop = va_arg(l, time_t *);
                if (rtop == NULL)
                        goto einval;
                *rtop = frcti_get_rto_min(flow->frcti);
                break;
        default:
                pthread_rwlock_unlock(&proc.lock);
                va_end(l);
                return -ENOTSUP;

        };

        pthread_rwlock_unlock(&proc.lock);

        if (emit_eos)
                frcti_fin_snd(flow->frcti);

        if (set_txq)
                ssm_rbuff_set_txq_target(flow->tx_rb, timeo);

        va_end(l);

        return 0;

 einval:
        pthread_rwlock_unlock(&proc.lock);
        va_end(l);
        return -EINVAL;
 eperm:
        pthread_rwlock_unlock(&proc.lock);
        va_end(l);
        return -EPERM;
}

/*
 * The ring counts slots, so the queue is only bytes if we know what a
 * packet weighs. Ordered so the unsigned arithmetic cannot wrap.
 */
static void flow_mean_len_update(struct flow * flow,
                                 size_t        len)
{
        size_t avg = LOAD_RELAXED(&flow->mean_len);

        if (avg == 0) {
                STORE_RELAXED(&flow->mean_len, len);
                return;
        }

        avg = avg + (len >> FLOW_AVG_SHIFT) - (avg >> FLOW_AVG_SHIFT);

        STORE_RELAXED(&flow->mean_len, avg == 0 ? 1 : avg);
}

static int flow_tx_spb(struct flow *        flow,
                       struct ssm_pk_buff * spb,
                       uint16_t             flags,
                       bool                 block,
                       struct timespec *    abstime)
{
        struct timespec now;
        ssize_t         idx;
        size_t          pci_total;
        int             ret;

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        flow->snd_act = now;

        idx = ssm_pk_buff_get_off(spb);

        if (ssm_pk_buff_len(spb) > 0) {
                if (FRCTI_SND(flow->frcti, spb, flags) < 0)
                        goto enomem;

                if (flow->info.qs.ber == 0) {
                        pci_total = flow->frcti != NULL
                                  ? frcti_data_hdr_len(flow->frcti) : 0;
                        if (crc_add(spb, pci_total) != 0)
                                goto enomem;
                }

                if (spb_encrypt(flow, spb) < 0)
                        goto enomem;
        }

        if (flow->poa != NULL)
                return poa_flow_tx(flow->poa, spb, block, abstime);

        flow_mean_len_update(flow, ssm_pk_buff_len(spb));

        if (!block)
                ret = ssm_rbuff_write(flow->tx_rb, idx);
        else
                ret = ssm_rbuff_write_b(flow->tx_rb, idx, abstime);

        if (ret < 0)
                return ret;

        ssm_flow_set_notify(flow->set, flow->info.id, FLOW_PKT);
        return 0;

 enomem:
        return -ENOMEM;
}

/* Per-fragment role for fragment i out of n; n == 1 yields SOLE. */
static __inline__ uint16_t flow_frag_role(size_t i, size_t n)
{
        if (n == 1)
                return FRCT_FR_SOLE;

        if (i == 0)
                return FRCT_FR_FIRST;

        if (i + 1 == n)
                return FRCT_FR_LAST;

        return FRCT_FR_MID;
}

static ssize_t flow_write_stream(struct flow *     flow,
                                 const void *      buf,
                                 size_t            count,
                                 int               oflags,
                                 struct timespec * dl)
{
        const uint8_t * src   = buf;
        size_t          payload;
        size_t          off   = 0;
        bool            block = !(oflags & FLOWFWNOBLOCK);

        if (!FRCTI_IS_FRTX(flow->frcti))
                return -EMSGSIZE;

        payload = FRCTI_PAYLOAD_CAP(flow->frcti);

        while (off < count) {
                struct ssm_pk_buff * spb;
                uint8_t *            ptr;
                ssize_t              idx;
                size_t               clen;
                int                  ret;

                ret = flow_wait_window(flow, 1, block, dl);
                if (ret < 0)
                        return off > 0 ? (ssize_t) off : (ssize_t) ret;

                clen = MIN(count - off, payload);

                if (block)
                        idx = ssm_pool_alloc_b(proc.pool, clen, &ptr,
                                               &spb, dl);
                else
                        idx = ssm_pool_alloc(proc.pool, clen, &ptr, &spb);
                if (idx < 0)
                        return off > 0 ? (ssize_t) off : idx;

                memcpy(ptr, src + off, clen);

                ret = flow_tx_spb(flow, spb, 0, block, dl);
                if (ret < 0) {
                        ssm_pool_remove(proc.pool, idx);
                        return off > 0 ? (ssize_t) off : (ssize_t) ret;
                }

                off += clen;
        }

        return (ssize_t) count;
}

/* Per-fragment flow_tx_spb loop. Raw flows refuse; FRCT splits the SDU. */
static ssize_t flow_write_frag(struct flow *     flow,
                               const void *      buf,
                               size_t            count,
                               int               oflags,
                               struct timespec * dl)
{
        const uint8_t * src   = buf;
        size_t          frag_payload;
        size_t          n;
        size_t          off   = 0;
        size_t          i;
        int             ret;
        bool            block = !(oflags & FLOWFWNOBLOCK);

        /* Raw flows carry no PCI; cannot fragment. */
        if (flow->frcti == NULL)
                return -EMSGSIZE;

        frag_payload = FRCTI_PAYLOAD_CAP(flow->frcti);

        /* Guard the ceil-divide against size_t overflow. */
        if (count > SIZE_MAX - frag_payload + 1)
                return -EMSGSIZE;

        n = (count + frag_payload - 1) / frag_payload;

        /* SDU larger than the FC window can ever offer would deadlock. */
        if (n > RQ_SIZE)
                return -EMSGSIZE;

        /* SDU-atomic FC: wait for n seqnos to avoid overshoot mid-SDU. */
        ret = flow_wait_window(flow, n, block, dl);
        if (ret < 0)
                return (ssize_t) ret;

        STAT_BUMP(flow->frcti, sdu_snd_frag);

        for (i = 0; i < n; ++i) {
                struct ssm_pk_buff * spb;
                uint8_t *            ptr;
                ssize_t              idx;
                size_t               clen;

                clen = (i + 1 == n) ? (count - off) : frag_payload;

                if (block)
                        idx = ssm_pool_alloc_b(proc.pool, clen, &ptr,
                                               &spb, dl);
                else
                        idx = ssm_pool_alloc(proc.pool, clen, &ptr, &spb);
                if (idx < 0) {
                        if (off > 0)
                                STAT_BUMP(flow->frcti, sdu_snd_alloc);
                        return off > 0 ? (ssize_t) off : idx;
                }

                memcpy(ptr, src + off, clen);

                ret = flow_tx_spb(flow, spb, flow_frag_role(i, n), block, dl);
                if (ret < 0) {
                        ssm_pool_remove(proc.pool, idx);
                        if (off > 0)
                                STAT_BUMP(flow->frcti, sdu_snd_tx);
                        return off > 0 ? (ssize_t) off : (ssize_t) ret;
                }

                off += clen;
        }

        return (ssize_t) count;
}

/*
 * Initiator promotes on the install grace (it holds the key-confirm
 * tag); responder waits for peer_synced. The near-exhaustion floor
 * backstops both roles: the receiver selects the epoch by the wire
 * selector, so promoting beats wedging TX on a spent keyring.
 */
static void flow_tx_promote(struct flow * flow)
{
        struct timespec now;
        int             nodes_left;
        bool            promote;

        if (flow->crypt == NULL)
                return;

        if (flow->rk_grace.tv_sec == 0 && flow->rk_grace.tv_nsec == 0)
                return;

        promote = crypt_peer_synced(flow->crypt);

        if (!promote && flow->rk_initiator) {
                clock_gettime(PTHREAD_COND_CLOCK, &now);
                promote = ts_diff_ns(&now, &flow->rk_grace) >= 0;
        }

        if (!promote) {
                nodes_left = crypt_nodes_left(flow->crypt);
                promote = nodes_left >= 0 && nodes_left <= REKEY_PROMOTE_FLOOR;
        }

        if (!promote)
                return;

        crypt_tx_promote(flow->crypt);
        flow->rk_grace.tv_sec  = 0;
        flow->rk_grace.tv_nsec = 0;
}

/* The reply carries no key; the seed arrives later over RB_REKEY. */
static int flow_rekey_trigger(struct flow * flow)
{
        struct flow_info info;
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};

        pthread_rwlock_rdlock(&proc.lock);
        if (flow->info.id < 0 || flow->crypt == NULL) {
                pthread_rwlock_unlock(&proc.lock);
                return -1;
        }
        info = flow->info;
        pthread_rwlock_unlock(&proc.lock);

        if (flow_update__irm_req_ser(&msg, &info, true) < 0)
                return -1;

        if (send_recv_msg(&msg) < 0)
                return -1;

        return 0;
}

static bool flow_wm_due(struct flow * flow)
{
        uint32_t tick;

        if (KEY_REKEY_WATERMARK == 0)
                return false;

        if (flow->crypt == NULL)
                return false;

        if (LOAD_RELAXED(&flow->rk_wm_inflight))
                return false;

        tick = FETCH_ADD_RELAXED(&flow->rk_wm_ctr, 1);
        if ((tick & (FLOW_WM_CHECK - 1)) != 0)
                return false;

        if (ssm_rbuff_get_flags(flow->rx_rb) & RB_REKEY)
                return false;

        return crypt_nodes_left(flow->crypt) <= KEY_REKEY_WATERMARK;
}

ssize_t flow_write(int          fd,
                   const void * buf,
                   size_t       count)
{
        struct flow *        flow;
        ssize_t              idx;
        int                  ret;
        int                  flags;
        struct timespec      abs;
        struct timespec      now;
        struct timespec *    dl = NULL;
        struct ssm_pk_buff * spb;
        uint8_t *            ptr;

        if (buf == NULL && count != 0)
                return -EINVAL;

        if (fd < 0 || fd >= PROC_MAX_FLOWS)
                return -EBADF;

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTALLOC;
        }

        flags = flow->oflags;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        if (flow->snd_timesout) {
                ts_add(&now, &flow->snd_timeo, &abs);
                dl = &abs;
        }

        pthread_rwlock_unlock(&proc.lock);

        if ((flags & FLOWFACCMODE) == FLOWFRDONLY)
                return -EPERM;

        if (flow->crypt != NULL
            && (ssm_rbuff_get_flags(flow->rx_rb) & RB_REKEY))
                flow_rekey(flow);

        flow_tx_promote(flow);

        /* Pre-empt TX key exhaustion; the timer is the backstop. */
        if (flow_wm_due(flow)) {
                STORE_RELAXED(&flow->rk_wm_inflight, true);
                if (flow_rekey_trigger(flow) < 0)
                        STORE_RELAXED(&flow->rk_wm_inflight, false);
        }

        tw_move_safe();

        if (flow->frcti != NULL) {
                /* Pump rx_rb so a pure-writer processes ACKs. */
                ret = flow_wait_window(flow, 1, !(flags & FLOWFWNOBLOCK), dl);
                if (ret < 0)
                        return ret;

                if (count > 0 && FRCTI_IS_STREAM(flow->frcti))
                        return flow_write_stream(flow, buf, count, flags, dl);

                if (FRCTI_NEEDS_FRAG(flow->frcti, count))
                        return flow_write_frag(flow, buf, count, flags, dl);
        } else if (flow->info.mtu > 0
                   && count > flow_user_mtu(flow, flow->info.mtu)) {
                /* Raw flows carry no PCI; refuse anything > one n-1 frame. */
                return -EMSGSIZE;
        }

        if (flags & FLOWFWNOBLOCK)
                idx = ssm_pool_alloc(proc.pool, count, &ptr, &spb);
        else
                idx = ssm_pool_alloc_b(proc.pool, count, &ptr, &spb, dl);
        if (idx < 0)
                return idx;

        if (count > 0)
                memcpy(ptr, buf, count);

        ret = flow_tx_spb(flow, spb, FRCT_FR_SOLE,
                          !(flags & FLOWFWNOBLOCK), dl);
        if (ret < 0) {
                ssm_pool_remove(proc.pool, idx);
                return (ssize_t) ret;
        }

        return (ssize_t) count;
}

static ssize_t flow_rx_spb(struct flow *         flow,
                           struct ssm_pk_buff ** spb,
                           bool                  block,
                           struct timespec *     abstime)
{
        ssize_t         idx;
        struct timespec now;

        idx = block ? ssm_rbuff_read_b(flow->rx_rb, abstime)
                    : ssm_rbuff_read(flow->rx_rb);
        if (idx < 0)
                return idx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        flow->rcv_act = now;

        *spb = ssm_pool_get(proc.pool, idx);

        if (invalid_pkt(flow, *spb)) {
                ssm_pool_remove(proc.pool, idx);
                return -EAGAIN;
        }

        return idx;
}

static ssize_t raw_flow_read_pkt(struct flow *     flow,
                                 bool              block,
                                 struct timespec * dl)
{
        struct ssm_pk_buff * spb;
        struct timespec      wait_abs;
        ssize_t              idx;

        while (true) {
                if (flow->crypt != NULL
                    && (ssm_rbuff_get_flags(flow->rx_rb) & RB_REKEY))
                        flow_rekey(flow);

                if (!block) {
                        idx = ssm_rbuff_read(flow->rx_rb);
                        if (idx < 0)
                                return -EAGAIN;
                } else {
                        compute_wait_deadline(dl, &wait_abs);
                        idx = ssm_rbuff_read_b(flow->rx_rb, &wait_abs);
                        if (idx == -ETIMEDOUT) {
                                if (deadline_passed(dl))
                                        return -ETIMEDOUT;
                                continue;
                        }
                        if (idx < 0)
                                return idx;
                }

                spb = ssm_pool_get(proc.pool, idx);
                if (!invalid_pkt(flow, spb))
                        return idx;

                ssm_pool_remove(proc.pool, idx);
                if (!block)
                        return -EAGAIN;
        }
}

static ssize_t deliver_pkt(struct flow *        flow,
                           struct ssm_pk_buff * spb,
                           ssize_t              idx,
                           void *               buf,
                           size_t               count,
                           bool                 partrd)
{
        uint8_t * packet = ssm_pk_buff_head(spb);
        ssize_t   n      = ssm_pk_buff_len(spb);

        assert(n >= 0);

        if (n <= (ssize_t) count) {
                memcpy(buf, packet, n);
                ipcp_spb_release(spb);
                if (partrd && n == (ssize_t) count)
                        flow->part_idx = DONE_PART;
                else
                        flow->part_idx = NO_PART;

                return n;
        }

        if (partrd) {
                memcpy(buf, packet, count);
                ssm_pk_buff_pop(spb, count);
                flow->part_idx = idx;
                return count;
        }

        ipcp_spb_release(spb);
        return -EMSGSIZE;
}

/* Drive frcti_consume until it delivers or errors. */
static ssize_t flow_read_frcti(struct flow *     flow,
                               void *            buf,
                               size_t            count,
                               bool              block,
                               bool              partrd,
                               struct timespec * dl)
{
        struct timespec   now;
        ssize_t           bytes;
        int               rc;

        while (true) {
                flow_drain_rx_nb(flow);

                bytes = FRCTI_CONSUME(flow->frcti, buf, count, partrd);
                if (bytes >= 0)
                        break;
                if (bytes != -EAGAIN)
                        return bytes;
                if (!block)
                        return -EAGAIN;
                rc = flow_rx_one(flow, dl);
                if (rc < 0)
                        return rc;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        flow->rcv_act = now;

        return bytes;
}

ssize_t flow_read(int    fd,
                  void * buf,
                  size_t count)
{
        struct flow *        flow;
        struct ssm_pk_buff * spb;
        struct timespec      abs;
        struct timespec      now;
        struct timespec *    dl = NULL;
        ssize_t              idx;
        bool                 block;
        bool                 partrd;

        if (fd < 0 || fd >= PROC_MAX_FLOWS)
                return -EBADF;

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTALLOC;
        }

        if (flow->part_idx == DONE_PART) {
                flow->part_idx = NO_PART;
                pthread_rwlock_unlock(&proc.lock);
                return 0;
        }

        block  = !(flow->oflags & FLOWFRNOBLOCK);
        partrd = !(flow->oflags & FLOWFRNOPART);

        if (flow->rcv_timesout) {
                clock_gettime(PTHREAD_COND_CLOCK, &now);
                ts_add(&now, &flow->rcv_timeo, &abs);
                dl = &abs;
        }

        pthread_rwlock_unlock(&proc.lock);

        if (flow->crypt != NULL
            && (ssm_rbuff_get_flags(flow->rx_rb) & RB_REKEY))
                flow_rekey(flow);

        /* Advance TX off a stale epoch even on recv-mostly (ACK-only) flows. */
        flow_tx_promote(flow);

        tw_move_safe();

        idx = flow->part_idx;
        if (idx < 0 && flow->frcti != NULL)
                return flow_read_frcti(flow, buf, count, block, partrd, dl);

        if (idx < 0) {
                idx = raw_flow_read_pkt(flow, block, dl);
                if (idx < 0)
                        return idx;
        }

        spb = ssm_pool_get(proc.pool, idx);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        flow->rcv_act = now;

        return deliver_pkt(flow, spb, idx, buf, count, partrd);
}

struct flow_set * fset_create(void)
{
        struct flow_set * set;

        set = malloc(sizeof(*set));
        if (set == NULL)
                goto fail_malloc;

        assert(proc.fqueues);

        pthread_rwlock_wrlock(&proc.lock);

        set->idx = bmp_allocate(proc.fqueues);
        if (!bmp_is_id_valid(proc.fqueues, set->idx))
                goto fail_bmp_alloc;

        pthread_rwlock_unlock(&proc.lock);

        return set;

 fail_bmp_alloc:
        pthread_rwlock_unlock(&proc.lock);
        free(set);
 fail_malloc:
        return NULL;
}

void fset_destroy(struct flow_set * set)
{
        if (set == NULL)
                return;

        fset_zero(set);

        pthread_rwlock_wrlock(&proc.lock);

        bmp_release(proc.fqueues, set->idx);

        pthread_rwlock_unlock(&proc.lock);

        free(set);
}

struct fqueue * fqueue_create(void)
{
        struct fqueue * fq = malloc(sizeof(*fq));
        if (fq == NULL)
                return NULL;

        memset(fq->fqueue, -1, SSM_RBUFF_SIZE * sizeof(*fq->fqueue));
        fq->fqsize = 0;
        fq->next   = 0;

        return fq;
}

void fqueue_destroy(struct fqueue * fq)
{
        free(fq);
}

void fset_zero(struct flow_set * set)
{
        if (set == NULL)
                return;

        ssm_flow_set_zero(proc.fqset, set->idx);
}

int fset_add(struct flow_set * set,
             int               fd)
{
        struct flow *           flow;
        int                     ret;

        if (set == NULL || fd < 0 || fd >= PROC_MAX_FLOWS)
                return -EINVAL;

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                ret = -EINVAL;
                goto fail;
        }

        if (flow->frcti != NULL)
                ssm_flow_set_del(proc.fqset, 0, flow->info.id);

        ret = ssm_flow_set_add(proc.fqset, set->idx, flow->info.id);
        if (ret < 0)
                goto fail;

        if (ssm_rbuff_queued(flow->rx_rb))
                ssm_flow_set_notify(proc.fqset, flow->info.id, FLOW_PKT);

        pthread_rwlock_unlock(&proc.lock);

        return ret;

 fail:
        pthread_rwlock_unlock(&proc.lock);
        return ret;
}

void fset_del(struct flow_set * set,
              int               fd)
{
        struct flow * flow;

        if (set == NULL || fd < 0 || fd >= PROC_MAX_FLOWS)
                return;

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id >= 0)
                ssm_flow_set_del(proc.fqset, set->idx, flow->info.id);

        if (flow->frcti != NULL)
                ssm_flow_set_add(proc.fqset, 0, flow->info.id);

        pthread_rwlock_unlock(&proc.lock);
}

bool fset_has(const struct flow_set * set,
              int                     fd)
{
        struct flow * flow;
        bool          ret;

        if (set == NULL || fd < 0 || fd >= PROC_MAX_FLOWS)
                return false;

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return false;
        }

        ret = (ssm_flow_set_has(proc.fqset, set->idx, flow->info.id) == 1);

        pthread_rwlock_unlock(&proc.lock);

        return ret;
}

static int fqueue_filter(struct fqueue * fq)
{
        struct ssm_pk_buff * spb;
        int                  fd;
        ssize_t              idx;
        struct frcti *       frcti;
        int                  ret = 0;

        /* proc.lock rdlock gates frcti_destroy via flow_fini wrlock. */
        pthread_rwlock_rdlock(&proc.lock);

        while (fq->next < fq->fqsize) {
                if (fq->fqueue[fq->next].event == FLOW_UPD) {
                        /* Re-key doorbell: pull internally, never surface. */
                        fd = proc.id_to_fd[fq->fqueue[fq->next].flow_id].fd;
                        ++fq->next;
                        if (fd >= 0) {
                                pthread_rwlock_unlock(&proc.lock);
                                flow_rekey(&proc.flows[fd]);
                                pthread_rwlock_rdlock(&proc.lock);
                        }
                        continue;
                }

                if (fq->fqueue[fq->next].event != FLOW_PKT) {
                        ret = 1;
                        goto out;
                }

                fd = proc.id_to_fd[fq->fqueue[fq->next].flow_id].fd;
                if (fd < 0) {
                        ++fq->next;
                        continue;
                }

                frcti = proc.flows[fd].frcti;
                if (frcti == NULL) {
                        ret = 1;
                        goto out;
                }

                if (FRCTI_PDU_READY(frcti)) {
                        ret = 1;
                        goto out;
                }

                idx = flow_rx_spb(&proc.flows[fd], &spb, false, NULL);
                if (idx < 0)
                        goto out;

                spb = ssm_pool_get(proc.pool, idx);

                FRCTI_RCV(frcti, spb);

                if (FRCTI_PDU_READY(frcti)) {
                        ret = 1;
                        goto out;
                }

                ++fq->next;
        }

 out:
        pthread_rwlock_unlock(&proc.lock);
        return ret;
}

int fqueue_next(struct fqueue * fq)
{
        int                fd;
        struct flowevent * e;

        if (fq == NULL)
                return -EINVAL;

        if (fq->fqsize == 0 || fq->next == fq->fqsize)
                return -EPERM;

        if (fq->next != 0 && fqueue_filter(fq) == 0)
                return -EPERM;

        pthread_rwlock_rdlock(&proc.lock);

        e = fq->fqueue + fq->next;

        fd = proc.id_to_fd[e->flow_id].fd;

        ++fq->next;

        pthread_rwlock_unlock(&proc.lock);

        return fd;
}

enum fqtype fqueue_type(struct fqueue * fq)
{
        if (fq == NULL)
                return -EINVAL;

        if (fq->fqsize == 0 || fq->next == 0)
                return -EPERM;

        return fq->fqueue[(fq->next - 1)].event;
}

ssize_t fevent(struct flow_set *       set,
               struct fqueue *         fq,
               const struct timespec * timeo)
{
        ssize_t           ret = 0;
        struct timespec   abs;
        struct timespec * dl = NULL;
        struct timespec   wait_abs;

        if (set == NULL || fq == NULL)
                return -EINVAL;

        if (fq->fqsize > 0 && fq->next != fq->fqsize)
                return 1;

        if (timeo != NULL) {
                struct timespec now;
                clock_gettime(PTHREAD_COND_CLOCK, &now);
                ts_add(&now, timeo, &abs);
                dl = &abs;
        }

        while (ret == 0) {
                tw_move_safe();

                compute_wait_deadline(dl, &wait_abs);

                ret = ssm_flow_set_wait(proc.fqset, set->idx,
                                        fq->fqueue, &wait_abs);
                if (ret == -ETIMEDOUT) {
                        if (deadline_passed(dl))
                                return -ETIMEDOUT;
                        ret = 0;
                        continue;
                }

                fq->fqsize = ret;
                fq->next   = 0;

                ret = fqueue_filter(fq);
        }

        assert(ret != 0);

        return 1;
}

int np1_flow_alloc(pid_t n_pid,
                   int   flow_id)
{
        struct flow_info  flow;
        struct crypt_sk crypt = { .nid = NID_undef, .key = NULL,
                                  .epoch = 0, .role = CRYPT_ROLE_INIT };

        memset(&flow, 0, sizeof(flow));

        flow.id      = flow_id;
        flow.n_pid   = getpid();
        flow.qs      = qos_np1;
        flow.mpl     = 0;
        /* np1 flow: n_1_pid is the upper. */
        flow.n_1_pid = n_pid;

        return flow_init(&flow, &crypt, 0, NULL);
}

int np1_flow_dealloc(int    flow_id,
                     time_t timeo)
{
        int fd;

        /* TODO: wait in IRMd, not here; needs async ops. */
        sleep(timeo);

        pthread_rwlock_rdlock(&proc.lock);

        fd = proc.id_to_fd[flow_id].fd;

        pthread_rwlock_unlock(&proc.lock);

        return fd;
}

int np1_flow_resp(int flow_id,
                  int resp)
{
        int fd;

        if (resp == 0 && flow_wait_assign(flow_id) != FLOW_ALLOCATED)
                return -1;

        pthread_rwlock_rdlock(&proc.lock);

        fd = proc.id_to_fd[flow_id].fd;

        pthread_rwlock_unlock(&proc.lock);

        return fd;
}

int np1_flow_fd(int flow_id)
{
        int fd;

        if (flow_id < 0 || flow_id >= SYS_MAX_FLOWS)
                return -1;

        pthread_rwlock_rdlock(&proc.lock);

        fd = proc.id_to_fd[flow_id].fd;

        pthread_rwlock_unlock(&proc.lock);

        return fd;
}

int np1_flow_id(int fd)
{
        int flow_id;

        if (fd < 0 || fd >= PROC_MAX_FLOWS)
                return -1;

        pthread_rwlock_rdlock(&proc.lock);

        flow_id = proc.flows[fd].info.id;

        pthread_rwlock_unlock(&proc.lock);

        return flow_id;
}

int ipcp_create_r(const struct ipcp_info * info)
{
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        int              err;

        if (ipcp_create_r__irm_req_ser(&msg,info) < 0)
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        return irm__irm_result_des(&msg);
}

/* Layer-wide bound for flow_info; set once before flows are served. */
void ipcp_flow_set_max_rtt(uint32_t max_rtt)
{
        proc.max_rtt = max_rtt;
}

int ipcp_flow_req_arr(const buffer_t * dst,
                      qosspec_t        qs,
                      time_t           mpl,
                      uint32_t         mtu,
                      const buffer_t * data)
{
        struct flow_info flow;
        uint8_t           buf[SOCK_BUF_SIZE];
        buffer_t          msg = {SOCK_BUF_SIZE, buf};
        struct crypt_sk crypt;
        uint8_t           key[SYMMKEYSZ];
        int               err;

        memset(&flow, 0, sizeof(flow));

        assert(dst != NULL && dst->len != 0 && dst->data != NULL);

        flow.n_1_pid = getpid();
        flow.qs      = qs;
        flow.mpl     = mpl;
        flow.mtu     = mtu;
        flow.max_rtt = proc.max_rtt;

        if (ipcp_flow_req_arr__irm_req_ser(&msg, dst, &flow, data) < 0)
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        crypt.key        = key;
        crypt.epoch      = 0;
        crypt.role       = CRYPT_ROLE_INIT;

        err = flow__irm_result_des(&msg, &flow, &crypt);
        if (err < 0)
                return err;

        /* np1 flows are not encrypted. */
        assert(crypt.nid == NID_undef);

        /* Inverted for np1_flow. */
        flow.n_1_pid = flow.n_pid;
        flow.n_pid   = getpid();
        flow.mpl     = 0;
        flow.mtu     = 0;
        flow.qs      = qos_np1;

        crypt.nid = NID_undef;

        return flow_init(&flow, &crypt, 0, NULL);
}

int ipcp_flow_update_arr(int              flow_id,
                         const buffer_t * data)
{
        struct flow_info flow;
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        int              err;

        memset(&flow, 0, sizeof(flow));

        flow.id      = flow_id;
        flow.n_1_pid = getpid();

        if (ipcp_flow_update_arr__irm_req_ser(&msg, &flow, data) < 0)
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        return irm__irm_result_des(&msg);
}

int ipcp_flow_alloc_reply(int              fd,
                          int              response,
                          time_t           mpl,
                          uint32_t         mtu,
                          const buffer_t * data)
{
        struct flow_info flow;
        uint8_t          buf[SOCK_BUF_SIZE];
        buffer_t         msg = {SOCK_BUF_SIZE, buf};
        int              err;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);

        pthread_rwlock_rdlock(&proc.lock);

        flow.id = proc.flows[fd].info.id;

        pthread_rwlock_unlock(&proc.lock);

        flow.mpl         = mpl;
        flow.mtu         = mtu;
        flow.max_rtt     = proc.max_rtt;

        if (ipcp_flow_alloc_reply__irm_msg_ser(&msg, &flow, response, data) < 0)
                return -ENOMEM;

        err = send_recv_msg(&msg);
        if (err < 0)
                return err;

        return irm__irm_result_des(&msg);
}

int ipcp_flow_read(int                   fd,
                   struct ssm_pk_buff ** spb)
{
        struct flow *        flow;
        struct ssm_pk_buff * out;
        uint8_t *            ptr;
        ssize_t              idx = -1;
        ssize_t              fret;
        size_t               len;
        size_t               nfrags;
        int                  ret;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(spb);

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTALLOC;
        }

        if (FRCTI_IS_STREAM(flow->frcti)) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTSUP;
        }

        pthread_rwlock_unlock(&proc.lock);

        if (flow->crypt != NULL
            && (ssm_rbuff_get_flags(flow->rx_rb) & RB_REKEY))
                flow_rekey(flow);

        /* Advance TX off a stale epoch even on recv-mostly flows. */
        flow_tx_promote(flow);

        tw_move_safe();

        pthread_rwlock_rdlock(&proc.lock);

        /* Raw flow: deliver the popped pkt directly (no FRCT rq). */
        if (flow->frcti == NULL) {
                idx = flow_rx_spb(flow, spb, false, NULL);
                pthread_rwlock_unlock(&proc.lock);
                return idx < 0 ? (int) idx : 0;
        }

        while (!FRCTI_PDU_READY(flow->frcti)) {
                idx = flow_rx_spb(flow, spb, false, NULL);
                if (idx < 0) {
                        pthread_rwlock_unlock(&proc.lock);
                        return idx;
                }

                FRCTI_RCV(flow->frcti, *spb);
        }

        pthread_rwlock_unlock(&proc.lock);

        /*
         * A hand-back of the fed spb would leave it double-owned by
         * the reorder queue; frcti_consume is the only safe way to
         * take it. A write can also complete a PDU, so PDU_READY may
         * be true with no loop-local spb to fall back on anyway.
         */

        ret = FRCTI_PDU_INFO(flow->frcti, &len, &nfrags);
        if (ret < 0)
                return ret;

        /*
         * Oversize (over frcti's own cap, or too big for any pool
         * class): force frcti_consume's total > count drop branch
         * now, so the run leaves the delivery edge instead of
         * stalling every read after this one.
         */
        if (len > frcti_get_max_rcv_sdu(flow->frcti)) {
                (void) FRCTI_CONSUME(flow->frcti, NULL, 0, false);
                return -EMSGSIZE;
        }

        idx = ssm_pool_alloc_b(proc.pool, len, &ptr, &out, NULL);
        if (idx < 0) {
                if (idx == -EMSGSIZE)
                        (void) FRCTI_CONSUME(flow->frcti, NULL, 0, false);
                return (int) idx;
        }

        fret = FRCTI_CONSUME(flow->frcti, ptr, len, false);
        if (fret < 0 || (size_t) fret != len) {
                ssm_pool_remove(proc.pool, idx);
                return fret < 0 ? (int) fret : -EIO;
        }

        *spb = out;

        return 0;
}

/*
 * Writes an spb to an IPCP-internal flow, splitting it over multiple
 * FRCT fragments when it exceeds the flow's fragment payload cap.
 * Consumes spb on success; on failure spb is left to the caller.
 */
int ipcp_flow_write(int                  fd,
                    struct ssm_pk_buff * spb)
{
        struct flow * flow;
        int           oflags;
        size_t        len;
        ssize_t       fret;
        int           ret;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(spb);

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTALLOC;
        }

        if ((flow->oflags & FLOWFACCMODE) == FLOWFRDONLY) {
                pthread_rwlock_unlock(&proc.lock);
                return -EPERM;
        }

        if (FRCTI_IS_STREAM(flow->frcti)) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTSUP;
        }

        oflags = flow->oflags;

        pthread_rwlock_unlock(&proc.lock);

        if (flow->crypt != NULL
            && (ssm_rbuff_get_flags(flow->rx_rb) & RB_REKEY))
                flow_rekey(flow);

        flow_tx_promote(flow);

        /* Pre-empt TX key exhaustion; the timer is the backstop. */
        if (flow_wm_due(flow)) {
                STORE_RELAXED(&flow->rk_wm_inflight, true);

                if (flow_rekey_trigger(flow) < 0)
                        STORE_RELAXED(&flow->rk_wm_inflight, false);
        }

        tw_move_safe();

        len = ssm_pk_buff_len(spb);
        if (FRCTI_NEEDS_FRAG(flow->frcti, len)) {
                fret = flow_write_frag(flow, ssm_pk_buff_head(spb), len,
                                       oflags, NULL);

                if (fret < 0)
                        return (int) fret;

                /* Partial: flow_write_frag swallowed the real cause. */
                if (fret != (ssize_t) len) {
                        /* PoA flows have no tx_rb flag to consult. */
                        if (flow->tx_rb != NULL
                            && (ssm_rbuff_get_flags(flow->tx_rb)
                                & RB_FLOWDOWN))
                                return -EFLOWDOWN;
                        return -EIO;
                }

                ipcp_spb_release(spb);

                return 0;
        }

        ret = flow_tx_spb(flow, spb, FRCT_FR_SOLE, true, NULL);

        return ret;
}

/* Copy src into dst_pool without consuming src. Caller owns both halves. */
static int pool_dup_spb(struct ssm_pool *     src_pool,
                        size_t                src_off,
                        struct ssm_pool *     dst_pool,
                        struct ssm_pk_buff ** dst_spb)
{
        struct ssm_pk_buff * src;
        uint8_t *            ptr;
        size_t               len;

        src = ssm_pool_get(src_pool, src_off);
        len = ssm_pk_buff_len(src);

        if (ssm_pool_alloc(dst_pool, len, &ptr, dst_spb) < 0)
                return -ENOMEM;

        memcpy(ptr, ssm_pk_buff_head(src), len);

        return 0;
}

int np1_flow_read(int                   fd,
                  struct ssm_pk_buff ** spb,
                  struct ssm_pool *     pool)
{
        struct flow * flow;
        ssize_t       off;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(spb);

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTALLOC;
        }

        off = ssm_rbuff_read(flow->rx_rb);
        if (off < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return off;
        }

        pthread_rwlock_unlock(&proc.lock);

        if (pool == NULL) {
                *spb = ssm_pool_get(proc.pool, off);
        } else {
                /* Cross-pool copy: PUP -> GSPP */
                if (pool_dup_spb(pool, off, proc.pool, spb) < 0) {
                        ssm_pool_remove(pool, off);
                        return -ENOMEM;
                }
                ssm_pool_remove(pool, off);
        }

        return 0;
}

/*
 * An N-1 flow gets no flow_write to advance its TX epoch off a rotated
 * key. Promoting is local; a re-key request here would block on the
 * IRMd.
 */
int np1_flow_write(int                  fd,
                   struct ssm_pk_buff * spb,
                   struct ssm_pool *    pool)
{
        struct flow *        flow;
        struct ssm_pk_buff * dst;
        int                  ret;
        size_t               off;
        size_t               dst_off;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(spb);

        flow = &proc.flows[fd];

        pthread_rwlock_rdlock(&proc.lock);

        if (flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -ENOTALLOC;
        }

        if ((flow->oflags & FLOWFACCMODE) == FLOWFRDONLY) {
                pthread_rwlock_unlock(&proc.lock);
                return -EPERM;
        }

        pthread_rwlock_unlock(&proc.lock);

        off = ssm_pk_buff_get_off(spb);

        if (pool == NULL) {
                ret = ssm_rbuff_write_b(flow->tx_rb, off, NULL);
                if (ret < 0)
                        return ret;
                ssm_flow_set_notify(flow->set, flow->info.id, FLOW_PKT);
        } else {
                /* Cross-pool copy: GSPP -> PUP. Src kept on error. */
                if (pool_dup_spb(proc.pool, off, pool, &dst) < 0)
                        return -ENOMEM;
                dst_off = ssm_pk_buff_get_off(dst);
                ret = ssm_rbuff_write_b(flow->tx_rb, dst_off, NULL);
                if (ret < 0) {
                        ssm_pool_remove(pool, dst_off);
                        return ret;
                }
                ssm_flow_set_notify(flow->set, flow->info.id, FLOW_PKT);
                ssm_pool_remove(proc.pool, off);
        }

        return 0;
}

int ipcp_spb_reserve(struct ssm_pk_buff ** spb,
                     size_t                len)
{
        return ssm_pool_alloc_b(proc.pool, len, NULL, spb, NULL) < 0
                ? -1 : 0;
}

void ipcp_spb_release(struct ssm_pk_buff * spb)
{
        ssm_pool_remove(proc.pool, ssm_pk_buff_get_off(spb));
}

int ipcp_flow_fini(int fd)
{
        struct ssm_rbuff * rx_rb;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);

        pthread_rwlock_rdlock(&proc.lock);

        if (proc.flows[fd].info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return -1;
        }

        ssm_rbuff_set_flags(proc.flows[fd].rx_rb, RB_FLOWDOWN);

        if (proc.flows[fd].tx_rb != NULL)
                ssm_rbuff_set_flags(proc.flows[fd].tx_rb, RB_FLOWDOWN);

        if (proc.flows[fd].set != NULL)
                ssm_flow_set_notify(proc.flows[fd].set, proc.flows[fd].info.id,
                                    FLOW_DEALLOC);

        rx_rb = proc.flows[fd].rx_rb;

        pthread_rwlock_unlock(&proc.lock);

        if (rx_rb != NULL)
                ssm_rbuff_fini(rx_rb);

        return 0;
}

int ipcp_flow_get_qoscube(int         fd,
                          qoscube_t * cube)
{
        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(cube);

        pthread_rwlock_rdlock(&proc.lock);

        assert(proc.flows[fd].info.id >= 0);

        *cube = qos_spec_to_cube(proc.flows[fd].info.qs);

        pthread_rwlock_unlock(&proc.lock);

        return 0;
}

/* Not a snapshot: two atomic loads; caller keeps the fd live. */
size_t ipcp_flow_queued(int fd)
{
        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(proc.flows[fd].info.id >= 0);

        if (proc.flows[fd].poa != NULL)
                return poa_flow_qlen(proc.flows[fd].poa);

        return ssm_rbuff_queued(proc.flows[fd].tx_rb)
                * LOAD_RELAXED(&proc.flows[fd].mean_len);
}

size_t ipcp_flow_mean_len(int fd)
{
        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(proc.flows[fd].info.id >= 0);

        if (proc.flows[fd].poa != NULL)
                return poa_flow_mean_len(proc.flows[fd].poa);

        return LOAD_RELAXED(&proc.flows[fd].mean_len);
}

/* An update racing the arm seeds one bogus window; the filter absorbs. */
int ipcp_flow_cap_arm(int fd)
{
        struct flow *    flow;
        struct cap_est * e;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(proc.flows[fd].info.id >= 0);

        flow = &proc.flows[fd];
        if (flow->poa != NULL) {
                cap_clear(poa_flow_cap_est(flow->poa));
                return 0;
        }

        e = flow->cap;
        if (e != NULL) {
                cap_clear(e);
                return 0;
        }

        if (posix_memalign((void **) &e, CAP_ALIGN, sizeof(*e)) != 0)
                return -ENOMEM;

        cap_clear(e);

        STORE_RELEASE(&flow->cap, e);

        return 0;
}

void ipcp_flow_cap_update(int    fd,
                          size_t qlen,
                          size_t len)
{
        struct flow *    flow;
        struct cap_est * e;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(proc.flows[fd].info.id >= 0);

        flow = &proc.flows[fd];
        if (flow->poa != NULL) {
                cap_update(poa_flow_cap_est(flow->poa), qlen, len);
                return;
        }

        e = LOAD_ACQUIRE(&flow->cap);
        if (e == NULL)
                return;

        cap_update(e, qlen, len);
}

uint64_t ipcp_flow_cap(int fd)
{
        struct flow *    flow;
        struct cap_est * e;

        assert(fd >= 0 && fd < PROC_MAX_FLOWS);
        assert(proc.flows[fd].info.id >= 0);

        flow = &proc.flows[fd];
        if (flow->poa != NULL)
                return cap_rate(poa_flow_cap_est(flow->poa));

        e = LOAD_ACQUIRE(&flow->cap);
        if (e == NULL)
                return 0;

        return cap_rate(e);
}

int local_flow_transfer(int               src_fd,
                        int               dst_fd,
                        struct ssm_pool * src_pool,
                        struct ssm_pool * dst_pool)
{
        struct flow *        src_flow;
        struct flow *        dst_flow;
        struct ssm_pk_buff * dst_spb;
        struct ssm_pool *    sp;
        struct ssm_pool *    dp;
        ssize_t              off;
        int                  ret;

        assert(src_fd >= 0);
        assert(dst_fd >= 0);

        src_flow = &proc.flows[src_fd];
        dst_flow = &proc.flows[dst_fd];

        sp = src_pool == NULL ? proc.pool : src_pool;
        dp = dst_pool == NULL ? proc.pool : dst_pool;

        pthread_rwlock_rdlock(&proc.lock);

        off = ssm_rbuff_read(src_flow->rx_rb);
        if (off < 0) {
                pthread_rwlock_unlock(&proc.lock);
                return off;
        }

        if (dst_flow->info.id < 0) {
                pthread_rwlock_unlock(&proc.lock);
                ssm_pool_remove(sp, off);
                return -ENOTALLOC;
        }

        pthread_rwlock_unlock(&proc.lock);

        if (sp == dp) {
                /* Same pool: zero-copy */
                ret = ssm_rbuff_write_b(dst_flow->tx_rb, off, NULL);
                if (ret < 0)
                        ssm_pool_remove(sp, off);
                else
                        ssm_flow_set_notify(dst_flow->set,
                                            dst_flow->info.id, FLOW_PKT);
        } else {
                /* Different pools: single copy */
                if (pool_dup_spb(sp, off, dp, &dst_spb) < 0) {
                        ssm_pool_remove(sp, off);
                        return -ENOMEM;
                }

                ssm_pool_remove(sp, off);
                off = ssm_pk_buff_get_off(dst_spb);
                ret = ssm_rbuff_write_b(dst_flow->tx_rb, off, NULL);
                if (ret < 0)
                        ssm_pool_remove(dp, off);
                else
                        ssm_flow_set_notify(dst_flow->set,
                                            dst_flow->info.id, FLOW_PKT);
        }

        return ret;
}

#include "cap.c"
#include "poa/poa.c"
