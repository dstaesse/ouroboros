/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Timerwheel
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#include <ouroboros/list.h>

#define RXMQ_SLOTS (1 << 8)           /* #slots / level.           */
#define RXMQ_LVLS  3                  /* #levels, bump for DTN.    */
#define RXMQ_BUMP  4                  /* factor to bump lvl.       */
#define RXMQ_RES   20                 /* res (ns) of lowest lvl.   */

#define ACKQ_SLOTS (1 << 7)           /* #slots for delayed ACK.   */
#define ACKQ_RES   20                 /* resolution for dACK.      */

/* Overflow limits range to about 6 hours. */
#define ts_to_ns(ts) (ts.tv_sec * BILLION + ts.tv_nsec)
#define ts_to_rxm_slot(ts) (ts_to_ns(ts) >> RXMQ_RES)
#define ts_to_ack_slot(ts) (ts_to_ns(ts) >> ACKQ_RES)

struct rxm {
        struct list_head     next;
        uint32_t             seqno;
        struct shm_du_buff * sdb;
        uint8_t *            head;
        uint8_t *            tail;
        time_t               t0;      /* Time when original was sent (us). */
        size_t               mul;     /* RTO multiplier.                   */
        struct frcti *       frcti;
        int                  fd;
        int                  flow_id; /* Prevent rtx when fd reused.       */
};

struct ack {
        struct list_head next;
        struct frcti *   frcti;
        int              fd;
        int              flow_id;
};

struct {
        /*
         * At a 1 ms min resolution, every level bumps the
         * resolution by a factor of 16.
         */
        struct list_head rxms[RXMQ_LVLS][RXMQ_SLOTS];

        struct list_head acks[ACKQ_SLOTS];
        bool             map[ACKQ_SLOTS][PROG_MAX_FLOWS];

        size_t           prv_rxm; /* Last processed rxm slot at lvl 0. */
        size_t           prv_ack; /* Last processed ack slot.          */
        pthread_mutex_t  lock;
} rw;

static void timerwheel_fini(void)
{
        size_t             i;
        size_t             j;
        struct list_head * p;
        struct list_head * h;

        pthread_mutex_lock(&rw.lock);

        for (i = 0; i < RXMQ_LVLS; ++i) {
                for (j = 0; j < RXMQ_SLOTS; j++) {
                        list_for_each_safe(p, h, &rw.rxms[i][j]) {
                                struct rxm * rxm;
                                rxm = list_entry(p, struct rxm, next);
                                list_del(&rxm->next);
                                shm_du_buff_ack(rxm->sdb);
                                ipcp_sdb_release(rxm->sdb);
                                free(rxm);
                        }
                }
        }

        for (i = 0; i < ACKQ_SLOTS; ++i) {
                list_for_each_safe(p, h, &rw.acks[i]) {
                        struct ack * a = list_entry(p, struct ack, next);
                        list_del(&a->next);
                        free(a);
                }
        }

        pthread_mutex_unlock(&rw.lock);

        pthread_mutex_destroy(&rw.lock);
}

static int timerwheel_init(void)
{
        struct timespec   now;
        size_t            i;
        size_t            j;

        if (pthread_mutex_init(&rw.lock, NULL))
                return -1;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        rw.prv_rxm = (ts_to_rxm_slot(now) - 1) & (RXMQ_SLOTS - 1);
        for (i = 0; i < RXMQ_LVLS; ++i) {
                for (j = 0; j < RXMQ_SLOTS; ++j)
                        list_head_init(&rw.rxms[i][j]);
        }

        rw.prv_ack = (ts_to_ack_slot(now) - 1) & (ACKQ_SLOTS - 1);
        for (i = 0; i < ACKQ_SLOTS; ++i)
                list_head_init(&rw.acks[i]);

        return 0;
}

static void timerwheel_move(void)
{
        struct timespec    now;
        struct list_head * p;
        struct list_head * h;
        size_t             rxm_slot;
        size_t             ack_slot;
        size_t             i;
        size_t             j;

        pthread_mutex_lock(&rw.lock);

        pthread_cleanup_push((void (*) (void *)) pthread_mutex_unlock,
                             (void *) &rw.lock);

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        rxm_slot = ts_to_ns(now) >> RXMQ_RES;
        j = rw.prv_rxm;
        rw.prv_rxm = rxm_slot & (RXMQ_SLOTS - 1);

        for (i = 0; i < RXMQ_LVLS; ++i) {
                size_t j_max_slot = rxm_slot & (RXMQ_SLOTS - 1);
                if (j_max_slot < j)
                        j_max_slot += RXMQ_SLOTS;

                while (j++ < j_max_slot) {
                        list_for_each_safe(p,
                                           h,
                                           &rw.rxms[i][j & (RXMQ_SLOTS - 1)]) {
                                struct rxm *         r;
                                struct frct_cr *     snd_cr;
                                struct frct_cr *     rcv_cr;
                                size_t               rslot;
                                ssize_t              idx;
                                struct shm_du_buff * sdb;
                                uint8_t *            head;
                                struct flow *        f;
                                uint32_t             snd_lwe;
                                uint32_t             rcv_lwe;
                                time_t               rto;

                                r = list_entry(p, struct rxm, next);

                                list_del(&r->next);

                                snd_cr = &r->frcti->snd_cr;
                                rcv_cr = &r->frcti->rcv_cr;
                                f      = &ai.flows[r->fd];

                                shm_du_buff_ack(r->sdb);

                                if (f->frcti == NULL
                                    || f->flow_id != r->flow_id) {
                                        ipcp_sdb_release(r->sdb);
                                        free(r);
                                        continue;
                                }

                                pthread_rwlock_wrlock(&r->frcti->lock);

                                snd_lwe = snd_cr->lwe;
                                rcv_lwe = rcv_cr->lwe;
                                rto     = r->frcti->rto;

                                pthread_rwlock_unlock(&r->frcti->lock);

                                /* Has been ack'd, remove. */
                                if ((int) (r->seqno - snd_lwe) < 0) {
                                        ipcp_sdb_release(r->sdb);
                                        free(r);
                                        continue;
                                }

                                /* Check for r-timer expiry. */
                                if (ts_to_ns(now) - r->t0 > r->frcti->r) {
                                        ipcp_sdb_release(r->sdb);
                                        free(r);
                                        shm_rbuff_set_acl(f->rx_rb,
                                                          ACL_FLOWDOWN);
                                        shm_rbuff_set_acl(f->tx_rb,
                                                          ACL_FLOWDOWN);
                                        continue;
                                }

                                if (r->frcti->probe
                                    && (r->frcti->rttseq + 1) == r->seqno)
                                        r->frcti->probe = false;

                                /* Copy the data, safe rtx in other layers. */
                                if (ipcp_sdb_reserve(&sdb, r->tail - r->head)) {
                                        ipcp_sdb_release(r->sdb);
                                        free(r);
                                        shm_rbuff_set_acl(f->rx_rb,
                                                          ACL_FLOWDOWN);
                                        shm_rbuff_set_acl(f->tx_rb,
                                                          ACL_FLOWDOWN);
                                        continue;
                                }

                                idx = shm_du_buff_get_idx(sdb);

                                head = shm_du_buff_head(sdb);
                                memcpy(head, r->head, r->tail - r->head);

                                ipcp_sdb_release(r->sdb);

                                ((struct frct_pci *) head)->ackno =
                                        hton32(rcv_lwe);

                                /* Retransmit the copy. */
                                if (shm_rbuff_write_b(f->tx_rb, idx, NULL)) {
                                        ipcp_sdb_release(sdb);
                                        free(r);
                                        shm_rbuff_set_acl(f->rx_rb,
                                                          ACL_FLOWDOWN);
                                        shm_rbuff_set_acl(f->tx_rb,
                                                          ACL_FLOWDOWN);
                                        continue;
                                }

                                /* Reschedule. */
                                shm_du_buff_wait_ack(sdb);

                                shm_flow_set_notify(f->set,
                                                    f->flow_id,
                                                    FLOW_PKT);

                                r->head = head;
                                r->tail = shm_du_buff_tail(sdb);
                                r->sdb  = sdb;
                                r->mul++;

                                /* Schedule at least in the next time slot. */
                                rslot = (rxm_slot
                                         + MAX(((rto * r->mul) >> RXMQ_RES), 1))
                                        & (RXMQ_SLOTS - 1);

                                list_add_tail(&r->next, &rw.rxms[i][rslot]);
                        }
                }
                /* Move up a level in the wheel. */
                rxm_slot >>= RXMQ_BUMP;
        }

        ack_slot = ts_to_ack_slot(now) & (ACKQ_SLOTS - 1) ;

        j = rw.prv_ack;

        if (ack_slot < j)
                ack_slot += ACKQ_SLOTS;

        while (j++ < ack_slot) {
                list_for_each_safe(p, h, &rw.acks[j & (ACKQ_SLOTS - 1)]) {
                        struct ack *  a;
                        struct flow * f;

                        a = list_entry(p, struct ack, next);

                        list_del(&a->next);

                        f = &ai.flows[a->fd];

                        rw.map[j & (ACKQ_SLOTS - 1)][a->fd] = false;

                        if (f->flow_id == a->flow_id && f->frcti != NULL)
                                frct_send_ack(a->frcti);

                        free(a);

                }
        }

        rw.prv_ack = ack_slot & (ACKQ_SLOTS - 1);

        pthread_cleanup_pop(true);
}

static int timerwheel_rxm(struct frcti *       frcti,
                          uint32_t             seqno,
                          struct shm_du_buff * sdb)
{
        struct timespec now;
        struct rxm *    r;
        size_t          slot;
        size_t          lvl = 0;
        time_t          rto_slot;

        r = malloc(sizeof(*r));
        if (r == NULL)
                return -ENOMEM;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        r->t0    = ts_to_ns(now);
        r->mul   = 0;
        r->seqno = seqno;
        r->sdb   = sdb;
        r->head  = shm_du_buff_head(sdb);
        r->tail  = shm_du_buff_tail(sdb);
        r->frcti = frcti;

        pthread_rwlock_rdlock(&r->frcti->lock);

        rto_slot = frcti->rto >> RXMQ_RES;
        slot     = r->t0 >> RXMQ_RES;

        r->fd      = frcti->fd;
        r->flow_id = ai.flows[r->fd].flow_id;

        pthread_rwlock_unlock(&r->frcti->lock);

        while (rto_slot >= RXMQ_SLOTS) {
                ++lvl;
                rto_slot >>= RXMQ_BUMP;
                slot >>= RXMQ_BUMP;
        }

        if (lvl >= RXMQ_LVLS) { /* Out of timerwheel range. */
                free(r);
                return -EPERM;
        }

        slot = (slot + rto_slot) & (RXMQ_SLOTS - 1);

        pthread_mutex_lock(&rw.lock);

        list_add_tail(&r->next, &rw.rxms[lvl][slot]);

        shm_du_buff_wait_ack(sdb);

        pthread_mutex_unlock(&rw.lock);

        return 0;
}

static int timerwheel_ack(int            fd,
                          struct frcti * frcti)
{
        struct timespec now;
        struct ack *    a;
        size_t          slot;

        a = malloc(sizeof(*a));
        if (a == NULL)
                return -ENOMEM;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        slot = DELT_ACK >> ACKQ_RES;
        if (slot >= ACKQ_SLOTS) { /* Out of timerwheel range. */
                free(a);
                return -EPERM;
        }

        slot = (((ts_to_ns(now) + DELT_ACK) >> ACKQ_RES) + 1)
                & (ACKQ_SLOTS - 1);

        a->fd    = fd;
        a->frcti = frcti;
        a->flow_id = ai.flows[fd].flow_id;

        pthread_mutex_lock(&rw.lock);

        if (rw.map[slot][fd]) {
                pthread_mutex_unlock(&rw.lock);
                free(a);
                return 0;
        }

        rw.map[slot][fd] = true;

        list_add_tail(&a->next, &rw.acks[slot]);

        pthread_mutex_unlock(&rw.lock);

        return 0;
}
