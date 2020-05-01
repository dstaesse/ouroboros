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

#define RXMQ_S     16                 /* defines #slots           */
#define RXMQ_M     24                 /* defines max delay  (us)  */
#define RXMQ_R     (RXMQ_M - RXMQ_S)  /* defines resolution (us)  */
#define RXMQ_SLOTS (1 << RXMQ_S)
#define RXMQ_MAX   (1 << RXMQ_M)      /* us                       */

/* Small inacurracy to avoid slow division by MILLION. */
#define ts_to_us(ts) (ts.tv_sec * MILLION + (ts.tv_nsec >> 10))
#define ts_to_slot(ts) ((ts_to_us(ts) >> RXMQ_R) & (RXMQ_SLOTS - 1))

struct rxm {
        struct list_head     next;
        uint32_t             seqno;
        struct shm_du_buff * sdb;
        uint8_t *            head;
        uint8_t *            tail;
        time_t               t0;    /* Time when original was sent (us). */
        size_t               mul;   /* RTO multiplier.                   */
        struct frcti *       frcti;
};

struct rxmwheel {
        struct list_head wheel[RXMQ_SLOTS];

        size_t           prv; /* Last processed slot. */
        pthread_mutex_t  lock;
};

static void rxmwheel_destroy(struct rxmwheel * rw)
{
        size_t             i;
        struct list_head * p;
        struct list_head * h;

        pthread_mutex_destroy(&rw->lock);

        for (i = 0; i < RXMQ_SLOTS; ++i) {
                list_for_each_safe(p, h, &rw->wheel[i]) {
                        struct rxm * rxm = list_entry(p, struct rxm, next);
                        list_del(&rxm->next);
                        shm_du_buff_ack(rxm->sdb);
                        ipcp_sdb_release(rxm->sdb);
                        free(rxm);
                }
        }
}

static struct rxmwheel * rxmwheel_create(void)
{
        struct rxmwheel * rw;
        struct timespec   now;
        size_t            i;

        rw = malloc(sizeof(*rw));
        if (rw == NULL)
                return NULL;

        if (pthread_mutex_init(&rw->lock, NULL)) {
                free(rw);
                return NULL;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        /* Mark the previous timeslot as the last one processed. */
        rw->prv = (ts_to_slot(now) - 1) & (RXMQ_SLOTS - 1);

        for (i = 0; i < RXMQ_SLOTS; ++i)
                list_head_init(&rw->wheel[i]);

        return rw;
}

static void check_probe(struct frcti * frcti,
                        uint32_t       seqno)
{
        /* Disable rtt probe on retransmitted packet! */

        pthread_rwlock_wrlock(&frcti->lock);

        if (frcti->probe && ((frcti->rttseq + 1) == seqno)) {
                /* Backoff to avoid never updating rtt */
                frcti->srtt_us += frcti->mdev_us;
                frcti->probe = false;
        }

        pthread_rwlock_unlock(&frcti->lock);
}

static void rxmwheel_move(struct rxmwheel * rw)
{
        struct timespec    now;
        struct list_head * p;
        struct list_head * h;
        size_t             slot;
        size_t             i;

        pthread_mutex_lock(&rw->lock);

        pthread_cleanup_push((void (*) (void *)) pthread_mutex_unlock,
                             (void *) &rw->lock);

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        slot = ts_to_slot(now);

        i = rw->prv;

        if (slot < i)
                slot += RXMQ_SLOTS;

        while (i++ < slot) {
                list_for_each_safe(p, h, &rw->wheel[i & (RXMQ_SLOTS - 1)]) {
                        struct rxm *         r;
                        struct frct_cr *     snd_cr;
                        struct frct_cr *     rcv_cr;
                        size_t               rslot;
                        ssize_t              idx;
                        struct shm_du_buff * sdb;
                        uint8_t *            head;
                        struct flow *        f;
                        int                  fd;
                        uint32_t             snd_lwe;
                        uint32_t             rcv_lwe;
                        time_t               rto;

                        r = list_entry(p, struct rxm, next);

                        list_del(&r->next);

                        snd_cr = &r->frcti->snd_cr;
                        rcv_cr = &r->frcti->rcv_cr;
                        fd     = r->frcti->fd;
                        f      = &ai.flows[fd];

                        shm_du_buff_ack(r->sdb);

                        pthread_rwlock_rdlock(&r->frcti->lock);

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
                        if (ts_to_us(now) - r->t0 > r->frcti->r) {
                                ipcp_sdb_release(r->sdb);
                                free(r);
                                shm_rbuff_set_acl(ai.flows[fd].rx_rb,
                                                  ACL_FLOWDOWN);
                                shm_rbuff_set_acl(ai.flows[fd].tx_rb,
                                                  ACL_FLOWDOWN);
                                continue;
                        }

                        /* Copy the payload, safe rtx in other layers. */
                        if (ipcp_sdb_reserve(&sdb, r->tail - r->head)) {
                                ipcp_sdb_release(r->sdb);
                                free(r);
                                shm_rbuff_set_acl(f->rx_rb, ACL_FLOWDOWN);
                                shm_rbuff_set_acl(f->tx_rb, ACL_FLOWDOWN);
                                continue;
                        }

                        idx = shm_du_buff_get_idx(sdb);

                        head = shm_du_buff_head(sdb);
                        memcpy(head, r->head, r->tail - r->head);

                        /* Release the old copy. */
                        ipcp_sdb_release(r->sdb);

                        /* Disable using this seqno as rto probe. */
                        check_probe(r->frcti, r->seqno);

                        /* Update ackno and make sure DRF is not set. */
                        ((struct frct_pci *) head)->ackno = ntoh32(rcv_lwe);
                        ((struct frct_pci *) head)->flags &= ~FRCT_DRF;

                        /* Retransmit the copy. */
                        if (shm_rbuff_write_b(f->tx_rb, idx, NULL)) {
                                ipcp_sdb_release(sdb);
                                free(r);
                                shm_rbuff_set_acl(f->rx_rb, ACL_FLOWDOWN);
                                shm_rbuff_set_acl(f->tx_rb, ACL_FLOWDOWN);
                                continue;
                        }

                        /* Reschedule. */
                        shm_du_buff_wait_ack(sdb);

                        shm_flow_set_notify(f->set, f->flow_id, FLOW_PKT);

                        r->head = head;
                        r->tail = shm_du_buff_tail(sdb);
                        r->sdb  = sdb;

                        /* Schedule at least in the next time slot */
                        rslot = (slot + MAX(rto >> RXMQ_R, 1))
                                & (RXMQ_SLOTS - 1);

                        list_add_tail(&r->next, &rw->wheel[rslot]);
                }
        }

        rw->prv = slot & (RXMQ_SLOTS - 1);

        pthread_cleanup_pop(true);
}

static int rxmwheel_add(struct rxmwheel *    rw,
                        struct frcti *       frcti,
                        uint32_t             seqno,
                        struct shm_du_buff * sdb)
{
        struct timespec now;
        struct rxm *    r;
        size_t          slot;

        r = malloc(sizeof(*r));
        if (r == NULL)
                return -ENOMEM;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        r->t0    = ts_to_us(now);
        r->mul   = 0;
        r->seqno = seqno;
        r->sdb   = sdb;
        r->head  = shm_du_buff_head(sdb);
        r->tail  = shm_du_buff_tail(sdb);
        r->frcti = frcti;

        pthread_rwlock_rdlock(&r->frcti->lock);

        slot = (((r->t0 + frcti->rto) >> RXMQ_R) + 1) & (RXMQ_SLOTS - 1);

        pthread_rwlock_unlock(&r->frcti->lock);

        pthread_mutex_lock(&rw->lock);

        list_add_tail(&r->next, &rw->wheel[slot]);

        shm_du_buff_wait_ack(sdb);

        pthread_mutex_unlock(&rw->lock);

        return 0;
}
