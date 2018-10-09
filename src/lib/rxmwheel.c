/*
 * Ouroboros - Copyright (C) 2016 - 2018
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

#define RXMQ_S     12                 /* defines #slots     */
#define RXMQ_M     15                 /* defines max delay  */
#define RXMQ_R     (RXMQ_M - RXMQ_S)  /* defines resolution */
#define RXMQ_SLOTS (1 << RXMQ_S)
#define RXMQ_MAX   (1 << RXMQ_M)      /* ms                 */

/* Small inacurracy to avoid slow division by MILLION. */
#define ts_to_ms(ts) (ts.tv_sec * 1000 + (ts.tv_nsec >> 20))
#define ts_to_slot(ts) ((ts_to_ms(ts) >> RXMQ_R) & (RXMQ_SLOTS - 1))

struct rxm {
        struct list_head     next;
        uint32_t             seqno;
        struct shm_du_buff * sdb;
        uint8_t *            head;
        uint8_t *            tail;
        time_t               t0;    /* Time when original was sent (s).  */
        size_t               mul;   /* RTO multiplier.                   */
        struct frcti *       frcti;
};

struct {
        struct list_head wheel[RXMQ_SLOTS];

        size_t           prv; /* Last processed slot. */
        pthread_mutex_t  lock;
} rw;

static void rxmwheel_fini(void)
{
        size_t             i;
        struct list_head * p;
        struct list_head * h;

        for (i = 0; i < RXMQ_SLOTS; ++i) {
                list_for_each_safe(p, h, &rw.wheel[i]) {
                        struct rxm * rxm = list_entry(p, struct rxm, next);
                        list_del(&rxm->next);
                        free(rxm);
                }
        }
}

static int rxmwheel_init(void)
{
        struct timespec now;
        size_t          i;

        if (pthread_mutex_init(&rw.lock, NULL))
                return -1;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        /* Mark the previous timeslot as the last one processed. */
        rw.prv = (ts_to_slot(now) - 1) & (RXMQ_SLOTS - 1);

        for (i = 0; i < RXMQ_SLOTS; ++i)
                list_head_init(&rw.wheel[i]);

        return 0;
}

static void rxmwheel_clear(int fd)
{
        size_t i;

        /* FIXME: Add list element to avoid looping over full rxmwheel */
        pthread_mutex_lock(&rw.lock);

        for (i = 0; i < RXMQ_SLOTS; ++i) {
                struct list_head * p;
                struct list_head * h;

                list_for_each_safe(p, h, &rw.wheel[i]) {
                        struct rxm * r = list_entry(p, struct rxm, next);
                        if (r->frcti->fd == fd) {
                                list_del(&r->next);
                                shm_du_buff_ack(r->sdb);
                                ipcp_sdb_release(r->sdb);
                                free(r);
                        }
                }
        }

        pthread_mutex_unlock(&rw.lock);
}

/* Return fd on r-timer expiry. */
static int rxmwheel_move(void)
{
        struct timespec    now;
        struct list_head * p;
        struct list_head * h;
        size_t             slot;
        size_t             i;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        slot = ts_to_slot(now);

        pthread_mutex_lock(&rw.lock);

        for (i = rw.prv; (ssize_t) (i - slot) <= 0; ++i) {
                list_for_each_safe(p, h, &rw.wheel[i]) {
                        struct rxm *         r;
                        struct frct_cr *     snd_cr;
                        struct frct_cr *     rcv_cr;
                        size_t               rslot;
                        time_t               newtime;
                        ssize_t              idx;
                        struct shm_du_buff * sdb;
                        uint8_t *            head;
                        struct flow *        f;

                        r = list_entry(p, struct rxm, next);
                        list_del(&r->next);

                        snd_cr = &r->frcti->snd_cr;
                        rcv_cr = &r->frcti->rcv_cr;
                        /* Has been ack'd, remove. */
                        if ((int) (r->seqno - snd_cr->lwe) <= 0) {
                                shm_du_buff_ack(r->sdb);
                                ipcp_sdb_release(r->sdb);
                                free(r);
                                continue;
                        }
                        /* Check for r-timer expiry. */
                        if (ts_to_ms(now) - r->t0 > r->frcti->r) {
                                int fd = r->frcti->fd;
                                pthread_mutex_unlock(&rw.lock);
                                shm_du_buff_ack(r->sdb);
                                ipcp_sdb_release(r->sdb);
                                free(r);
                                return fd;
                        }

                        /* Copy the payload, safe rtx in other layers. */
                        if (ipcp_sdb_reserve(&sdb, r->tail - r->head)) {
                                /* FIXME: reschedule send? */
                                int fd = r->frcti->fd;
                                pthread_mutex_unlock(&rw.lock);
                                shm_du_buff_ack(r->sdb);
                                ipcp_sdb_release(r->sdb);
                                free(r);
                                return fd;
                        }

                        idx = shm_du_buff_get_idx(sdb);

                        head = shm_du_buff_head(sdb);
                        memcpy(head, r->head, r->tail - r->head);

                        /* Release the old copy */
                        shm_du_buff_ack(r->sdb);
                        ipcp_sdb_release(r->sdb);

                        /* Update ackno and make sure DRF is not set*/
                        ((struct frct_pci *) head)->ackno = ntoh32(rcv_cr->lwe);
                        ((struct frct_pci *) head)->flags &= ~FRCT_DRF;

                        f = &ai.flows[r->frcti->fd];

                        /* Retransmit the copy. */
                        if (shm_rbuff_write(f->tx_rb, idx)) {
                                ipcp_sdb_release(sdb);
                                free(r);
                                /* FIXME: reschedule send? */
                                continue;
                        }

                        shm_flow_set_notify(f->set, f->flow_id, FLOW_PKT);

                        /* Reschedule. */
                        shm_du_buff_wait_ack(sdb);

                        r->head = head;
                        r->tail = shm_du_buff_tail(sdb);
                        r->sdb  = sdb;

                        newtime = ts_to_ms(now) + (f->frcti->rto << ++r->mul);
                        rslot   = (newtime >> RXMQ_R) & (RXMQ_SLOTS - 1);

                        list_add_tail(&r->next, &rw.wheel[rslot]);
                }
        }

        rw.prv = slot;

        pthread_mutex_unlock(&rw.lock);

        return 0;
}

static int rxmwheel_add(struct frcti *       frcti,
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

        pthread_mutex_lock(&rw.lock);

        r->t0    = ts_to_ms(now);
        r->mul   = 0;
        r->seqno = seqno;
        r->sdb   = sdb;
        r->head  = shm_du_buff_head(sdb);
        r->tail  = shm_du_buff_tail(sdb);
        r->frcti = frcti;

        slot = ((r->t0 + frcti->rto) >> RXMQ_R) & (RXMQ_SLOTS - 1);

        list_add_tail(&r->next, &rw.wheel[slot]);

        pthread_mutex_unlock(&rw.lock);

        shm_du_buff_wait_ack(sdb);

        return 0;
}
