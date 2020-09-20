/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Flow and Retransmission Control
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

/* Default Delta-t parameters */
#define DELT_MPL        (5 * BILLION) /* ns */
#define DELT_A          (1 * BILLION) /* ns */
#define DELT_R         (20 * BILLION) /* ns */

#define DELT_ACK       (10 * MILLION) /* ns */

#define RQ_SIZE        256

#define FRCT_PCILEN    (sizeof(struct frct_pci))

struct frct_cr {
        uint32_t        lwe;     /* Left window edge               */
        uint32_t        rwe;     /* Right window edge              */

        uint8_t         cflags;
        uint32_t        seqno;   /* SEQ to send, or last SEQ Ack'd */

        struct timespec act;     /* Last seen activity             */
        time_t          inact;   /* Inactivity (s)                 */
};

struct frcti {
        int               fd;

        time_t            mpl;
        time_t            a;
        time_t            r;

        time_t            srtt;        /* Smoothed rtt           */
        time_t            mdev;        /* Deviation              */
        time_t            rto;         /* Retransmission timeout */
        uint32_t          rttseq;
        struct timespec   t_probe;     /* Probe time             */
        bool              probe;       /* Probe active           */

        struct frct_cr    snd_cr;
        struct frct_cr    rcv_cr;

        ssize_t           rq[RQ_SIZE];
        pthread_rwlock_t  lock;
};

enum frct_flags {
        FRCT_DATA = 0x01, /* PDU carries data */
        FRCT_DRF  = 0x02, /* Data run flag    */
        FRCT_ACK  = 0x04, /* ACK field valid  */
        FRCT_FC   = 0x08, /* FC window valid  */
        FRCT_RDVS = 0x10, /* Rendez-vous      */
        FRCT_FFGM = 0x20, /* First Fragment   */
        FRCT_MFGM = 0x40, /* More fragments   */
};

struct frct_pci {
        uint8_t  flags;

        uint8_t  pad;

        uint16_t window;

        uint32_t seqno;
        uint32_t ackno;
} __attribute__((packed));

static bool before(uint32_t seq1,
                   uint32_t seq2)
{
        return (int32_t)(seq1 - seq2) < 0;
}

static bool after(uint32_t seq1,
                  uint32_t seq2)
{
        return (int32_t)(seq2 - seq1) < 0;
}

static void __send_ack(int fd,
                       int ackno)
{
        struct shm_du_buff * sdb;
        struct frct_pci *    pci;
        ssize_t              idx;
        struct flow *        f;

        /* Raw calls needed to bypass frcti. */
        idx = shm_rdrbuff_alloc_b(ai.rdrb, sizeof(*pci), NULL, &sdb, NULL);
        if (idx < 0)
                return;

        pci = (struct frct_pci *) shm_du_buff_head(sdb);
        memset(pci, 0, sizeof(*pci));

        pci->flags = FRCT_ACK;
        pci->ackno = hton32(ackno);

        f = &ai.flows[fd];

        if (shm_rbuff_write_b(f->tx_rb, idx, NULL)) {
                ipcp_sdb_release(sdb);
                return;
        }

        shm_flow_set_notify(f->set, f->flow_id, FLOW_PKT);
}

static void frct_send_ack(struct frcti * frcti)
{
        struct timespec      now;
        time_t               diff;
        uint32_t             ackno;
        int                  fd;

        assert(frcti);

        pthread_rwlock_rdlock(&frcti->lock);

        if (frcti->rcv_cr.lwe == frcti->rcv_cr.seqno) {
                pthread_rwlock_unlock(&frcti->lock);
                return;
        }

        ackno = frcti->rcv_cr.lwe;
        fd    = frcti->fd;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        diff = ts_diff_ns(&frcti->rcv_cr.act, &now);

        pthread_rwlock_unlock(&frcti->lock);

        if (diff > frcti->a || diff < DELT_ACK)
                return;

        __send_ack(fd, ackno);

        pthread_rwlock_wrlock(&frcti->lock);

        if (after(frcti->rcv_cr.lwe, frcti->rcv_cr.seqno))
                frcti->rcv_cr.seqno = frcti->rcv_cr.lwe;

        pthread_rwlock_unlock(&frcti->lock);
}

static struct frcti * frcti_create(int fd)
{
        struct frcti *  frcti;
        ssize_t         idx;
        struct timespec now;
        time_t          mpl;
        time_t          a;
        time_t          r;

        frcti = malloc(sizeof(*frcti));
        if (frcti == NULL)
                goto fail_malloc;

        memset(frcti, 0, sizeof(*frcti));

        if (pthread_rwlock_init(&frcti->lock, NULL))
                goto fail_lock;

        for (idx = 0; idx < RQ_SIZE; ++idx)
                frcti->rq[idx] = -1;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        frcti->mpl = mpl = DELT_MPL;
        frcti->a   = a   = DELT_A;
        frcti->r   = r   = DELT_R;
        frcti->fd  = fd;


        frcti->rttseq = 0;
        frcti->probe  = false;

        frcti->srtt = 0;            /* Updated on first ACK */
        frcti->mdev = 10 * MILLION; /* Initial rxm will be after 20 ms */
        frcti->rto  = 20 * MILLION; /* Initial rxm will be after 20 ms */

        if (ai.flows[fd].qs.loss == 0) {
                frcti->snd_cr.cflags |= FRCTFRTX | FRCTFLINGER;
                frcti->rcv_cr.cflags |= FRCTFRTX;
        }

        frcti->snd_cr.inact  = (3 * mpl + a + r) / BILLION + 1; /* s */
        frcti->snd_cr.act.tv_sec = now.tv_sec - (frcti->snd_cr.inact + 1);

        frcti->rcv_cr.inact = (2 * mpl + a + r)  / BILLION + 1; /* s */
        frcti->rcv_cr.act.tv_sec = now.tv_sec - (frcti->rcv_cr.inact + 1);

        return frcti;

 fail_lock:
        free(frcti);
 fail_malloc:
        return NULL;
}

static void frcti_destroy(struct frcti * frcti)
{
        pthread_rwlock_destroy(&frcti->lock);

        free(frcti);
}

static uint16_t frcti_getflags(struct frcti * frcti)
{
        uint16_t ret;

        assert(frcti);

        pthread_rwlock_rdlock(&frcti->lock);

        ret = frcti->snd_cr.cflags;

        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

static void frcti_setflags(struct frcti * frcti,
                           uint16_t       flags)
{
        flags |= FRCTFRESCNTRL | FRCTFRTX; /* Should not be set by command */

        assert(frcti);

        pthread_rwlock_wrlock(&frcti->lock);

        frcti->snd_cr.cflags &= FRCTFRESCNTRL | FRCTFRTX; /* Zero other flags */

        frcti->snd_cr.cflags &= flags;

        pthread_rwlock_unlock(&frcti->lock);
}

#define frcti_queued_pdu(frcti)                         \
        (frcti == NULL ? idx : __frcti_queued_pdu(frcti))

#define frcti_snd(frcti, sdb)                           \
        (frcti == NULL ? 0 : __frcti_snd(frcti, sdb))

#define frcti_rcv(frcti, sdb)                           \
        (frcti == NULL ? 0 : __frcti_rcv(frcti, sdb))

#define frcti_tick(frcti)                               \
        (frcti == NULL ? 0 : __frcti_tick())

#define frcti_dealloc(frcti)                            \
        (frcti == NULL ? 0 : __frcti_dealloc(frcti))

static ssize_t __frcti_queued_pdu(struct frcti * frcti)
{
        ssize_t idx;
        size_t  pos;

        assert(frcti);

        /* See if we already have the next PDU. */
        pthread_rwlock_wrlock(&frcti->lock);

        pos = frcti->rcv_cr.lwe & (RQ_SIZE - 1);

        idx = frcti->rq[pos];
        if (idx != -1) {
                ++frcti->rcv_cr.lwe;
                frcti->rq[pos] = -1;
        }

        pthread_rwlock_unlock(&frcti->lock);

        return idx;
}

static ssize_t __frcti_pdu_ready(struct frcti * frcti)
{
        ssize_t idx;
        size_t  pos;

        assert(frcti);

        /* See if we already have the next PDU. */
        pthread_rwlock_rdlock(&frcti->lock);

        pos = frcti->rcv_cr.lwe & (RQ_SIZE - 1);
        idx = frcti->rq[pos];

        pthread_rwlock_unlock(&frcti->lock);

        return idx;
}

#include <timerwheel.c>

/*
 * Send a final ACK for everything that has not been ACK'd.
 * If the flow should be kept active for retransmission,
 * the returned time will be negative.
 */
static time_t __frcti_dealloc(struct frcti * frcti)
{
        struct timespec now;
        time_t          wait;
        int             ackno;
        int             fd = -1;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_rdlock(&frcti->lock);

        ackno = frcti->rcv_cr.lwe;
        if (frcti->rcv_cr.lwe != frcti->rcv_cr.seqno)
                fd = frcti->fd;

        wait = MAX(frcti->rcv_cr.inact - now.tv_sec + frcti->rcv_cr.act.tv_sec,
                   frcti->snd_cr.inact - now.tv_sec + frcti->snd_cr.act.tv_sec);

        if (frcti->snd_cr.cflags & FRCTFLINGER
            && before(frcti->snd_cr.lwe, frcti->snd_cr.seqno))
                wait = -wait;

        pthread_rwlock_unlock(&frcti->lock);

        if (fd != -1)
                __send_ack(fd, ackno);

        return wait;
}

static int __frcti_snd(struct frcti *       frcti,
                       struct shm_du_buff * sdb)
{
        struct frct_pci * pci;
        struct timespec   now;
        struct frct_cr *  snd_cr;
        struct frct_cr *  rcv_cr;
        uint32_t          seqno;
        bool              rtx;

        assert(frcti);

        snd_cr = &frcti->snd_cr;
        rcv_cr = &frcti->rcv_cr;

        timerwheel_move();

        pci = (struct frct_pci *) shm_du_buff_head_alloc(sdb, FRCT_PCILEN);
        if (pci == NULL)
                return -1;

        memset(pci, 0, sizeof(*pci));

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_wrlock(&frcti->lock);

        rtx = snd_cr->cflags & FRCTFRTX;

        pci->flags |= FRCT_DATA;

        /* Set DRF if there are no unacknowledged packets. */
        if (snd_cr->seqno == snd_cr->lwe)
                pci->flags |= FRCT_DRF;

        /* Choose a new sequence number if sender inactivity expired. */
        if (now.tv_sec - snd_cr->act.tv_sec > snd_cr->inact) {
                /* There are no unacknowledged packets. */
                assert(snd_cr->seqno == snd_cr->lwe);
                random_buffer(&snd_cr->seqno, sizeof(snd_cr->seqno));
                frcti->snd_cr.lwe = snd_cr->seqno - 1;
        }

        seqno = snd_cr->seqno;
        pci->seqno = hton32(seqno);

        if (!rtx) {
                snd_cr->lwe++;
        } else {
                if (!frcti->probe) {
                        frcti->rttseq  = snd_cr->seqno;
                        frcti->t_probe = now;
                        frcti->probe   = true;
                }

                if (now.tv_sec - rcv_cr->act.tv_sec <= rcv_cr->inact) {
                        pci->flags |= FRCT_ACK;
                        pci->ackno = hton32(rcv_cr->lwe);
                        rcv_cr->seqno = rcv_cr->lwe;
                }
        }

        snd_cr->seqno++;
        snd_cr->act = now;

        pthread_rwlock_unlock(&frcti->lock);

        if (rtx)
                timerwheel_rxm(frcti, seqno, sdb);

        return 0;
}

static void rtt_estimator(struct frcti * frcti,
                          time_t         mrtt)
{
        time_t srtt     = frcti->srtt;
        time_t rttvar   = frcti->mdev;

        if (srtt == 0) { /* first measurement */
                srtt   = mrtt;
                rttvar = mrtt >> 1;
        } else {
                time_t delta = mrtt - srtt;
                srtt += (delta >> 3);
                rttvar += (ABS(delta) - rttvar) >> 2;
        }

        frcti->srtt     = MAX(1000U, srtt);
        frcti->mdev     = MAX(100U, rttvar);
        frcti->rto      = MAX(RTO_MIN * 1000,
                              frcti->srtt + (frcti->mdev << 1));
}

static void __frcti_tick(void)
{
        timerwheel_move();
}

/* Always queues the next application packet on the RQ. */
static void __frcti_rcv(struct frcti *       frcti,
                        struct shm_du_buff * sdb)
{
        ssize_t           idx;
        size_t            pos;
        struct frct_pci * pci;
        struct timespec   now;
        struct frct_cr *  rcv_cr;
        uint32_t          seqno;
        uint32_t          ackno;
        int               fd = -1;

        assert(frcti);

        rcv_cr = &frcti->rcv_cr;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pci = (struct frct_pci *) shm_du_buff_head_release(sdb, FRCT_PCILEN);

        idx = shm_du_buff_get_idx(sdb);
        seqno = ntoh32(pci->seqno);
        pos = seqno & (RQ_SIZE - 1);

        pthread_rwlock_wrlock(&frcti->lock);

        if (now.tv_sec - rcv_cr->act.tv_sec > rcv_cr->inact) {
                if (pci->flags & FRCT_DRF) /* New run. */
                        rcv_cr->lwe = seqno;
                else
                        goto drop_packet;
        }

        if (pci->flags & FRCT_ACK) {
                ackno = ntoh32(pci->ackno);
                if (after(ackno, frcti->snd_cr.lwe))
                        frcti->snd_cr.lwe = ackno;

                if (frcti->probe && after(ackno, frcti->rttseq)) {
                        rtt_estimator(frcti, ts_diff_ns(&frcti->t_probe, &now));
                        frcti->probe = false;
                }
        }

        if (!(pci->flags & FRCT_DATA))
                goto drop_packet;

        if (before(seqno, rcv_cr->lwe)) {
                rcv_cr->seqno = seqno;
                goto drop_packet;
        }

        if (rcv_cr->cflags & FRCTFRTX) {
                if ((seqno - rcv_cr->lwe) >= RQ_SIZE)
                        goto drop_packet; /* Out of rq. */

                if (frcti->rq[pos] != -1)
                        goto drop_packet; /* Duplicate in rq. */

                fd = frcti->fd;
        } else {
                rcv_cr->lwe = seqno;
        }

        frcti->rq[pos] = idx;

        rcv_cr->act = now;

        pthread_rwlock_unlock(&frcti->lock);

        if (fd != -1)
                timerwheel_ack(fd, frcti);

        return;

 drop_packet:
        pthread_rwlock_unlock(&frcti->lock);

        frct_send_ack(frcti);

        shm_rdrbuff_remove(ai.rdrb, idx);
        return;
}

/* Filter fqueue events for non-data packets */
int frcti_filter(struct fqueue * fq)
{
        struct shm_du_buff * sdb;
        int                  fd;
        ssize_t              idx;
        struct frcti *       frcti;
        struct shm_rbuff *   rb;

        while (fq->next < fq->fqsize) {
                if (fq->fqueue[fq->next + 1] != FLOW_PKT)
                        return 1;

                pthread_rwlock_rdlock(&ai.lock);

                fd = ai.ports[fq->fqueue[fq->next]].fd;
                rb = ai.flows[fd].rx_rb;
                frcti = ai.flows[fd].frcti;

                if (frcti == NULL) {
                        pthread_rwlock_unlock(&ai.lock);
                        return 1;
                }

                if (__frcti_pdu_ready(frcti) >= 0) {
                        pthread_rwlock_unlock(&ai.lock);
                        return 1;
                }

                idx = shm_rbuff_read(rb);
                if (idx < 0) {
                        pthread_rwlock_unlock(&ai.lock);
                        return 0;
                }

                sdb = shm_rdrbuff_get(ai.rdrb, idx);

                __frcti_rcv(frcti, sdb);

                if (__frcti_pdu_ready(frcti) >= 0) {
                        pthread_rwlock_unlock(&ai.lock);
                        return 1;
                }

                pthread_rwlock_unlock(&ai.lock);

                fq->next += 2;
        }

        return fq->next < fq->fqsize;
}
