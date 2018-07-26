/*
 * Ouroboros - Copyright (C) 2016 - 2018
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
#define DELT_MPL       60000 /* ms */
#define DELT_A         0     /* ms */
#define DELT_R         2000  /* ms */

#define RQ_SIZE        64

#define TW_ELEMENTS    6000
#define TW_RESOLUTION  1     /* ms */

#define FRCT_PCILEN    (sizeof(struct frct_pci))
#define FRCT_CRCLEN    (sizeof(uint32_t))

struct frct_cr {
        bool     drf;
        uint32_t lwe;
        uint32_t rwe;

        uint32_t seqno;
        bool     conf;
        uint8_t  cflags;

        time_t   rto;     /* ms */
        time_t   act;     /* s */
        time_t   inact;   /* s */
};

struct frcti {
        int              fd;

        time_t           mpl;
        time_t           a;
        time_t           r;

        struct frct_cr   snd_cr;
        struct frct_cr   rcv_cr;

        ssize_t          rq[RQ_SIZE];
        pthread_rwlock_t lock;
};

enum frct_flags {
        FRCT_DATA = 0x01, /* PDU carries data */
        FRCT_DRF  = 0x02, /* Data run flag    */
        FRCT_ACK  = 0x03, /* ACK field valid  */
        FRCT_FC   = 0x08, /* FC window valid  */
        FRCT_RDVZ = 0x10, /* Rendez-vous      */
        FRCT_CFG  = 0x20, /* Configuration    */
        FRCT_MFGM = 0x40, /* More fragments   */
        FRCT_CRC  = 0x80, /* CRC present      */
};

struct frct_pci {
        uint8_t  flags;

        uint8_t  cflags;

        uint16_t window;

        uint32_t seqno;
        uint32_t ackno;
} __attribute__((packed));

#include <rxmwheel.c>

static struct frcti * frcti_create(int       fd,
                                   qoscube_t qc)
{
        struct frcti *  frcti;
        time_t          delta_t;
        ssize_t         idx;
        struct timespec now;

        frcti = malloc(sizeof(*frcti));
        if (frcti == NULL)
                goto fail_malloc;

        memset(frcti, 0, sizeof(*frcti));

        if (pthread_rwlock_init(&frcti->lock, NULL))
                goto fail_lock;

        for (idx = 0; idx < RQ_SIZE; ++idx)
                frcti->rq[idx] = -1;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        frcti->mpl = DELT_MPL;
        frcti->a   = DELT_A;
        frcti->r   = DELT_R;
        frcti->fd  = fd;

        delta_t = (frcti->mpl + frcti->a + frcti->r) / 1000;

        if (qc == QOS_CUBE_DATA)
                frcti->snd_cr.cflags |= FRCTFRTX;

        frcti->snd_cr.conf   = true;
        frcti->snd_cr.inact  = 3 * delta_t + 1;
        frcti->snd_cr.act    = now.tv_sec - (frcti->snd_cr.inact + 1);
        /* Initial rto. FIXME: recalc using Karn algorithm. */
        frcti->snd_cr.rto    = 120;

        frcti->rcv_cr.inact  = 2 * delta_t + 1;
        frcti->rcv_cr.act    = now.tv_sec - (frcti->rcv_cr.inact + 1);

        return frcti;

 fail_lock:
        free(frcti);
 fail_malloc:
        return NULL;
}

static void frcti_destroy(struct frcti * frcti)
{
        /*
         * FIXME: In case of reliable transmission we should
         * make sure everything is acked.
         */

        rxmwheel_clear(frcti->fd);

        pthread_rwlock_destroy(&frcti->lock);

        free(frcti);
}

static int frcti_setconf(struct frcti * frcti,
                         uint16_t       flags)
{
        assert(frcti);

        pthread_rwlock_wrlock(&frcti->lock);

        if (frcti->snd_cr.cflags != flags) {
                frcti->snd_cr.cflags = flags;
                frcti->snd_cr.conf   = true;
                frcti->snd_cr.drf    = true;
        }

        pthread_rwlock_unlock(&frcti->lock);

        return 0;
}

static uint16_t frcti_getconf(struct frcti * frcti)
{
        uint16_t ret;

        assert (frcti);

        pthread_rwlock_rdlock(&frcti->lock);

        ret = frcti->snd_cr.cflags;

        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

#define frcti_queued_pdu(frcti) \
        (frcti == NULL ? -1 : __frcti_queued_pdu(frcti))

#define frcti_snd(frcti, sdb) \
        (frcti == NULL ? 0 : __frcti_snd(frcti, sdb))

#define frcti_rcv(frcti, sdb) \
        (frcti == NULL ? 0 : __frcti_rcv(frcti, sdb))

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
                struct shm_du_buff * sdb;
                struct frct_pci *    pci;

                sdb = shm_rdrbuff_get(ai.rdrb, idx);
                pci = (struct frct_pci *) shm_du_buff_head(sdb) - 1;
                if (pci->flags & FRCT_CFG)
                        frcti->rcv_cr.cflags = pci->cflags;

                ++frcti->rcv_cr.lwe;
                frcti->rq[pos] = -1;
        }

        pthread_rwlock_unlock(&frcti->lock);

        return idx;
}

static int frct_chk_crc(uint8_t * head,
                        uint8_t * tail)
{
        uint32_t crc;

        mem_hash(HASH_CRC32, &crc, head, tail - head);

        return crc == *((uint32_t *) tail);
}

static void frct_add_crc(uint8_t * head,
                         uint8_t * tail)
{
        mem_hash(HASH_CRC32, tail, head, tail - head);
}

static struct frct_pci * frcti_alloc_head(struct shm_du_buff * sdb)
{
        struct frct_pci * pci;

        pci = (struct frct_pci *) shm_du_buff_head_alloc(sdb, FRCT_PCILEN);
        if (pci != NULL)
                memset(pci, 0, sizeof(*pci));

        return pci;
}

static int __frcti_snd(struct frcti *       frcti,
                       struct shm_du_buff * sdb)
{
        struct frct_pci * pci;
        struct timespec   now;
        struct frct_cr *  snd_cr;
        struct frct_cr *  rcv_cr;

        assert(frcti);

        snd_cr = &frcti->snd_cr;
        rcv_cr = &frcti->rcv_cr;

        rxmwheel_move();

        pci = frcti_alloc_head(sdb);
        if (pci == NULL)
                return -1;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_wrlock(&frcti->lock);

        pci->flags |= FRCT_DATA;

        if (snd_cr->cflags & FRCTFERRCHCK) {
                uint8_t * tail = shm_du_buff_tail_alloc(sdb, FRCT_CRCLEN);
                if (tail == NULL) {
                        pthread_rwlock_unlock(&frcti->lock);
                        return -1;
                }

                frct_add_crc((uint8_t *) pci, tail);

                pci->flags |= FRCT_CRC;
        }

        /* Set DRF if there are no unacknowledged packets. */
        if (snd_cr->seqno == snd_cr->lwe)
                pci->flags |= FRCT_DRF;

        if (snd_cr->conf) {
                /* FIXME: This packet must be acked! */
                pci->flags |= FRCT_CFG;
                pci->cflags = snd_cr->cflags;
        }

        /* Choose a new sequence number if sender inactivity expired. */
        if (now.tv_sec - snd_cr->act > snd_cr->inact) {
                /* There are no unacknowledged packets. */
                assert(snd_cr->seqno == snd_cr->lwe);
#ifdef CONFIG_OUROBOROS_DEBUG
                frcti->snd_cr.seqno = 0;
#else
                random_buffer(&snd_cr->seqno, sizeof(snd_cr->seqno));
#endif
                frcti->snd_cr.lwe = frcti->snd_cr.seqno;
        }

        pci->seqno = hton32(snd_cr->seqno);
        if (!(snd_cr->cflags & FRCTFRTX)) {
                snd_cr->lwe++;
        } else if (now.tv_sec - rcv_cr->act <= rcv_cr->inact) {
                rxmwheel_add(frcti, snd_cr->seqno, sdb);
                pci->flags |= FRCT_ACK;
                pci->ackno = hton32(rcv_cr->lwe);
        }

        snd_cr->seqno++;
        snd_cr->act  = now.tv_sec;
        snd_cr->conf = false;

        pthread_rwlock_unlock(&frcti->lock);

        return 0;
}

/* Returns 0 when idx contains an SDU for the application. */
static int __frcti_rcv(struct frcti *       frcti,
                       struct shm_du_buff * sdb)
{
        ssize_t           idx;
        struct frct_pci * pci;
        struct timespec   now;
        struct frct_cr *  snd_cr;
        struct frct_cr *  rcv_cr;
        uint32_t          seqno;
        int               ret = 0;

        assert(frcti);

        rcv_cr = &frcti->rcv_cr;
        snd_cr = &frcti->snd_cr;

        pci = (struct frct_pci *) shm_du_buff_head_release(sdb, FRCT_PCILEN);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_wrlock(&frcti->lock);

        idx = shm_du_buff_get_idx(sdb);

        /* PDU may be corrupted. */
        if (pci->flags & FRCT_CRC) {
                uint8_t * tail = shm_du_buff_tail_release(sdb, FRCT_CRCLEN);
                if (frct_chk_crc((uint8_t *) pci, tail))
                        goto drop_packet;
        }

        seqno = ntoh32(pci->seqno);

        /* Check if receiver inactivity is true. */
        if (now.tv_sec - rcv_cr->act > rcv_cr->inact) {
                /* Inactive receiver, check for DRF. */
                if (pci->flags & FRCT_DRF) /* New run. */
                        rcv_cr->lwe = seqno - 1;
                else
                        goto drop_packet;
        }

        if (seqno == rcv_cr->lwe + 1) {
                rcv_cr->lwe = seqno;
                /* Check for online reconfiguration. */
                if (pci->flags & FRCT_CFG)
                        rcv_cr->cflags = pci->cflags;
        } else { /* Out of order. */
                if ((int32_t)(seqno - rcv_cr->lwe) <= 0) /* Duplicate. */
                        goto drop_packet;

                if (rcv_cr->cflags & FRCTFRTX) {
                        size_t pos = seqno & (RQ_SIZE - 1);
                        if ((seqno - rcv_cr->lwe) > RQ_SIZE /* Out of rq. */
                            || frcti->rq[pos] != -1) /* Duplicate in rq. */
                                goto drop_packet;
                        /* Queue. */
                        frcti->rq[pos] = idx;
                        ret = -EAGAIN;
                } else {
                        rcv_cr->lwe = seqno;
                }
        }

        if (rcv_cr->cflags & FRCTFRTX && pci->flags & FRCT_ACK) {
                uint32_t ackno = ntoh32(pci->ackno);
                /* Check for duplicate (old) acks. */
                if ((int32_t)(ackno - snd_cr->lwe) >= 0)
                        snd_cr->lwe = ackno;
        }

        rcv_cr->act = now.tv_sec;

        if (!(pci->flags & FRCT_DATA))
                shm_rdrbuff_remove(ai.rdrb, idx);

        pthread_rwlock_unlock(&frcti->lock);

        rxmwheel_move();

        return ret;

 drop_packet:
        shm_rdrbuff_remove(ai.rdrb, idx);
        pthread_rwlock_unlock(&frcti->lock);
        rxmwheel_move();
        return -EAGAIN;
}
