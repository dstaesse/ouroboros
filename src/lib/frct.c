/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Flow and Retransmission Control
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

#define DELT_RDV         (100 * MILLION) /* ns */
#define MAX_RDV            (1 * BILLION) /* ns */

#define FRCT             "frct"
#define FRCT_PCILEN      (sizeof(struct frct_pci))
#define FRCT_NAME_STRLEN 32

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
        time_t            rdv;

        time_t            srtt;        /* Smoothed rtt           */
        time_t            mdev;        /* Deviation              */
        time_t            rto;         /* Retransmission timeout */
        uint32_t          rttseq;
        struct timespec   t_probe;     /* Probe time             */
        bool              probe;       /* Probe active           */
#ifdef PROC_FLOW_STATS
        size_t            n_rtx;       /* Number of rxm packets  */
        size_t            n_dup;       /* Duplicates received    */
        size_t            n_rdv;       /* Number of rdv packets  */
        size_t            n_out;       /* Packets out of window  */
        size_t            n_rqo;       /* Packets out of rqueue  */
#endif
        struct frct_cr    snd_cr;
        struct frct_cr    rcv_cr;


        ssize_t           rq[RQ_SIZE];
        pthread_rwlock_t  lock;

        bool              open;        /* Window open/closed     */
        struct timespec   t_wnd;       /* Window closed time     */
        struct timespec   t_rdvs;      /* Last rendez-vous sent  */
        pthread_cond_t    cond;
        pthread_mutex_t   mtx;
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

        uint8_t  pad;    /* 24 bit window! */
        uint16_t window;

        uint32_t seqno;
        uint32_t ackno;
} __attribute__((packed));

#ifdef PROC_FLOW_STATS

static int frct_rib_read(const char * path,
                         char *       buf,
                         size_t       len)
{
        struct timespec now;
        char *          entry;
        struct flow *   flow;
        struct frcti *  frcti;
        int             fd;

        (void) len;

        entry = strstr(path, RIB_SEPARATOR);
        assert(entry);
        *entry = '\0';

        fd = atoi(path);

        flow = &ai.flows[fd];

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_rdlock(&ai.lock);

        frcti = flow->frcti;

        pthread_rwlock_rdlock(&frcti->lock);

        sprintf(buf,
                "Maximum packet lifetime (ns):    %20ld\n"
                "Max time to Ack (ns):            %20ld\n"
                "Max time to Retransmit (ns):     %20ld\n"
                "Smoothed rtt (ns):               %20ld\n"
                "RTT standard deviation (ns):     %20ld\n"
                "Retransmit timeout RTO (ns):     %20ld\n"
                "Sender left window edge:         %20u\n"
                "Sender right window edge:        %20u\n"
                "Sender inactive (ns):            %20ld\n"
                "Sender current sequence number:  %20u\n"
                "Receiver left window edge:       %20u\n"
                "Receiver right window edge:      %20u\n"
                "Receiver inactive (ns):          %20ld\n"
                "Receiver last ack:               %20u\n"
                "Number of pkt retransmissions:   %20zu\n"
                "Number of duplicates received:   %20zu\n"
                "Number of rendez-vous sent:      %20zu\n"
                "Number of packets out of window: %20zu\n"
                "Number of packets out of rqueue: %20zu\n",
                frcti->mpl,
                frcti->a,
                frcti->r,
                frcti->srtt,
                frcti->mdev,
                frcti->rto,
                frcti->snd_cr.lwe,
                frcti->snd_cr.rwe,
                ts_diff_ns(&frcti->snd_cr.act, &now),
                frcti->snd_cr.seqno,
                frcti->rcv_cr.lwe,
                frcti->rcv_cr.rwe,
                ts_diff_ns(&frcti->rcv_cr.act, &now),
                frcti->rcv_cr.seqno,
                frcti->n_rtx,
                frcti->n_dup,
                frcti->n_rdv,
                frcti->n_out,
                frcti->n_rqo);

        pthread_rwlock_unlock(&flow->frcti->lock);

        pthread_rwlock_unlock(&ai.lock);

        return strlen(buf);
}

static int frct_rib_readdir(char *** buf)
{
        *buf = malloc(sizeof(**buf));
        if (*buf == NULL)
                goto fail_malloc;

        (*buf)[0] = strdup("frct");
        if ((*buf)[0] == NULL)
                goto fail_strdup;

        return 1;

 fail_strdup:
        free(*buf);
 fail_malloc:
        return -ENOMEM;
}

static int frct_rib_getattr(const char *      path,
                            struct rib_attr * attr)
{
        (void) path;
        (void) attr;

        attr->size  = 1027;
        attr->mtime = 0;

        return 0;
}


static struct rib_ops r_ops = {
        .read    = frct_rib_read,
        .readdir = frct_rib_readdir,
        .getattr = frct_rib_getattr
};

#endif /* PROC_FLOW_STATS */

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

static void __send_frct_pkt(int      fd,
                            uint8_t  flags,
                            uint32_t ackno,
                            uint32_t rwe)
{
        struct shm_du_buff * sdb;
        struct frct_pci *    pci;
        ssize_t              idx;
        struct flow *        f;

        /* Raw calls needed to bypass frcti. */
#ifdef RXM_BLOCKING
        idx = shm_rdrbuff_alloc_b(ai.rdrb, sizeof(*pci), NULL, &sdb, NULL);
#else
        idx = shm_rdrbuff_alloc(ai.rdrb, sizeof(*pci), NULL, &sdb);
#endif
        if (idx < 0)
                return;

        pci = (struct frct_pci *) shm_du_buff_head(sdb);
        memset(pci, 0, sizeof(*pci));

        *((uint32_t *) pci) = hton32(rwe);

        pci->flags = flags;
        pci->ackno = hton32(ackno);

        f = &ai.flows[fd];

        if (f->qs.cypher_s > 0 && crypt_encrypt(f, sdb) < 0)
                goto fail;

#ifdef RXM_BLOCKING
        if (shm_rbuff_write_b(f->tx_rb, idx, NULL))
#else
        if (shm_rbuff_write(f->tx_rb, idx))
#endif
                goto fail;

        shm_flow_set_notify(f->set, f->flow_id, FLOW_PKT);

        return;

 fail:
        ipcp_sdb_release(sdb);
        return;
}

static void send_frct_pkt(struct frcti * frcti)
{
        struct timespec      now;
        time_t               diff;
        uint32_t             ackno;
        uint32_t             rwe;
        int                  fd;

        assert(frcti);

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_wrlock(&frcti->lock);

        if (!after(frcti->rcv_cr.lwe, frcti->rcv_cr.seqno)) {
                pthread_rwlock_unlock(&frcti->lock);
                return;
        }

        fd    = frcti->fd;
        ackno = frcti->rcv_cr.lwe;
        rwe   = frcti->rcv_cr.rwe;

        diff = ts_diff_ns(&frcti->rcv_cr.act, &now);

        if (diff > frcti->a || diff < frcti->mdev) {
                pthread_rwlock_unlock(&frcti->lock);
                return;
        }

        frcti->rcv_cr.seqno = frcti->rcv_cr.lwe;

        pthread_rwlock_unlock(&frcti->lock);

        __send_frct_pkt(fd, FRCT_ACK | FRCT_FC, ackno, rwe);

}

static void __send_rdv(int fd)
{
        __send_frct_pkt(fd, FRCT_RDVS, 0, 0);
}

static struct frcti * frcti_create(int    fd,
                                   time_t a,
                                   time_t r,
                                   time_t mpl)
{
        struct frcti *      frcti;
        ssize_t             idx;
        struct timespec     now;
        pthread_condattr_t  cattr;
#ifdef PROC_FLOW_STATS
        char                frctstr[FRCT_NAME_STRLEN + 1];
#endif
        mpl *= BILLION;
        a   *= BILLION;
        r   *= BILLION;

        frcti = malloc(sizeof(*frcti));
        if (frcti == NULL)
                goto fail_malloc;

        memset(frcti, 0, sizeof(*frcti));

        if (pthread_rwlock_init(&frcti->lock, NULL))
                goto fail_lock;

        if (pthread_mutex_init(&frcti->mtx, NULL))
                goto fail_mutex;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&frcti->cond, &cattr))
                goto fail_cond;

#ifdef PROC_FLOW_STATS
        sprintf(frctstr, "%d", fd);
        if (rib_reg(frctstr, &r_ops))
                goto fail_rib_reg;
#endif
        pthread_condattr_destroy(&cattr);

        for (idx = 0; idx < RQ_SIZE; ++idx)
                frcti->rq[idx] = -1;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        frcti->mpl = mpl;
        frcti->a   = a;
        frcti->r   = r;
        frcti->rdv = DELT_RDV;
        frcti->fd  = fd;


        frcti->rttseq = 0;
        frcti->probe  = false;

        frcti->srtt = 0;            /* Updated on first ACK */
        frcti->mdev = 10 * MILLION; /* Initial rxm will be after 20 ms */
        frcti->rto  = BILLION;      /* Initial rxm will be after 1 s   */
#ifdef PROC_FLOW_STATS
        frcti->n_rtx = 0;
        frcti->n_dup = 0;
        frcti->n_rdv = 0;
        frcti->n_out = 0;
        frcti->n_rqo = 0;
#endif
        if (ai.flows[fd].qs.loss == 0) {
                frcti->snd_cr.cflags |= FRCTFRTX | FRCTFLINGER;
                frcti->rcv_cr.cflags |= FRCTFRTX;
        }

        frcti->snd_cr.cflags |= FRCTFRESCNTL;

        frcti->snd_cr.rwe = START_WINDOW;

        frcti->snd_cr.inact  = (3 * mpl + a + r) / BILLION + 1; /* s */
        frcti->snd_cr.act.tv_sec = now.tv_sec - (frcti->snd_cr.inact + 1);

        frcti->rcv_cr.inact = (2 * mpl + a + r)  / BILLION + 1; /* s */
        frcti->rcv_cr.act.tv_sec = now.tv_sec - (frcti->rcv_cr.inact + 1);

        return frcti;

#ifdef PROC_FLOW_STATS
 fail_rib_reg:
        pthread_cond_destroy(&frcti->cond);
#endif
 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(&frcti->mtx);
 fail_mutex:
        pthread_rwlock_destroy(&frcti->lock);
 fail_lock:
        free(frcti);
 fail_malloc:
        return NULL;
}

static void frcti_destroy(struct frcti * frcti)
{
#ifdef PROC_FLOW_STATS
        char frctstr[FRCT_NAME_STRLEN + 1];
        sprintf(frctstr, "%d", frcti->fd);
        rib_unreg(frctstr);
#endif
        pthread_cond_destroy(&frcti->cond);
        pthread_mutex_destroy(&frcti->mtx);
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
        flags |= FRCTFRTX; /* Should not be set by command */

        assert(frcti);

        pthread_rwlock_wrlock(&frcti->lock);

        frcti->snd_cr.cflags &= FRCTFRTX; /* Zero other flags */

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

#define frcti_is_window_open(frcti)                     \
        (frcti == NULL ? true : __frcti_is_window_open(frcti))

#define frcti_window_wait(frcti, abstime)               \
        (frcti == NULL ? 0 : __frcti_window_wait(frcti, abstime))


static bool __frcti_is_window_open(struct frcti * frcti)
{
        struct frct_cr * snd_cr = &frcti->snd_cr;
        bool             ret    = true;

        pthread_rwlock_rdlock(&frcti->lock);

        if (snd_cr->cflags & FRCTFRESCNTL)
                ret = before(snd_cr->seqno, snd_cr->rwe);

        if (!ret) {
                struct timespec now;

                clock_gettime(PTHREAD_COND_CLOCK, &now);

                pthread_mutex_lock(&frcti->mtx);
                if (frcti->open) {
                        frcti->open   = false;
                        frcti->t_wnd  = now;
                        frcti->t_rdvs = now;
                } else {
                        time_t diff;
                        diff = ts_diff_ns(&frcti->t_wnd, &now);
                        if (diff > MAX_RDV) {
                                pthread_mutex_unlock(&frcti->mtx);
                                pthread_rwlock_unlock(&frcti->lock);
                                return false;
                        }

                        diff = ts_diff_ns(&frcti->t_rdvs, &now);
                        if  (diff > frcti->rdv) {
                                frcti->t_rdvs = now;
                                __send_rdv(frcti->fd);
#ifdef PROC_FLOW_STATS
                                frcti->n_rdv++;
#endif

                        }
                }

                pthread_mutex_unlock(&frcti->mtx);
        }

        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

static int __frcti_window_wait(struct frcti *    frcti,
                               struct timespec * abstime)
{
        struct frct_cr * snd_cr = &frcti->snd_cr;
        int ret                 = 0;

        pthread_rwlock_rdlock(&frcti->lock);

        if (!(snd_cr->cflags & FRCTFRESCNTL)) {
                pthread_rwlock_unlock(&frcti->lock);
                return 0;
        }

        while (snd_cr->seqno == snd_cr->rwe && ret != -ETIMEDOUT) {
                struct timespec now;

                pthread_rwlock_unlock(&frcti->lock);
                pthread_mutex_lock(&frcti->mtx);

                if (frcti->open) {
                        clock_gettime(PTHREAD_COND_CLOCK, &now);

                        frcti->t_wnd  = now;
                        frcti->t_rdvs = now;
                        frcti->open   = false;
                }

                pthread_cleanup_push(__cleanup_mutex_unlock, &frcti->mtx);

                ret = -pthread_cond_timedwait(&frcti->cond,
                                              &frcti->mtx,
                                              abstime);

                pthread_cleanup_pop(false);

                if (ret == -ETIMEDOUT) {
                        time_t diff;

                        clock_gettime(PTHREAD_COND_CLOCK, &now);

                        diff = ts_diff_ns(&frcti->t_wnd, &now);
                        if (diff > MAX_RDV) {
                                pthread_mutex_unlock(&frcti->mtx);
                                return -ECONNRESET; /* write fails! */
                        }

                        diff = ts_diff_ns(&frcti->t_rdvs, &now);
                        if  (diff > frcti->rdv) {
                                frcti->t_rdvs = now;
                                __send_rdv(frcti->fd);
                        }
                }

                pthread_mutex_unlock(&frcti->mtx);
                pthread_rwlock_rdlock(&frcti->lock);
        }

        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

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
                ++frcti->rcv_cr.rwe;
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
        wait = MAX(wait, 0);

        if (frcti->snd_cr.cflags & FRCTFLINGER
            && before(frcti->snd_cr.lwe, frcti->snd_cr.seqno))
                wait = -wait;

        pthread_rwlock_unlock(&frcti->lock);

        if (fd != -1)
                __send_frct_pkt(fd, FRCT_ACK, ackno, 0);

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
        assert(shm_du_buff_head(sdb) != shm_du_buff_tail(sdb));

        snd_cr = &frcti->snd_cr;
        rcv_cr = &frcti->rcv_cr;

        timerwheel_move();

        pci = (struct frct_pci *) shm_du_buff_head_alloc(sdb, FRCT_PCILEN);
        if (pci == NULL)
                return -ENOMEM;

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
                snd_cr->lwe = snd_cr->seqno;
                snd_cr->rwe = snd_cr->lwe + START_WINDOW;
        }

        seqno = snd_cr->seqno;
        pci->seqno = hton32(seqno);

        if (now.tv_sec - rcv_cr->act.tv_sec < rcv_cr->inact) {
                pci->flags |= FRCT_FC;
                *((uint32_t *) pci) |= hton32(rcv_cr->rwe & 0x00FFFFFF);
        }

        if (!rtx) {
                snd_cr->lwe++;
        } else {
                if (!frcti->probe) {
                        frcti->rttseq  = snd_cr->seqno;
                        frcti->t_probe = now;
                        frcti->probe   = true;
                }
                if ((now.tv_sec - rcv_cr->act.tv_sec) * BILLION <= frcti->a) {
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
        frcti->rto      = MAX(RTO_MIN, frcti->srtt + (frcti->mdev << 2));
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
        struct frct_cr *  snd_cr;
        uint32_t          seqno;
        uint32_t          ackno;
        uint32_t          rwe;
        int               fd = -1;

        assert(frcti);

        rcv_cr = &frcti->rcv_cr;
        snd_cr = &frcti->snd_cr;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pci = (struct frct_pci *) shm_du_buff_head_release(sdb, FRCT_PCILEN);

        idx = shm_du_buff_get_idx(sdb);
        seqno = ntoh32(pci->seqno);
        pos = seqno & (RQ_SIZE - 1);

        pthread_rwlock_wrlock(&frcti->lock);

        if (now.tv_sec - rcv_cr->act.tv_sec > rcv_cr->inact) {
                if (pci->flags & FRCT_DRF)  { /* New run. */
                        rcv_cr->lwe = seqno;
                        rcv_cr->rwe = seqno + RQ_SIZE;
                } else {
                        goto drop_packet;
                }
        }

        /* For now, just send an immediate window update. */
        if (pci->flags & FRCT_RDVS) {
                fd = frcti->fd;
                rwe = rcv_cr->rwe;
                pthread_rwlock_unlock(&frcti->lock);

                __send_frct_pkt(fd, FRCT_FC, 0, rwe);

                shm_rdrbuff_remove(ai.rdrb, idx);
                return;
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

        if (pci->flags & FRCT_FC) {
                uint32_t rwe;

                rwe = ntoh32(*((uint32_t *)pci) & hton32(0x00FFFFFF));
                rwe |= snd_cr->rwe & 0xFF000000;

                /* Rollover for 24 bit */
                if (before(rwe, snd_cr->rwe) && snd_cr->rwe - rwe > 0x007FFFFF)
                        rwe += 0x01000000;

                snd_cr->rwe = rwe;

                pthread_mutex_lock(&frcti->mtx);
                if (!frcti->open) {
                        frcti->open = true;
                        pthread_cond_broadcast(&frcti->cond);
                }
                pthread_mutex_unlock(&frcti->mtx);
        }

        if (!(pci->flags & FRCT_DATA))
                goto drop_packet;

        if (before(seqno, rcv_cr->lwe)) {
                rcv_cr->seqno = seqno; /* Ensures we send a new ACK. */
#ifdef PROC_FLOW_STATS
                frcti->n_dup++;
#endif
                goto drop_packet;
        }

        if (rcv_cr->cflags & FRCTFRTX) {

                if (!before(seqno, rcv_cr->rwe)) {  /* Out of window. */
#ifdef PROC_FLOW_STATS
                        frcti->n_out++;
#endif
                        goto drop_packet;
                }

                if (!before(seqno, rcv_cr->lwe + RQ_SIZE))  {
#ifdef PROC_FLOW_STATS
                        frcti->n_rqo++;
#endif
                        goto drop_packet; /* Out of rq. */
                }
                if (frcti->rq[pos] != -1) {
#ifdef PROC_FLOW_STATS
                        frcti->n_dup++;
#endif
                        goto drop_packet; /* Duplicate in rq. */
                }
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

        send_frct_pkt(frcti);

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
