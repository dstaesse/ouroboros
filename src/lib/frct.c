/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Flow and Retransmission Control Task (FRCT)
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

/* Included by dev.c; uses dev.c statics (proc, spb_encrypt, ...). */

#define DELT_RDV         (100 * MILLION) /* ns */
#define MAX_RDV          (1 * BILLION)   /* ns */

#define MAX_RTO_MUL      20              /* caps the RTO backoff shift */
#define INITIAL_RTO      (1 * BILLION)   /* RFC 6298 §2.1: 1 s default */
#define RTT_BOOT_NS      (10 * MILLION)  /* rtt_hint floor + initial mdev */
#define SRTT_FLOOR_NS    1000L           /* 1 us; smoothed RTT floor */
#define MDEV_FLOOR_NS    100L            /* 100 ns; mdev sanity floor */
#define RTT_CLAMP_MUL    16              /* probe sample cap = N * srtt */
#define MIN_RTT_WIN_NS   (300ULL * BILLION) /* 5 min, Linux tcp default */
#define NACK_COOLDOWN_NS (100 * MILLION) /* pre-DRF NACK cooldown fallback */

#define FRCT             "frct"
#define FRCT_PCILEN      (sizeof(struct frct_pci))
#define FRCT_NAME_STRLEN 32

/* Wire-protocol cap on SACK blocks per packet; binds both peers. */
#define SACK_MAX_BLOCKS  2048
#define SACK_BLOCK_SIZE  (2 * sizeof(uint32_t))
/* 2B count + 2B pad to 4-byte align the block list. */
#define SACK_HDR_SIZE    (sizeof(uint32_t))
#define SACK_MIN_GAP_NS  (250u * 1000u)         /* 250 us SACK gap     */
#define MIN_REORDER_NS   (250u * 1000u)         /* 250 us RACK floor   */
#define SACK_RXM_MAX     32   /* Cap on retransmits staged from single SACK.*/
#define DUP_THRESH       3    /* RFC 8985 §6.2 step 2.2 SACK count gate.    */

/* RFC 8985 §7.2 RACK reorder-window scaling cap. */
#define REO_WND_MULT_MAX 20
/* RFC 8985 §7.2 step 5: round trips of no DSACK before halving. */
#define REO_DECAY_PKTS   16
/* DSACK seqno sanity: reject reports older/farther than one rcv window. */
#define MAX_DSACK_LAG    RQ_SIZE

/* FRCT r-timer: do not retransmit packet older than t_r (from first send). */
#define RXM_AGED_OUT(t0, now_ns, t_r) (((now_ns) - (t0)) > (uint64_t) (t_r))

/* FRCT a-timer: do not (re)transmit ACK after t_a from last data receive. */
#define ACK_AGED_OUT(act, now_ns, t_a) (((now_ns) - (act)) > (uint64_t) (t_a))

struct sack_args {
        uint16_t n;
        bool     dsack;         /* RFC 2883: block[0] is a DSACK report   */
        uint32_t ack;
        uint32_t rwe;
        uint32_t blocks[][2];   /* flexible — sized at alloc time */
};

/* NewReno-careful (RFC 6582) exit pad; gates RTT samples post-signal. */
#define RTT_QUARANTINE   32
#define RTTP_NONCE_LEN   16

/* RTT-probe wire payload (after the FRCT PCI). */
struct frct_rttp {
        uint32_t probe_id;                 /* sender counter; 0 on reply  */
        uint32_t echo_id;                  /* peer's probe_id; 0 outbound */
        uint8_t  nonce[RTTP_NONCE_LEN];    /* random; echoed verbatim     */
} __attribute__((packed));

#define RTTP_PAYLOAD sizeof(struct frct_rttp)
#define RTTP_POS(id) ((id) & (RTTP_RING - 1))

/*
 * Flag values are assigned MSB-first on the wire (RFC convention):
 * bit 0 = 0x8000 occupies wire-position 0 of the 16-bit flags
 * field, bit 11 = 0x0010 is the last assigned bit, and the four
 * LSBs (0x000F) are reserved.
 */
enum frct_flags {
        FRCT_DATA = 0x8000, /* PDU carries data                         */
        FRCT_DRF  = 0x4000, /* Data run flag                            */
        FRCT_ACK  = 0x2000, /* ACK field valid                          */
        FRCT_NACK = 0x1000, /* Neg-ACK: pci->seqno is arrival_seqno - 1 */
        FRCT_FC   = 0x0800, /* FC window valid                          */
        FRCT_RDVS = 0x0400, /* Rendez-vous                              */
        FRCT_FFGM = 0x0200, /* First fragment (begin)                   */
        FRCT_LFGM = 0x0100, /* Last fragment (end)                      */
        FRCT_RXM  = 0x0080, /* Retransmission                           */
        FRCT_SACK = 0x0040, /* SACK block list follows                  */
        FRCT_RTTP = 0x0020, /* RTT probe / echo                         */
        FRCT_KA   = 0x0010, /* Keepalive                                */
        FRCT_FIN  = 0x0008, /* End of stream (stream)                   */
};

/*
 * DATA-packet fragment role (FFGM = begin, LFGM = end), SCTP-style:
 *   1 1 = sole / un-fragmented SDU (begin AND end)
 *   1 0 = first fragment of a multi-fragment SDU
 *   0 0 = middle fragment
 *   0 1 = last fragment
 */
#define FRCT_FR_MASK  (FRCT_FFGM | FRCT_LFGM)
#define FRCT_FR_SOLE  (FRCT_FFGM | FRCT_LFGM)
#define FRCT_FR_FIRST (FRCT_FFGM)
#define FRCT_FR_MID   (0)
#define FRCT_FR_LAST  (FRCT_LFGM)

/* Default cap on a single reassembled SDU. App can raise via FRCTSMAXSDU */
#define FRCT_MAX_SDU          (1U << 20)

/* Stream-mode PCI extension: [start, end) byte range on every DATA pkt. */
struct frct_pci_stream {
        uint32_t start;
        uint32_t end;
} __attribute__((packed));

#define FRCT_PCI_STREAM_LEN  (sizeof(struct frct_pci_stream))

/* Bytes following PCI: SACK list / RTTP nonce / control payload. */
#define FRCT_BODY(pci)    ((uint8_t *) (pci) + FRCT_PCILEN)
/* Typed access to the stream PCI extension on stream DATA packets. */
#define FRCT_SPCI(pci) \
        ((struct frct_pci_stream *) ((uint8_t *) (pci) + FRCT_PCILEN))

/* Push the FRCT header onto spb's head. */
#define FRCT_HDR_PUSH(spb, frcti)                                       \
        ((struct frct_pci *) ssm_pk_buff_push((spb),                    \
                                              frcti_data_hdr_len(frcti)))

/* Pop a fixed-size header off spb's head; cast to type *. */
#define FRCT_HDR_POP(spb, type)                                         \
        ((struct type *) ssm_pk_buff_pop((spb), sizeof(struct type)))

/* Default / max per-flow stream rx ring (pow2); min N * per_pkt. */
#define FRCT_STREAM_RING_MIN_PKTS 4
#define FRCT_STREAM_RING_SZ      (1U << 20)  /* 1 MiB default */
#define FRCT_STREAM_RING_SZ_MAX  (1U << 27)  /* 128 MiB       */

struct frct_pci {
        uint16_t flags;
        uint16_t hcs;

        uint32_t window;
        uint32_t seqno;
        uint32_t ackno;
} __attribute__((packed));

/* Stat counters; fold to no-ops without PROC_FLOW_STATS. */
#ifdef PROC_FLOW_STATS
struct frcti_stat {
        size_t rxm_snd;         /* RXM packets sent                */
        size_t rxm_rcv;         /* RXM packets received            */
        size_t rxm_fire;        /* tw RXM fires                    */
        size_t rxm_sack;        /* SACK-driven retransmits         */
        size_t rxm_rack;        /* RACK fast retransmits           */
        size_t rxm_dupthresh;   /* DupThresh-driven retransmits    */
        size_t rxm_due_count;   /* rxm_due entries (pre-bail)      */
        size_t rxm_due_acked;   /* bail: seqno < snd_lwe           */
        size_t rxm_due_unowned; /* bail: slot.rxm replaced         */
        size_t rxm_due_aged;    /* bail: r->t0 + t_r < now         */
        size_t rxm_arm_fail;    /* rxm_arm: malloc failed          */
        size_t rxm_cancel;      /* entries cancelled at teardown   */
        size_t ack_snd;         /* ACK packets sent (bare + SACK)  */
        size_t ack_fire;        /* delayed-ACK timer fires         */
        size_t ack_supp_seqno;  /* fire suppressed: seqno          */
        size_t ack_supp_inact;  /* fire suppressed: inact          */
        size_t ack_supp_rate;   /* fire suppressed: rate           */
        size_t ack_rcv;         /* ACK packets received            */
        size_t ack_rtt;         /* ACKs that fed RTT estimator     */
        size_t ack_dup_rcv;     /* ACK packet wire dups dropped    */
        size_t dup_rcv;         /* duplicates received             */
        size_t out_rcv;         /* pkts out of window              */
        size_t rqo_rcv;         /* pkts out of rqueue              */
        size_t ooo_rcv;         /* OOO arrivals                    */
        size_t sack_snd;        /* SACK packets sent               */
        size_t sack_rcv;        /* SACK packets received           */
        size_t dsack_snd;       /* SACK pkts carrying a DSACK      */
        size_t dsack_rcv;       /* DSACK blocks parsed             */
        size_t dsack_drop;      /* DSACK blocks past MAX_DSACK_LAG */
        size_t nack_snd;        /* pre-DRF NACKs sent              */
        size_t nack_rcv;        /* pre-DRF NACKs received          */
        size_t rttp_snd;        /* RTT probes sent                 */
        size_t rttp_rcv;        /* RTT probe replies rcvd          */
        size_t rtt_smpl;        /* RTT estimator samples           */
        size_t rdv_snd;         /* rendez-vous packets sent        */
        size_t rdv_rcv;         /* rendez-vous packets rcvd        */
        size_t ka_snd;          /* keepalives sent                 */
        size_t ka_rcv;          /* keepalives received             */
        size_t sdu_snd_frag;    /* writes that fragmented          */
        size_t frag_snd;        /* fragments sent: FIRST/MID/LAST  */
        size_t frag_rcv;        /* fragments stashed in rq[]       */
        size_t sdu_reasm;       /* SDUs delivered reassembled      */
        size_t frag_drop;       /* dropped at malformed run        */
        size_t strm_snd_byte;   /* bytes sent on stream            */
        size_t strm_rcv_byte;   /* bytes copied to ring            */
        size_t strm_dlv_byte;   /* bytes delivered to reader       */
        size_t strm_drop;       /* stream rcvs dropped             */
        size_t strm_fin_drop;   /* stream FIN packets rejected     */
        /* Profiling instrumentation. */
        size_t rcv_proc_ns;     /* time inside FRCTI_RCV (ns)      */
        size_t tw_move_ns;      /* time inside tw_move (ns)        */
        size_t drain_calls;     /* flow_drain_rx_nb invocations    */
};

#define STAT_BUMP(frcti, field)   FETCH_ADD_RELAXED(&(frcti)->stat.field, 1)
#define STAT_ADD(frcti, field, v) FETCH_ADD_RELAXED(&(frcti)->stat.field, (v))
#define STAT_LOAD(frcti, field)   LOAD_RELAXED(&(frcti)->stat.field)
#else
#define STAT_BUMP(frcti, field)   ((void) (frcti))
#define STAT_ADD(frcti, field, v) ((void) (frcti))
#define STAT_LOAD(frcti, field)   ((void) (frcti), (size_t) 0)
#endif

#define frcti_to_flow(f) (&proc.flows[(f)->fd])

#define RTTP_RING        8
#define RTTP_COLD_NS     (100 * MILLION)        /* cold-probe cadence */
#define RQ_SLOT(seqno)   ((seqno) & (RQ_SIZE - 1))

struct rxm_entry;

enum snd_slot_flags {
        SND_RTX      = 0x01, /* Any retransmit; Karn skips next RTT sample. */
        SND_FAST_RXM = 0x02, /* Fast-retx one-shot gate per loss event.     */
};

struct snd_slot {
        struct rxm_entry * rxm;   /* RXM entry, NULL if none.          */
        uint64_t           time;  /* ts_to_ns of last send (any kind). */
        uint8_t            flags; /* SND_* bits above.                 */
};

/* Per-seqno reorder slot (FRTX) and stream-mode byte/FIN metadata. */
struct rcv_slot {
        ssize_t  idx;     /* spb idx; -1 = empty              */
        uint32_t start;   /* stream byte start                */
        uint32_t end;     /* stream byte end                  */
        uint8_t  fin;     /* stream FIN bit                   */
};

struct frct_cr {
        uint32_t lwe;     /* Left window edge                  */
        uint32_t rwe;     /* Right window edge                 */

        uint8_t  cflags;
        uint32_t seqno;   /* SEQ to send, or last SEQ Ack'd    */
        uint32_t ackno;   /* snd: ACK-pkt seqno; rcv: dedup    */

        uint64_t act;     /* ts_to_ns of last activity         */
        uint64_t inact;   /* Inactivity threshold (ns)         */
};

struct frcti {
        /* IMM: set once in frcti_create; read-only thereafter. */
        int               fd;
        uint64_t          t_mpl;           /* MPL (ns)                    */
        uint64_t          t_a;             /* a-timer (ns)                */
        uint64_t          t_r;             /* r-timer (ns)                */
        uint64_t          t_rdv;           /* RDV cooldown (ns)           */
        time_t            ber;             /* cached qs.ber               */
        bool              lossy;           /* qs.loss != 0                */
        time_t            qs_timeout;      /* cached qs.timeout (ms)      */
        size_t            frag_mtu;        /* max FRCT pkt: PCI + payload */
        uint16_t          sack_n_max;      /* SACK blocks that fit MTU    */
        bool              stream;

        /* All fields below are protected by lock (rwlock/LOAD_ACQUIRE).  */
        struct {
                struct frct_cr   snd_cr;
                struct frct_cr   rcv_cr;

                /* RTT/RACK estimator */
                time_t           srtt;                /* smoothed RTT     */
                time_t           mdev;                /* mean deviation   */
                time_t           min_rtt;             /* RACK base, ns    */
                uint64_t         t_min_rtt;           /* min_rtt last set */
                time_t           rto;                 /* retransmit TO    */
                time_t           rto_min;             /* RTO floor (ns)   */
                uint8_t          rto_mul;             /* RTO backoff bits */
                uint32_t         rtt_lwe;             /* RTT-sample fence */
                uint64_t         t_rcv_rtt;           /* last RTT feed    */
                uint64_t         t_snd_probe;         /* last probe sent  */
                uint64_t         t_latest_ack;        /* RACK.fack snd-ts */
                uint32_t         probe_id_next;
                struct {
                        uint32_t id;
                        uint64_t ts;                    /* ts_to_ns send  */
                        uint8_t  nonce[RTTP_NONCE_LEN]; /* echoed back    */
                } probes[RTTP_RING];

                /* rcv reassembly */
                size_t           max_rcv_sdu;         /* max reasm bytes  */
                uint8_t *        rcv_ring;            /* lazy alloc       */
                size_t           rcv_ring_sz;         /* power of 2       */
                uint32_t         ring_seq_cap;        /* ring/per_pkt     */

                uint32_t         snd_byte_next;
                bool             snd_fin_sent;
                uint32_t         snd_fin_seqno;
                uint32_t         rcv_byte_next;
                uint32_t         rcv_byte_high;       /* contiguous high  */
                uint32_t         rcv_byte_fin;        /* set when FIN     */
                bool             rcv_fin_seen;

                struct rcv_slot  rcv_slots[RQ_SIZE];
                struct snd_slot  snd_slots[RQ_SIZE];  /* .rxm is ATOM     */

                /* rcv SACK dedup */
                uint64_t         t_snd_sack;
                uint32_t         sack_lwe;            /* rcv lwe at SACK  */
                uint16_t         sack_n;              /* SACK block count */

                /* RFC 2883 D-SACK: pending report (single-slot, latest). */
                uint32_t         dsack_seqno;
                bool             dsack_valid;

                /* RFC 8985 §7.2 RACK reorder-window scaling. */
                uint8_t          reo_wnd_mult;        /* 1..REO_WND_MULT_MAX */
                uint32_t         dsack_lwe_snap;      /* lwe @ last DSACK */

                uint32_t         dup_thresh;          /* RFC 8985         */
                uint64_t         t_nack;
                bool             open;                /* FC window state  */
                bool             in_recovery;
                uint32_t         recovery_high;       /* seqno @ entry    */
                uint32_t         rack_fired_lwe;      /* lwe @ last RACK  */
                struct timespec  t_wnd;               /* window-closed ts */
                struct timespec  t_last_rdv;          /* last RDV sent    */
                struct list_head rxm_list;            /* live rxm entries */

                pthread_rwlock_t lock;
        };

        /* Read/written via __atomic without holding lock. */
        uint64_t          t_ka_rcv;        /* ts_to_ns of last KA rx      */
        uint8_t           ack_pending;     /* delayed-ACK dedup           */

        /* Timer entries; ownership belongs to the tw module. */
        struct tw_entry   ack_tw;          /* delayed-ACK timer           */
        struct tw_entry   ka_tw;           /* keepalive timer             */

#ifdef PROC_FLOW_STATS
        /* STAT: lock-free relaxed atomic counters. */
        struct frcti_stat stat;
#endif
};

#ifdef PROC_FLOW_STATS

__attribute__((cold))
static int frct_rib_read(const char * path,
                         char *       buf,
                         size_t       len)
{
        struct frcti *  frcti;
        struct timespec now;
        uint64_t        now_ns;
        char *          entry;
        int             fd;
        int             written;
        /* Snapshot under the locks; format outside (pure userspace). */
        struct {
                uint64_t          t_mpl;
                uint64_t          t_a;
                uint64_t          t_r;
                time_t            srtt;
                time_t            mdev;
                time_t            rto;
                time_t            min_rtt;
                struct frct_cr    snd_cr;
                struct frct_cr    rcv_cr;
                struct frcti_stat stat;
        } s;

        entry = strstr(path, RIB_SEPARATOR);
        assert(entry);
        *entry = '\0';

        fd = atoi(path);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        if (fd < 0 || fd >= PROC_MAX_FLOWS)
                return 0;

        pthread_rwlock_rdlock(&proc.lock);

        frcti = proc.flows[fd].frcti;
        if (frcti == NULL) {
                pthread_rwlock_unlock(&proc.lock);
                return 0;
        }

        s.t_mpl  = frcti->t_mpl;
        s.t_a    = frcti->t_a;
        s.t_r    = frcti->t_r;

        pthread_rwlock_rdlock(&frcti->lock);

        s.srtt    = frcti->srtt;
        s.mdev    = frcti->mdev;
        s.rto     = frcti->rto;
        s.min_rtt = frcti->min_rtt;
        s.snd_cr  = frcti->snd_cr;
        s.rcv_cr  = frcti->rcv_cr;
        s.stat    = frcti->stat;

        pthread_rwlock_unlock(&frcti->lock);
        pthread_rwlock_unlock(&proc.lock);

        written = snprintf(buf, len,
                "Maximum packet lifetime (ns):    %20" PRIu64 "\n"
                "Max time to Ack (ns):            %20" PRIu64 "\n"
                "Max time to Retransmit (ns):     %20" PRIu64 "\n"
                "Smoothed rtt (ns):               %20ld\n"
                "RTT standard deviation (ns):     %20ld\n"
                "Retransmit timeout RTO (ns):     %20ld\n"
                "Minimum RTT (RACK base, ns):     %20ld\n"
                "Sender left window edge:         %20u\n"
                "Sender right window edge:        %20u\n"
                "Sender inactive (ns):            %20lld\n"
                "Sender current sequence number:  %20u\n"
                "Receiver left window edge:       %20u\n"
                "Receiver right window edge:      %20u\n"
                "Receiver inactive (ns):          %20lld\n"
                "Receiver last ack:               %20u\n"
                "RXM packets sent:                %20zu\n"
                "RXM packets received:            %20zu\n"
                "RXM timer fires:                 %20zu\n"
                "RXM (SACK-driven) sent:          %20zu\n"
                "RXM (RACK-driven) sent:          %20zu\n"
                "RXM (DupThresh-driven) sent:     %20zu\n"
                "ACK packets sent:                %20zu\n"
                "Delayed-ACK timer fires:         %20zu\n"
                "  suppressed (seqno):            %20zu\n"
                "  suppressed (inact):            %20zu\n"
                "  suppressed (rate):             %20zu\n"
                "ACK packets received:            %20zu\n"
                "  fed RTT estimator:             %20zu\n"
                "  wire dups dropped:             %20zu\n"
                "Duplicates received:             %20zu\n"
                "Out-of-window pkts received:     %20zu\n"
                "Out-of-rqueue pkts received:     %20zu\n"
                "OOO arrivals:                    %20zu\n"
                "SACKs sent:                      %20zu\n"
                "SACKs received:                  %20zu\n"
                "D-SACKs sent:                    %20zu\n"
                "D-SACKs received:                %20zu\n"
                "D-SACK out-of-range dropped:     %20zu\n"
                "Pre-DRF NACKs sent:              %20zu\n"
                "Pre-DRF NACKs received:          %20zu\n"
                "RTT probes sent:                 %20zu\n"
                "RTT probe replies received:      %20zu\n"
                "RTT estimator samples:           %20zu\n"
                "Rendez-vous packets sent:        %20zu\n"
                "Rendez-vous packets received:    %20zu\n"
                "Keepalives sent:                 %20zu\n"
                "Keepalives received:             %20zu\n"
                "SDU writes fragmented:           %20zu\n"
                "Fragments sent:                  %20zu\n"
                "Fragments received:              %20zu\n"
                "SDUs delivered reassembled:      %20zu\n"
                "Fragments dropped (malformed):   %20zu\n"
                "Stream bytes sent:               %20zu\n"
                "Stream bytes received:           %20zu\n"
                "Stream bytes delivered:          %20zu\n"
                "Stream packets dropped:          %20zu\n"
                "Stream FINs dropped:             %20zu\n"
                "FRCTI_RCV time (ns):             %20zu\n"
                "tw_move time (ns):               %20zu\n"
                "drain_rx_nb calls:               %20zu\n"
                "RXM-due entries:                 %20zu\n"
                "  bail (acked):                  %20zu\n"
                "  bail (unowned):                %20zu\n"
                "  bail (aged):                   %20zu\n"
                "RXM-arm malloc failures:         %20zu\n"
                "RXM cancels (teardown):          %20zu\n",
                s.t_mpl, s.t_a, s.t_r,
                s.srtt, s.mdev, s.rto, s.min_rtt,
                s.snd_cr.lwe, s.snd_cr.rwe,
                (long long)(now_ns - s.snd_cr.act),
                s.snd_cr.seqno,
                s.rcv_cr.lwe, s.rcv_cr.rwe,
                (long long)(now_ns - s.rcv_cr.act),
                s.rcv_cr.seqno,
                s.stat.rxm_snd, s.stat.rxm_rcv, s.stat.rxm_fire,
                s.stat.rxm_sack, s.stat.rxm_rack, s.stat.rxm_dupthresh,
                s.stat.ack_snd, s.stat.ack_fire,
                s.stat.ack_supp_seqno, s.stat.ack_supp_inact,
                s.stat.ack_supp_rate,
                s.stat.ack_rcv, s.stat.ack_rtt, s.stat.ack_dup_rcv,
                s.stat.dup_rcv, s.stat.out_rcv, s.stat.rqo_rcv,
                s.stat.ooo_rcv,
                s.stat.sack_snd, s.stat.sack_rcv,
                s.stat.dsack_snd, s.stat.dsack_rcv, s.stat.dsack_drop,
                s.stat.nack_snd, s.stat.nack_rcv,
                s.stat.rttp_snd, s.stat.rttp_rcv, s.stat.rtt_smpl,
                s.stat.rdv_snd, s.stat.rdv_rcv,
                s.stat.ka_snd, s.stat.ka_rcv,
                s.stat.sdu_snd_frag, s.stat.frag_snd, s.stat.frag_rcv,
                s.stat.sdu_reasm, s.stat.frag_drop,
                s.stat.strm_snd_byte, s.stat.strm_rcv_byte,
                s.stat.strm_dlv_byte,
                s.stat.strm_drop, s.stat.strm_fin_drop,
                s.stat.rcv_proc_ns, s.stat.tw_move_ns,
                s.stat.drain_calls,
                s.stat.rxm_due_count,
                s.stat.rxm_due_acked, s.stat.rxm_due_unowned,
                s.stat.rxm_due_aged, s.stat.rxm_arm_fail,
                s.stat.rxm_cancel);

        if (written < 0)
                return 0;

        if ((size_t) written >= len)
                return (int) (len - 1);

        return written;
}

__attribute__((cold))
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

__attribute__((cold))
static int frct_rib_getattr(const char *      path,
                            struct rib_attr * attr)
{
        (void) path;

        /* Must be >= the sprintf output in frct_rib_read. */
        attr->size  = 4096;
        attr->mtime = 0;

        return 0;
}


static struct rib_ops r_ops = {
        .read    = frct_rib_read,
        .readdir = frct_rib_readdir,
        .getattr = frct_rib_getattr
};

#endif /* PROC_FLOW_STATS */

static __inline__ bool before(uint32_t s1, uint32_t s2)
{
        return (int32_t)(s1 - s2) < 0;
}

static __inline__ bool after(uint32_t s1, uint32_t s2)
{
        return (int32_t)(s2 - s1) < 0;
}

static __inline__ bool within(uint32_t seq, uint32_t lo, uint32_t hi)
{
        return after(seq, lo) && !after(seq, hi);
}

/*
 * RACK reorder window R (RFC 8985 §6.2):
 *   R = MIN(reo_wnd_mult * RACK.min_RTT / 4, SRTT)
 * reo_wnd_mult scales on D-SACK evidence of under-tolerance (§7.2).
 * Fall back to srtt when no min_rtt sample exists yet; MIN_REORDER_NS
 * floor guards collapse below the timer-tick resolution.
 */
static __inline__ uint64_t rack_reorder_window(struct frcti * frcti)
{
        uint64_t mult = frcti->reo_wnd_mult > 0 ? frcti->reo_wnd_mult : 1;
        uint64_t base = frcti->min_rtt > 0 ? (uint64_t) frcti->min_rtt
                                           : (uint64_t) frcti->srtt;
        uint64_t R    = mult * (base / 4);

        R = MAX(R, (uint64_t) MIN_REORDER_NS);
        R = MIN(R, (uint64_t) frcti->srtt);

        return R;
}

static __inline__ int frct_spb_reserve(size_t                len,
                                       struct ssm_pk_buff ** spb)
{
        ssize_t idx = ssm_pool_alloc_b(proc.pool, len, NULL, spb, NULL);

        return idx < 0 ? (int) idx : 0;
}

static __inline__ void frct_spb_release(struct ssm_pk_buff * spb)
{
        ssm_pool_remove(proc.pool, ssm_pk_buff_get_off(spb));
}

static __inline__ void frct_spb_release_idx(size_t idx)
{
        ssm_pool_remove(proc.pool, idx);
}

/* Fetch the spb stashed at the rq slot for seqno. */
static __inline__ struct ssm_pk_buff * rq_frag(const struct frcti * frcti,
                                               uint32_t             seqno)
{
        return ssm_pool_get(proc.pool, frcti->rcv_slots[RQ_SLOT(seqno)].idx);
}

static __inline__ size_t frcti_data_hdr_len(const struct frcti * frcti)
{
        return FRCT_PCILEN + (frcti->stream ? FRCT_PCI_STREAM_LEN : 0);
}

static __inline__ size_t frcti_ctrl_hdr_len(const struct frcti * frcti)
{
        (void) frcti;

        return FRCT_PCILEN;
}

/*
 * HCS at offset 2 inside PCI. Covers flags (bytes 0..1) and
 * window/seqno/ackno (bytes 4..15), plus SPCI for stream DATA.
 */
static void frct_hcs_set(struct frct_pci * pci,
                         bool              stream)
{
        uint16_t hcs  = 0;
        size_t   tail;

        tail = sizeof(*pci) - sizeof(pci->flags) - sizeof(pci->hcs);
        if (stream)
                tail += FRCT_PCI_STREAM_LEN;

        crc16_ccitt_false(&hcs, pci, sizeof(pci->flags));
        crc16_ccitt_false(&hcs, &pci->window, tail);

        pci->hcs = hton16(hcs);
}

static int frct_hcs_check(const struct frct_pci * pci,
                          const struct frcti *    frcti)
{
        uint16_t hcs = 0;
        uint16_t flags;
        size_t   tail;

        /* Untrusted flag read; mismatch on HCS will drop on corrupt. */
        flags = ntoh16(pci->flags);

        tail = sizeof(*pci) - sizeof(pci->flags) - sizeof(pci->hcs);
        if (frcti->stream && (flags & FRCT_DATA))
                tail += FRCT_PCI_STREAM_LEN;

        crc16_ccitt_false(&hcs, pci, sizeof(pci->flags));
        crc16_ccitt_false(&hcs, &pci->window, tail);

        return hcs != ntoh16(pci->hcs);
}

static int frct_tx(struct frcti * frcti, struct ssm_pk_buff * spb)
{
        struct flow *           f = frcti_to_flow(frcti);
        const struct frct_pci * pci;
        uint16_t                flags;
        ssize_t                 idx;
        int                     ret;

        pci   = (const struct frct_pci *) ssm_pk_buff_head(spb);
        flags = ntoh16(pci->flags);

        /* CRC32 covers plaintext body; PCI is in HCS. Pre-encrypt. */
        if (flags & FRCT_SACK) {
                if (crc_add(spb, frcti_ctrl_hdr_len(frcti)) != 0)
                        goto fail;
        } else if ((flags & FRCT_DATA) && f->info.qs.ber == 0) {
                if (crc_add(spb, frcti_data_hdr_len(frcti)) != 0)
                        goto fail;
        }

        if (spb_encrypt(f, spb) < 0)
                goto fail;

        idx = ssm_pk_buff_get_off(spb);

        ret = ssm_rbuff_write_b(f->tx_rb, idx, NULL);
        if (ret < 0)
                goto fail;

        ssm_flow_set_notify(f->set, f->info.id, FLOW_PKT);

        return 0;

 fail:
        ssm_pool_remove(proc.pool, ssm_pk_buff_get_off(spb));
        return -ENOMEM;
}

__attribute__((cold))
static void frct_mark_flow_down(struct frcti * frcti)
{
        struct flow * f = frcti_to_flow(frcti);

        if (f->rx_rb != NULL)
                ssm_rbuff_set_acl(f->rx_rb, ACL_FLOWDOWN);

        if (f->tx_rb != NULL)
                ssm_rbuff_set_acl(f->tx_rb, ACL_FLOWDOWN);
}

__attribute__((cold))
static void frct_mark_peer_dead(struct frcti * frcti)
{
        struct flow * f = frcti_to_flow(frcti);

        if (f->rx_rb != NULL)
                ssm_rbuff_set_acl(f->rx_rb, ACL_FLOWPEER);

        if (proc.fqset != NULL)
                ssm_flow_set_notify(proc.fqset, f->info.id, FLOW_PEER);
}

static __inline__ int frct_ctrl_alloc(struct ssm_pk_buff ** spb,
                                      struct frct_pci **    pci,
                                      size_t                payload_len)
{
        if (frct_spb_reserve(FRCT_PCILEN + payload_len, spb) < 0)
                return -1;

        *pci = (struct frct_pci *) ssm_pk_buff_head(*spb);
        memset(*pci, 0, FRCT_PCILEN);

        return 0;
}

/*
 * Advertised rwe. Stream mode clamps to lwe + ring_seq_cap so the
 * byte-equivalent fits the rx ring. Caller holds at least the rdlock.
 */
static __inline__ uint32_t frcti_advert_rwe(struct frcti * frcti)
{
        uint32_t rwe;
        uint32_t cap;

        rwe = frcti->rcv_cr.rwe;

        if (!frcti->stream)
                return rwe;

        cap = frcti->rcv_cr.lwe + frcti->ring_seq_cap;

        return before(cap, rwe) ? cap : rwe;
}

static void frcti_pkt_snd(struct frcti * frcti,
                          uint16_t       flags,
                          uint32_t       ackno,
                          uint32_t       rwe)
{
        struct ssm_pk_buff * spb;
        struct frct_pci *    pci;

        if (frct_ctrl_alloc(&spb, &pci, 0) < 0)
                return;

        pci->flags  = hton16(flags);
        pci->window = hton32(rwe);
        pci->ackno  = hton32(ackno);
        if (flags & FRCT_ACK) {
                /* reuse ackno for the sequence number of delayed ACK */
                ackno = FETCH_ADD_RELAXED(&frcti->snd_cr.ackno, 1);
                pci->seqno = hton32(ackno + 1);
        }

        frct_hcs_set(pci, false);

        frct_tx(frcti, spb);
}

/* RTO floor scales with srtt; hard floor rto_min guards sub-ms RTT. */
static void rtt_init(struct frcti * frcti,
                     time_t         rtt_hint)
{
        time_t floor;

        if (rtt_hint > 0) {
                rtt_hint = MAX(rtt_hint, (time_t) RTT_BOOT_NS);
                frcti->srtt = rtt_hint;
                frcti->mdev = rtt_hint >> 3;
                floor = MAX(frcti->rto_min, 2 * frcti->srtt);
                frcti->rto = MAX(floor, rtt_hint + (frcti->mdev << MDEV_MUL));
                frcti->min_rtt = rtt_hint;
        } else {
                /* Boot from first ACK. */
                frcti->srtt = 0;
                frcti->mdev = RTT_BOOT_NS;
                frcti->rto = MAX((time_t) INITIAL_RTO, frcti->rto_min);
                frcti->min_rtt = 0;
        }

        frcti->rto_mul = 0;
}

/* RFC 8985 §6.2: replace min_RTT on unset, smaller sample, or expiry. */
static __inline__ bool min_rtt_stale(struct frcti * frcti,
                                     time_t         mrtt,
                                     uint64_t       now_ns)
{
        if (frcti->min_rtt == 0)
                return true;

        if (mrtt < frcti->min_rtt)
                return true;

        return (now_ns - frcti->t_min_rtt) > MIN_RTT_WIN_NS;
}

/* Linux-style windowed-min refresh of RACK.min_RTT. */
static __inline__ void min_rtt_update(struct frcti * frcti,
                                      time_t         mrtt,
                                      uint64_t       now_ns)
{
        if (!min_rtt_stale(frcti, mrtt, now_ns))
                return;

        frcti->min_rtt   = mrtt;
        frcti->t_min_rtt = now_ns;
}

static void rtt_update(struct frcti * frcti,
                       time_t         mrtt,
                       uint64_t       now_ns)
{
        time_t srtt     = frcti->srtt;
        time_t rttvar   = frcti->mdev;
        time_t floor;
        time_t rto;

        if (srtt == 0) {
                srtt   = mrtt;
                rttvar = mrtt >> 1;
        } else {
                /* RFC 6298 symmetric EWMA. */
                time_t delta = mrtt - srtt;
                srtt += (delta >> 3);
                delta = (ABS(delta) - rttvar) >> 2;
#ifdef FRCT_LINUX_RTT_ESTIMATOR
                if (delta < 0)
                        delta >>= 3;
#endif
                rttvar += delta;
        }
        STAT_BUMP(frcti, rtt_smpl);
        frcti->srtt = MAX(SRTT_FLOOR_NS, srtt);
        frcti->mdev = MAX(MDEV_FLOOR_NS, rttvar);

        min_rtt_update(frcti, mrtt, now_ns);

        floor = MAX(frcti->rto_min, 2 * frcti->srtt);
        rto   = MAX(floor, frcti->srtt + (frcti->mdev << MDEV_MUL));

        STORE_RELEASE(&frcti->rto, rto);
        STORE_RELEASE(&frcti->rto_mul, 0);
}

/* Fill probes[pos], return new probe_id; 0 on entropy failure. Wrlock. */
static uint32_t rttp_alloc_probe(struct frcti * frcti,
                                 uint64_t       now_ns,
                                 uint8_t        nonce[RTTP_NONCE_LEN])
{
        uint32_t probe_id;
        size_t   pos;

        if (random_buffer(nonce, RTTP_NONCE_LEN) < 0)
                return 0;

        probe_id = frcti->probe_id_next++;
        if (probe_id == 0)
                probe_id = frcti->probe_id_next++;

        pos = RTTP_POS(probe_id);
        frcti->probes[pos].id = probe_id;
        frcti->probes[pos].ts = now_ns;
        memcpy(frcti->probes[pos].nonce, nonce, RTTP_NONCE_LEN);
        frcti->t_snd_probe = now_ns;

        STAT_BUMP(frcti, rttp_snd);

        return probe_id;
}

/* Caller wrlock; out args valid on true (caller emits post-unlock). */
static bool rtt_probe_arm(struct frcti * frcti,
                          uint64_t       now_ns,
                          uint32_t *     probe_id,
                          uint8_t        nonce[RTTP_NONCE_LEN])
{
        if (frcti->srtt == 0)
                return false;

        if (!after(frcti->snd_cr.seqno, frcti->snd_cr.lwe))
                return false;

        if (now_ns - frcti->t_rcv_rtt <= 2u * (uint64_t) frcti->srtt)
                return false;

        if (now_ns - frcti->t_snd_probe <= (uint64_t) frcti->srtt)
                return false;

        *probe_id = rttp_alloc_probe(frcti, now_ns, nonce);

        return *probe_id != 0;
}

static void frcti_rttp_snd(struct frcti *  frcti,
                           uint32_t        probe_id,
                           uint32_t        echo_id,
                           const uint8_t * nonce)
{
        struct ssm_pk_buff * spb;
        struct frct_pci *    pci;
        struct frct_rttp *   rttp;

        if (frct_ctrl_alloc(&spb, &pci, RTTP_PAYLOAD) < 0)
                return;

        pci->flags = hton16(FRCT_RTTP);

        frct_hcs_set(pci, false);

        rttp = (struct frct_rttp *) FRCT_BODY(pci);
        rttp->probe_id = hton32(probe_id);
        rttp->echo_id  = hton32(echo_id);
        memcpy(rttp->nonce, nonce, sizeof(rttp->nonce));

        frct_tx(frcti, spb);
}

struct rxm_entry {
        struct tw_entry  tw;
        struct list_head next;       /* in frcti->rxm_list */
        struct frcti *   frcti;
        uint32_t         seqno;
        uint64_t         t0;
        size_t           len;
        uint8_t          pkt[];      /* flexible — sized at alloc time */
};

static struct rxm_entry * rxm_entry_create(struct frcti *             frcti,
                                           uint32_t                   seqno,
                                           const struct ssm_pk_buff * spb)
{
        struct rxm_entry * r;
        struct timespec    now;
        size_t             len = ssm_pk_buff_len(spb);

        r = malloc(sizeof(*r) + len);
        if (r == NULL) {
                STAT_BUMP(frcti, rxm_arm_fail);
                return NULL;
        }

        memcpy(r->pkt, ssm_pk_buff_head(spb), len);
        r->len   = len;
        r->frcti = frcti;
        r->seqno = seqno;

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        r->t0 = TS_TO_UINT64(now);

        tw_init_entry(&r->tw);

        return r;
}

static void rxm_entry_destroy(struct rxm_entry * r)
{
        free(r);
}

static bool rxm_still_owned(struct frcti *     frcti,
                            size_t             pos,
                            struct rxm_entry * r)
{
        return LOAD_ACQUIRE(&frcti->snd_slots[pos].rxm) == r;
}

/*
 * All in-flight slots share the HoL backoff; otherwise non-HoL timers
 * cycle at base RTO and storm the wire while HoL is still backing off.
 */
static uint64_t rxm_next_deadline(struct frcti * frcti,
                                  uint64_t       now_ns)
{
        time_t  rto     = LOAD_RELAXED(&frcti->rto);
        uint8_t rto_mul = LOAD_RELAXED(&frcti->rto_mul);

        return now_ns + ((uint64_t) rto << rto_mul);
}

/* Copy pkt, set FRCT_RXM, refresh ackno, re-seal HCS. */
static struct ssm_pk_buff * rxm_pkt_prepare(const void * pkt,
                                            size_t       len,
                                            uint32_t     rcv_lwe,
                                            bool         stream)
{
        struct ssm_pk_buff * spb;
        struct frct_pci *    pci;
        uint16_t             flags;

        if (frct_spb_reserve(len, &spb) < 0)
                return NULL;

        pci = (struct frct_pci *) ssm_pk_buff_head(spb);
        memcpy(pci, pkt, len);

        flags      = ntoh16(pci->flags) | FRCT_RXM;
        pci->flags = hton16(flags);
        pci->ackno = hton32(rcv_lwe);

        frct_hcs_set(pci, stream);

        return spb;
}

/* Caller must NOT hold frcti->lock. */
static void rxm_snd(struct frcti * frcti,
                    uint32_t       seqno,
                    const void *   pkt,
                    size_t         len)
{
        struct ssm_pk_buff * spb;
        struct timespec      now;
        struct snd_slot *    slot;
        uint32_t             snd_lwe;
        uint32_t             rcv_lwe;
        size_t               pos;

        snd_lwe = LOAD_RELAXED(&frcti->snd_cr.lwe);
        rcv_lwe = LOAD_RELAXED(&frcti->rcv_cr.lwe);

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_wrlock(&frcti->lock);

        pos  = RQ_SLOT(seqno);
        slot = &frcti->snd_slots[pos];

        slot->time  = TS_TO_UINT64(now);
        /* RTO clears fast-rtx gate: a fresh loss event for SACK/RACK. */
        slot->flags = (slot->flags & ~SND_FAST_RXM) | SND_RTX;

        frcti->rtt_lwe = seqno + 1;

        /* Only the HoL retransmit bumps the global RTO backoff. */
        if (seqno == snd_lwe && frcti->rto_mul < MAX_RTO_MUL)
                STORE_RELEASE(&frcti->rto_mul, frcti->rto_mul + 1);

        /* RFC 8985 §7.2 step 4: RTO on HoL resets RACK reo scaling. */
        if (seqno == snd_lwe)
                frcti->reo_wnd_mult = 1;

        pthread_rwlock_unlock(&frcti->lock);

        STAT_BUMP(frcti, rxm_snd);
        STAT_BUMP(frcti, rxm_fire);

        spb = rxm_pkt_prepare(pkt, len, rcv_lwe, frcti->stream);
        if (spb == NULL)
                return;

        if (frct_tx(frcti, spb) < 0)
                frct_mark_flow_down(frcti);
}

static void rxm_due(void * arg)
{
        struct rxm_entry * r     = arg;
        struct frcti *     frcti = r->frcti;
        struct timespec    now;
        uint64_t           now_ns;
        uint32_t           snd_lwe;
        size_t             pos = RQ_SLOT(r->seqno);

        STAT_BUMP(frcti, rxm_due_count);

        snd_lwe = LOAD_RELAXED(&frcti->snd_cr.lwe);

        /* Already ACK'd: expected for the steady-state majority. */
        if (before(r->seqno, snd_lwe)) {
                STAT_BUMP(frcti, rxm_due_acked);
                goto cleanup;
        }

        /* SACK/RACK-cleared the slot (caller NULL'd snd_slots[pos].rxm). */
        if (!rxm_still_owned(frcti, pos, r)) {
                STAT_BUMP(frcti, rxm_due_unowned);
                goto cleanup;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        /* R-timer expired: peer unreachable. */
        if (RXM_AGED_OUT(r->t0, now_ns, frcti->t_r)) {
                STAT_BUMP(frcti, rxm_due_aged);
                frct_mark_flow_down(frcti);
                goto cleanup;
        }

        rxm_snd(frcti, r->seqno, r->pkt, r->len);

        /* Re-check ownership: fire path may have replaced our entry. */
        if (rxm_still_owned(frcti, pos, r)) {
                uint64_t anchor;

                /* Per-slot anchor breaks co-fire re-bin. */
                anchor = frcti->snd_slots[pos].time;
                tw_post(&r->tw, rxm_next_deadline(frcti, anchor), rxm_due, r);
                return;
        }

 cleanup:
        pthread_rwlock_wrlock(&frcti->lock);

        if (rxm_still_owned(frcti, pos, r))
                STORE_RELEASE(&frcti->snd_slots[pos].rxm, NULL);

        list_del(&r->next);

        pthread_rwlock_unlock(&frcti->lock);

        rxm_entry_destroy(r);
}

static int rxm_arm(struct frcti *             frcti,
                   uint32_t                   seqno,
                   const struct ssm_pk_buff * spb)
{
        struct rxm_entry * r;
        time_t             rto;
        uint8_t            rto_mul;
        uint64_t           deadline;

        r = rxm_entry_create(frcti, seqno, spb);
        if (r == NULL)
                return -ENOMEM;

        rto      = LOAD_RELAXED(&frcti->rto);
        rto_mul  = LOAD_RELAXED(&frcti->rto_mul);
        deadline = r->t0 + ((uint64_t) rto << rto_mul);

        pthread_rwlock_wrlock(&frcti->lock);

        list_add_tail(&r->next, &frcti->rxm_list);
        STORE_RELEASE(&frcti->snd_slots[RQ_SLOT(seqno)].rxm, r);

        pthread_rwlock_unlock(&frcti->lock);

        tw_post(&r->tw, deadline, rxm_due, r);

        return 0;
}

static void rxm_cancel_all(struct frcti * frcti)
{
        struct list_head * p;
        struct list_head * t;

        list_for_each_safe(p, t, &frcti->rxm_list) {
                struct rxm_entry * r = list_entry(p, struct rxm_entry, next);
                list_del(&r->next);
                tw_cancel(&r->tw);
                rxm_entry_destroy(r);
                STAT_BUMP(frcti, rxm_cancel);
        }
}

static __inline__ void sack_block_put(uint8_t * payload,
                                      uint16_t  i,
                                      uint32_t  s,
                                      uint32_t  e)
{
        uint32_t * blk = (uint32_t *)
                (payload + SACK_HDR_SIZE + i * SACK_BLOCK_SIZE);

        blk[0] = hton32(s);
        blk[1] = hton32(e);
}

static __inline__ void sack_block_get(const uint8_t * payload,
                                      uint16_t        i,
                                      uint32_t *      s,
                                      uint32_t *      e)
{
        const uint32_t * blk = (const uint32_t *)
                (payload + SACK_HDR_SIZE + i * SACK_BLOCK_SIZE);

        *s = ntoh32(blk[0]);
        *e = ntoh32(blk[1]);
}

/*
 * Build SACK blocks for ranges *above* rcv_cr.lwe.  Wire invariant
 * (see doc/frct.txt §1.3): every block produced here satisfies
 * blocks[i].start > rcv_cr.lwe = ackno, which makes the "first block
 * below ackno" convention used to mark a D-SACK (RFC 2883 §4 case 1)
 * unambiguous.  Caller holds frcti->lock.
 */
static uint16_t sack_blocks_build(struct frcti * frcti,
                                  uint32_t       blocks[][2],
                                  uint16_t       max_n)
{
        const struct rcv_slot * slots = frcti->rcv_slots;
        uint32_t                s;
        uint32_t                end;
        uint16_t                n = 0;

        s   = frcti->rcv_cr.lwe + 1;
        end = frcti->rcv_cr.lwe + RQ_SIZE;
        if (after(end, frcti->rcv_cr.rwe))
                end = frcti->rcv_cr.rwe;

        while (before(s, end) && n < max_n) {
                while (before(s, end) && slots[RQ_SLOT(s)].idx == -1)
                        ++s;

                if (!before(s, end))
                        break;

                blocks[n][0] = s;
                while (before(s, end) && slots[RQ_SLOT(s)].idx != -1)
                        ++s;
                blocks[n][1] = s;
                ++n;
        }

        return n;
}

/*
 * Prepend the pending D-SACK report (if any) as block[0]; clear flag.
 * Returns the number of slots consumed at the head (0 or 1).  Caller
 * holds wrlock.
 */
static __inline__ uint16_t dsack_consume(struct frcti * frcti,
                                         uint32_t       blocks[][2])
{
        if (!frcti->dsack_valid || frcti->sack_n_max == 0)
                return 0;

        blocks[0][0] = frcti->dsack_seqno;
        blocks[0][1] = frcti->dsack_seqno + 1;
        frcti->dsack_valid = false;
        return 1;
}

/* Caller must NOT hold frcti->lock. */
static void frcti_sack_snd(struct frcti *           frcti,
                           const struct sack_args * sa)
{
        struct ssm_pk_buff * spb;
        struct frct_pci *    pci;
        buffer_t             buf;
        uint16_t             i;

        assert(sa->n <= SACK_MAX_BLOCKS);

        buf.len = SACK_HDR_SIZE + sa->n * SACK_BLOCK_SIZE;

        if (frct_ctrl_alloc(&spb, &pci, buf.len) < 0)
                return;

        pci->flags  = hton16(FRCT_ACK | FRCT_FC | FRCT_SACK);
        pci->window = hton32(sa->rwe);
        pci->ackno  = hton32(sa->ack);
        pci->seqno  = hton32(FETCH_ADD_RELAXED(&frcti->snd_cr.ackno, 1) + 1);

        frct_hcs_set(pci, false);

        buf.data = FRCT_BODY(pci);
        memset(buf.data, 0, SACK_HDR_SIZE);
        *(uint16_t *) buf.data = hton16(sa->n);
        for (i = 0; i < sa->n; ++i)
                sack_block_put(buf.data, i, sa->blocks[i][0], sa->blocks[i][1]);

        frct_tx(frcti, spb);
}

static void ack_snd(struct frcti * frcti,
                    bool           with_sack)
{
        struct timespec      now;
        uint64_t             now_ns;
        time_t               diff;
        uint32_t             ackno;
        uint32_t             rwe;
        struct sack_args *   sa = NULL;
        size_t               sa_sz;
        bool                 sacking = false;

        assert(frcti);

        STAT_BUMP(frcti, ack_fire);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        if (with_sack && frcti->sack_n_max > 0) {
                sa_sz = sizeof(*sa) + frcti->sack_n_max * sizeof(sa->blocks[0]);
                sa = malloc(sa_sz);
                /* If alloc fails, fall through and send a bare cum-ACK. */
        }

        pthread_rwlock_wrlock(&frcti->lock);

        /* D-SACK rides through cum-ACK freshness; signal is the duplicate. */
        if (!after(frcti->rcv_cr.lwe, frcti->rcv_cr.seqno)
            && !frcti->dsack_valid) {
                pthread_rwlock_unlock(&frcti->lock);
                STAT_BUMP(frcti, ack_supp_seqno);
                goto out;
        }

        ackno = frcti->rcv_cr.lwe;
        rwe   = frcti_advert_rwe(frcti);

        if (ACK_AGED_OUT(frcti->rcv_cr.act, now_ns, frcti->t_a)) {
                pthread_rwlock_unlock(&frcti->lock);
                STAT_BUMP(frcti, ack_supp_inact);
                goto out;
        }

        diff = (time_t)(now_ns - frcti->snd_cr.act);
        if (diff < TICTIME && !frcti->dsack_valid) {
                pthread_rwlock_unlock(&frcti->lock);
                STAT_BUMP(frcti, ack_supp_rate);
                goto out;
        }

        /* RFC 2018: piggyback SACK on timer ACK; dedup unchanged board. */
        if (sa == NULL || (frcti->sack_n == 0 && !frcti->dsack_valid))
                goto no_sack;

        sa->dsack = false;
        sa->n     = dsack_consume(frcti, sa->blocks);
        if (sa->n == 1)
                sa->dsack = true;

        sa->n += sack_blocks_build(frcti, sa->blocks + sa->n,
                                   frcti->sack_n_max - sa->n);
        if (sa->n == 0)
                goto no_sack;

        if (!sa->dsack && ackno == frcti->sack_lwe && sa->n == frcti->sack_n)
                goto no_sack;

        sa->ack = ackno;
        sa->rwe = rwe;
        frcti->sack_lwe   = ackno;
        frcti->sack_n     = sa->n;
        frcti->t_snd_sack = now_ns;
        sacking = true;

 no_sack:
        frcti->rcv_cr.seqno = frcti->rcv_cr.lwe;

        pthread_rwlock_unlock(&frcti->lock);

        STAT_BUMP(frcti, ack_snd);

        if (sacking) {
                STAT_BUMP(frcti, sack_snd);
                if (sa->dsack)
                        STAT_BUMP(frcti, dsack_snd);
                frcti_sack_snd(frcti, sa);
        } else {
                frcti_pkt_snd(frcti, FRCT_ACK | FRCT_FC, ackno, rwe);
        }

 out:
        free(sa);
}

/* Delayed-ACK timer: per-flow, dedup'd via atomic test-and-set. */
static void ack_due(void * arg)
{
        struct frcti * frcti = arg;

        __atomic_clear(&frcti->ack_pending, __ATOMIC_RELAXED);

        ack_snd(frcti, true);
}

static int ack_arm(struct frcti * frcti)
{
        struct timespec now;
        uint64_t        deadline;

        if (__atomic_test_and_set(&frcti->ack_pending, __ATOMIC_RELAXED))
                return 0;

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        deadline = TS_TO_UINT64(now) + 2ULL * (uint64_t) TICTIME;

        tw_post(&frcti->ack_tw, deadline, ack_due, frcti);

        return 0;
}

/* Forward decl breaks the keepalive cycle: ka_arm <-> ka_due. */
static void ka_due(void * arg);

static int ka_arm(struct frcti * frcti)
{
        struct timespec now;
        uint64_t        now_ns;
        uint64_t        timeo_ns;
        uint64_t        snd_ns;
        uint64_t        rcv_ns;
        uint64_t        deadline;

        timeo_ns = (uint64_t) frcti->qs_timeout * MILLION;   /* IMM */
        snd_ns   = LOAD_RELAXED(&frcti->snd_cr.act) + timeo_ns / 4;
        rcv_ns   = LOAD_RELAXED(&frcti->rcv_cr.act) + timeo_ns;

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns   = TS_TO_UINT64(now);
        deadline = MIN(snd_ns, rcv_ns);
        if (deadline <= now_ns)
                deadline = now_ns + timeo_ns / 4;

        tw_post(&frcti->ka_tw, deadline, ka_due, frcti);

        return 0;
}

__attribute__((cold))
static void ka_snd(struct frcti * frcti)
{
        struct ssm_pk_buff * spb;
        struct frct_pci *    pci;
        struct timespec      now;
        uint64_t             now_ns;
        time_t               timeo_ns;
        uint64_t             rcv_act;
        uint64_t             ka_rcv;
        int64_t              rcv_idle;
        int64_t              snd_idle;
        uint32_t             ackno;

        assert(frcti);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        timeo_ns = (time_t)(frcti->qs_timeout) * MILLION;     /* IMM */
        rcv_act  = LOAD_RELAXED(&frcti->rcv_cr.act);
        ka_rcv   = LOAD_RELAXED(&frcti->t_ka_rcv);
        rcv_idle = (int64_t)(now_ns - (rcv_act > ka_rcv ? rcv_act : ka_rcv));
        snd_idle = (int64_t)(now_ns - LOAD_RELAXED(&frcti->snd_cr.act));

        if (rcv_idle > timeo_ns) {
                frct_mark_peer_dead(frcti);
                return;
        }

        if (snd_idle <= timeo_ns / 4) {
                ka_arm(frcti);
                return;
        }

        if (frct_ctrl_alloc(&spb, &pci, 0) < 0) {
                ka_arm(frcti);
                return;
        }

        ackno = LOAD_RELAXED(&frcti->rcv_cr.lwe);

        pci->flags = hton16(FRCT_KA | FRCT_ACK);
        pci->ackno = hton32(ackno);

        frct_hcs_set(pci, false);

        STAT_BUMP(frcti, ka_snd);
        frct_tx(frcti, spb);

        ka_arm(frcti);
}

/* Keepalive timer: re-posted by the fire callback itself. */
static void ka_due(void * arg)
{
        ka_snd((struct frcti *) arg);
}

static void frcti_rdv_snd(struct frcti * frcti)
{
        frcti_pkt_snd(frcti, FRCT_RDVS, 0, 0);
}

#define HAS_RESCNTL(cr) ((cr)->cflags & FRCTFRESCNTL)
static bool frcti_is_window_open(struct frcti * frcti)
{
        struct frct_cr * snd_cr = &frcti->snd_cr;
        struct timespec  now;
        time_t           diff;
        bool             ret    = false;

        if (!HAS_RESCNTL(snd_cr))
                return true;

        if (before(snd_cr->seqno, LOAD_RELAXED(&snd_cr->rwe)))
                return true;

        /* Window may be closed; wrlock for RDV state mutations. */
        pthread_rwlock_wrlock(&frcti->lock);

        if (before(snd_cr->seqno, snd_cr->rwe)) {
                ret = true;
                goto unlock;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        if (frcti->open) {
                frcti->open   = false;
                frcti->t_wnd  = now;
                frcti->t_last_rdv = now;
                goto unlock;
        }

        diff = ts_diff_ns(&now, &frcti->t_wnd);
        if (diff > MAX_RDV)
                goto unlock;

        diff = ts_diff_ns(&now, &frcti->t_last_rdv);
        if (diff > (time_t) frcti->t_rdv) {
                frcti->t_last_rdv = now;
                frcti_rdv_snd(frcti);
                STAT_BUMP(frcti, rdv_snd);
        }
 unlock:
        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

/* n contiguous seqnos free? No RDV: the n=1 path drives it. */
static bool frcti_is_window_open_n(struct frcti * frcti,
                                   size_t         n)
{
        struct frct_cr * snd_cr = &frcti->snd_cr;

        if (!HAS_RESCNTL(snd_cr))
                return true;

        if (n <= 1)
                return frcti_is_window_open(frcti);

        return before(snd_cr->seqno + (uint32_t)(n - 1),
                      LOAD_RELAXED(&snd_cr->rwe));
}

static void release_rq(struct frcti * frcti)
{
        size_t i;

        for (i = 0; i < RQ_SIZE; ++i) {
                if (frcti->rcv_slots[i].idx == -1)
                        continue;

                /* Stream rq entries are sentinels (no spb owned). */
                if (!frcti->stream)
                        frct_spb_release_idx(frcti->rcv_slots[i].idx);

                frcti->rcv_slots[i].idx = -1;
        }
}

static __inline__ bool stream_ring_sz_ok(struct frcti * frcti,
                                         size_t         n)
{
        size_t per_pkt;

        if (n > FRCT_STREAM_RING_SZ_MAX)
                return false;

        if ((n & (n - 1)) != 0)
                return false;

        per_pkt = frcti->frag_mtu - frcti_data_hdr_len(frcti);

        return n >= FRCT_STREAM_RING_MIN_PKTS * per_pkt;
}

/* Default ring sized for full RQ_SIZE seqno window; pow2, capped. */
static size_t default_stream_ring_sz(size_t per_pkt)
{
        size_t need;
        size_t sz;

        need = (size_t) RQ_SIZE * per_pkt;
        sz   = FRCT_STREAM_RING_SZ;

        while (sz < need && sz < FRCT_STREAM_RING_SZ_MAX)
                sz <<= 1;

        return sz;
}

struct frcti * frcti_create(int       fd,
                            uint64_t  a,
                            uint64_t  r,
                            uint64_t  mpl,
                            time_t    rtt_hint,
                            qosspec_t qs,
                            uint32_t  mtu)
{
        struct frcti *  frcti;
        ssize_t         idx;
        struct timespec now;
        uint64_t        now_ns;
        size_t          bb;
        size_t          per_pkt;
#ifdef PROC_FLOW_STATS
        char            frctstr[FRCT_NAME_STRLEN + 1];
#endif
        mpl *= MILLION;  /* ms -> ns */
        a   *= MILLION;  /* ms -> ns */
        r   *= MILLION;  /* ms -> ns */

        frcti = malloc(sizeof(*frcti));
        if (frcti == NULL)
                goto fail_malloc;

        memset(frcti, 0, sizeof(*frcti));

        list_head_init(&frcti->rxm_list);

        if (pthread_rwlock_init(&frcti->lock, NULL))
                goto fail_lock;

#ifdef PROC_FLOW_STATS
        sprintf(frctstr, "%d", fd);
        if (rib_reg(frctstr, &r_ops))
                goto fail_rib_reg;
#endif

        for (idx = 0; idx < RQ_SIZE; ++idx)
                frcti->rcv_slots[idx].idx = -1;

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        frcti->t_mpl         = mpl;
        frcti->t_a           = a;
        frcti->t_r           = r;
        frcti->t_rdv         = DELT_RDV;
        frcti->fd            = fd;
        frcti->ber           = (time_t) qs.ber;
        frcti->lossy         = (qs.loss != 0);
        frcti->qs_timeout    = (time_t) qs.timeout;

        frcti->frag_mtu = (size_t) mtu;

        /* Cap blocks per SACK at what fits in the per-flow frag_mtu. */
        bb = (frcti->frag_mtu - FRCT_PCILEN - SACK_HDR_SIZE)
             / SACK_BLOCK_SIZE;
        if (bb > SACK_MAX_BLOCKS)
                bb = SACK_MAX_BLOCKS;
        frcti->sack_n_max = (uint16_t) bb;

        frcti->max_rcv_sdu = FRCT_MAX_SDU;

        frcti->stream = (qs.service == SVC_STREAM);
        if (frcti->stream) {
                per_pkt = frcti->frag_mtu - frcti_data_hdr_len(frcti);
                frcti->rcv_ring_sz = default_stream_ring_sz(per_pkt);
                frcti->ring_seq_cap =
                        (uint32_t) (frcti->rcv_ring_sz / per_pkt);
        }

        frcti->rto_min = (time_t) MAX(RTO_MIN, 1ULL << RXMQ_RES);
        rtt_init(frcti, rtt_hint);
        frcti->t_min_rtt      = now_ns;
        frcti->probe_id_next  = 1;
        frcti->t_rcv_rtt      = now_ns;
        frcti->t_snd_probe    = now_ns;
        frcti->t_snd_sack     = 0;
        frcti->sack_lwe       = 0;
        frcti->sack_n         = 0;
        frcti->dsack_seqno    = 0;
        frcti->dsack_valid    = false;
        frcti->reo_wnd_mult   = 1;
        frcti->dsack_lwe_snap = 0;
        /* So the first pre-DRF NACK fires without waiting cooldown. */
        frcti->t_nack         = now_ns - BILLION;
        frcti->in_recovery    = false;
        frcti->recovery_high  = 0;
        frcti->rack_fired_lwe = 0;

        tw_init_entry(&frcti->ack_tw);
        tw_init_entry(&frcti->ka_tw);

        if (!frcti->lossy) {
                frcti->snd_cr.cflags |= FRCTFRTX | FRCTFLINGER;
                frcti->rcv_cr.cflags |= FRCTFRTX;
        }

        frcti->snd_cr.cflags |= FRCTFRESCNTL;

        frcti->snd_cr.rwe = START_WINDOW;
        if (frcti->lossy)
                frcti->snd_cr.rwe = RQ_SIZE;

        frcti->snd_cr.inact = 3 * mpl + a + r + BILLION;       /* ns */
        frcti->snd_cr.act   = now_ns - frcti->snd_cr.inact - BILLION;

        frcti->rcv_cr.inact = 2 * mpl + a + r + BILLION;       /* ns */
        frcti->rcv_cr.act   = now_ns - frcti->rcv_cr.inact - BILLION;

        frcti->t_ka_rcv = now_ns;

        /* qs_timeout == 0: no KA, silent peer crash goes undetected. */
        if (frcti->qs_timeout > 0) {
                if (ka_arm(frcti) < 0)
                        goto fail_ka_arm;
        }

        return frcti;

 fail_ka_arm:
#ifdef PROC_FLOW_STATS
        sprintf(frctstr, "%d", fd);
        rib_unreg(frctstr);
 fail_rib_reg:
#endif
        pthread_rwlock_destroy(&frcti->lock);
 fail_lock:
        free(frcti);
 fail_malloc:
        return NULL;
}

void frcti_destroy(struct frcti * frcti)
{
#ifdef PROC_FLOW_STATS
        char frctstr[FRCT_NAME_STRLEN + 1];
#endif
        /* Drop every wheel entry referencing frcti before freeing it. */
        rxm_cancel_all(frcti);
        tw_cancel(&frcti->ack_tw);
        tw_cancel(&frcti->ka_tw);

#if defined(PROC_FLOW_STATS) && defined(FRCT_DEBUG_STDOUT)
        printf("[FRCT teardown] pid=%d fd=%d "
               "frag_snd=%zu rxm_sack=%zu rxm_dup=%zu rxm_snd=%zu "
               "rxm_due=%zu acked=%zu unowned=%zu aged=%zu "
               "cancel=%zu arm_fail=%zu inflight=%u\n",
               (int) getpid(), frcti->fd,
               frcti->stat.frag_snd, frcti->stat.rxm_sack,
               frcti->stat.rxm_dupthresh,
               frcti->stat.rxm_snd,
               frcti->stat.rxm_due_count, frcti->stat.rxm_due_acked,
               frcti->stat.rxm_due_unowned, frcti->stat.rxm_due_aged,
               frcti->stat.rxm_cancel, frcti->stat.rxm_arm_fail,
               frcti->snd_cr.seqno - frcti->snd_cr.lwe);
#endif

        release_rq(frcti);
        free(frcti->rcv_ring);
#ifdef PROC_FLOW_STATS
        sprintf(frctstr, "%d", frcti->fd);
        rib_unreg(frctstr);
#endif
        pthread_rwlock_destroy(&frcti->lock);

        free(frcti);
}

uint16_t frcti_getflags(struct frcti * frcti)
{
        uint16_t ret;

        assert(frcti);

        pthread_rwlock_rdlock(&frcti->lock);

        ret = frcti->snd_cr.cflags & FRCTFMASK;

        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

void frcti_setflags(struct frcti * frcti,
                    uint16_t       flags)
{
        assert(frcti);

        flags &= FRCTFSETMASK;

        pthread_rwlock_wrlock(&frcti->lock);

        frcti->snd_cr.cflags = (frcti->snd_cr.cflags & ~FRCTFSETMASK) | flags;

        pthread_rwlock_unlock(&frcti->lock);
}

size_t frcti_get_max_rcv_sdu(struct frcti * frcti)
{
        size_t ret;

        assert(frcti);

        pthread_rwlock_rdlock(&frcti->lock);
        ret = frcti->max_rcv_sdu;
        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

int frcti_set_max_rcv_sdu(struct frcti * frcti,
                          size_t         max)
{
        assert(frcti);

        if (max == 0)
                return -EINVAL;

        pthread_rwlock_wrlock(&frcti->lock);
        frcti->max_rcv_sdu = max;
        pthread_rwlock_unlock(&frcti->lock);

        return 0;
}

size_t frcti_get_rcv_ring_sz(struct frcti * frcti)
{
        size_t ret;

        assert(frcti);

        pthread_rwlock_rdlock(&frcti->lock);
        ret = frcti->rcv_ring_sz;
        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

/* Set before any stream byte has been delivered; -EBUSY otherwise. */
int frcti_set_rcv_ring_sz(struct frcti * frcti,
                          size_t         n)
{
        int    ret = 0;
        size_t per_pkt;

        assert(frcti);

        if (!frcti->stream)
                return -ENOTSUP;
        if (!stream_ring_sz_ok(frcti, n))
                return -EINVAL;

        per_pkt = frcti->frag_mtu - frcti_data_hdr_len(frcti);

        pthread_rwlock_wrlock(&frcti->lock);

        if (frcti->rcv_ring != NULL) {
                ret = -EBUSY;
        } else {
                frcti->rcv_ring_sz  = n;
                frcti->ring_seq_cap = (uint32_t) (n / per_pkt);
        }

        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

time_t frcti_get_rto_min(struct frcti * frcti)
{
        time_t v;

        assert(frcti);

        pthread_rwlock_rdlock(&frcti->lock);
        v = frcti->rto_min;
        pthread_rwlock_unlock(&frcti->lock);

        return v;
}

/* Floor at the timer-wheel resolution; finer granularity is unrepresentable. */
int frcti_set_rto_min(struct frcti * frcti,
                      time_t         rto_min)
{
        time_t floor = (time_t) (1ULL << RXMQ_RES);
        time_t rto_floor;
        time_t rto;

        assert(frcti);

        if (rto_min < floor)
                return -EINVAL;

        pthread_rwlock_wrlock(&frcti->lock);

        frcti->rto_min = rto_min;
        if (frcti->srtt > 0) {
                rto_floor = MAX(rto_min, 2 * frcti->srtt);
                rto       = MAX(rto_floor,
                                frcti->srtt + (frcti->mdev << MDEV_MUL));
                STORE_RELEASE(&frcti->rto, rto);
        } else if (frcti->rto < rto_min) {
                STORE_RELEASE(&frcti->rto, rto_min);
        }

        pthread_rwlock_unlock(&frcti->lock);

        return 0;
}

/* Re-arm a fresh rxm so a lost fast-retx still recovers via RTO. */
static void sack_rxm_snd(struct frcti * frcti,
                         void *         pkt,
                         size_t         len)
{
        struct ssm_pk_buff *    spb;
        const struct frct_pci * pci;
        uint32_t                rcv_lwe;
        uint32_t                seqno;

        rcv_lwe = LOAD_RELAXED(&frcti->rcv_cr.lwe);

        spb = rxm_pkt_prepare(pkt, len, rcv_lwe, frcti->stream);
        if (spb == NULL)
                return;

        pci   = (const struct frct_pci *) ssm_pk_buff_head(spb);
        seqno = ntoh32(pci->seqno);

        /* Register fresh rxm before send; old entry self-cleans. */
        if (rxm_arm(frcti, seqno, spb) < 0) {
                frct_spb_release(spb);
                return;
        }

        STAT_BUMP(frcti, rxm_sack);
        frct_tx(frcti, spb);
}

/* Additive HoL emit; original snd_slots[hp].rxm stays armed (NewReno). */
static void fast_rxm_send(struct frcti * frcti,
                        void *         pkt,
                        size_t         len)
{
        struct ssm_pk_buff * spb;
        uint32_t             rcv_lwe;

        rcv_lwe = LOAD_RELAXED(&frcti->rcv_cr.lwe);

        spb = rxm_pkt_prepare(pkt, len, rcv_lwe, frcti->stream);
        if (spb == NULL)
                return;

        frct_tx(frcti, spb);
}

/* PCI bytes survive head_release at receive; just rewind the pointer. */
static __inline__ uint16_t frag_role_peek(struct ssm_pk_buff * spb)
{
        const struct frct_pci * pci;

        assert(ssm_pk_buff_head(spb) != NULL);

        pci = (const struct frct_pci *) (ssm_pk_buff_head(spb) - FRCT_PCILEN);

        return ntoh16(pci->flags) & FRCT_FR_MASK;
}

enum frag_state {
        FRAG_NOT_READY,   /* head missing / FIRST..LAST run incomplete */
        FRAG_DELIVER,     /* *count fragments form a deliverable SDU   */
        FRAG_DROP,        /* *count fragments at lwe are malformed     */
};

/*
 * On a gap in the run: FRTX waits (NOT_READY); best-effort scans forward
 * for the next FIRST/SOLE and returns DROP for the broken prefix. *count
 * gets the offset from the trailing edge. NOT_READY if no later run is
 * in window. Caller rdlock.
 */
static enum frag_state frag_inspect_gap(struct frcti * frcti,
                                        size_t         start,
                                        size_t *       count)
{
        const struct rcv_slot * slots = frcti->rcv_slots;
        struct ssm_pk_buff *    spb;
        uint32_t                k;
        uint16_t                role;
        size_t                  m;

        if (frcti->rcv_cr.cflags & FRCTFRTX)
                return FRAG_NOT_READY;

        k = frcti->rcv_cr.rwe - RQ_SIZE;

        for (m = start; m < RQ_SIZE; ++m) {
                if (slots[RQ_SLOT(k + m)].idx == -1)
                        continue;

                spb  = rq_frag(frcti, k + m);
                role = frag_role_peek(spb);

                if (role == FRCT_FR_SOLE || role == FRCT_FR_FIRST) {
                        if (m == 0)
                                return FRAG_NOT_READY;

                        *count = m;
                        return FRAG_DROP;
                }
        }

        return FRAG_NOT_READY;
}

/*
 * Inspect rq[lwe..]; set *count and return DELIVER/DROP/NOT_READY. DROP
 * covers broken prefixes (mid/last at HoL, FIRST..[non-LAST]..new-FIRST).
 * Non-FRTX flows skip past gaps to the next FIRST/SOLE. Caller rdlock.
 */
static enum frag_state frag_run_inspect(struct frcti * frcti,
                                        size_t *       count)
{
        const struct rcv_slot * slots = frcti->rcv_slots;
        struct ssm_pk_buff *    spb;
        uint32_t                k     = frcti->rcv_cr.rwe - RQ_SIZE;
        uint16_t                role;
        size_t                  n     = 0;

        if (slots[RQ_SLOT(k)].idx == -1)
                return frag_inspect_gap(frcti, 0, count);

        spb  = rq_frag(frcti, k);
        role = frag_role_peek(spb);

        if (role == FRCT_FR_SOLE) {
                *count = 1;
                return FRAG_DELIVER;
        }

        if (role != FRCT_FR_FIRST) {
                *count = 1;
                return FRAG_DROP;
        }

        while (true) {
                if (n == RQ_SIZE || slots[RQ_SLOT(k + n)].idx == -1)
                        return frag_inspect_gap(frcti, n, count);

                spb  = rq_frag(frcti, k + n);
                role = frag_role_peek(spb);
                ++n;

                if (role == FRCT_FR_LAST) {
                        *count = n;
                        return FRAG_DELIVER;
                }

                if (n > 1 && role != FRCT_FR_MID) {
                        /* SOLE or new FIRST mid-run: drop the prefix. */
                        *count = n - 1;
                        return FRAG_DROP;
                }
        }
}

/* Caller wrlock. Delivery edge is implicit: rwe - RQ_SIZE. */
static void frag_drop(struct frcti * frcti,
                      size_t         count)
{
        uint32_t k    = frcti->rcv_cr.rwe - RQ_SIZE;
        uint32_t edge;
        size_t   i;

        for (i = 0; i < count; ++i) {
                size_t pos = RQ_SLOT(k + i);

                if (frcti->rcv_slots[pos].idx == -1)
                        continue;

                frct_spb_release_idx(frcti->rcv_slots[pos].idx);
                frcti->rcv_slots[pos].idx = -1;
        }

        frcti->rcv_cr.rwe += count;

        /* Drop may span a gap; pull lwe up to preserve rwe - RQ_SIZE <= lwe. */
        edge = frcti->rcv_cr.rwe - RQ_SIZE;
        if (before(frcti->rcv_cr.lwe, edge))
                STORE_RELEASE(&frcti->rcv_cr.lwe, edge);
}

/* Copy `count` fragments at rq[lwe..] into buf; release + advance lwe. */
static size_t frag_gather(struct frcti * frcti,
                          size_t         count,
                          uint8_t *      buf)
{
        struct ssm_pk_buff * frag;
        size_t               off = 0;
        size_t               i;
        uint32_t             k   = frcti->rcv_cr.rwe - RQ_SIZE;

        for (i = 0; i < count; ++i) {
                size_t pos = RQ_SLOT(k + i);
                size_t flen;

                frag = rq_frag(frcti, k + i);
                flen = ssm_pk_buff_len(frag);
                memcpy(buf + off, ssm_pk_buff_head(frag), flen);
                off += flen;
                frct_spb_release_idx(frcti->rcv_slots[pos].idx);
                frcti->rcv_slots[pos].idx = -1;
        }

        frcti->rcv_cr.rwe += count;

        return off;
}

/* Caller holds lock. */
static size_t frag_total_len(struct frcti * frcti,
                             size_t         count,
                             bool *         overflow)
{
        struct ssm_pk_buff * frag;
        size_t               total = 0;
        size_t               i;
        uint32_t             k     = frcti->rcv_cr.rwe - RQ_SIZE;

        *overflow = false;

        for (i = 0; i < count; ++i) {
                size_t flen;

                frag = rq_frag(frcti, k + i);
                flen = ssm_pk_buff_len(frag);
                if (total + flen < total) {
                        *overflow = true;
                        return 0;
                }
                total += flen;
        }

        return total;
}

/*
 * Process a delivered slot at lwe: latch FIN if acceptable,
 * advance byte_high (clamped to byte_fin once latched).
 */
static __inline__ void stream_deliver_slot(struct frcti * frcti,
                                           size_t         lp)
{
        uint32_t end;

        end = frcti->rcv_slots[lp].end;

        if (frcti->rcv_slots[lp].fin) {
                if (end == frcti->rcv_byte_high && !frcti->rcv_fin_seen) {
                        frcti->rcv_fin_seen = true;
                        frcti->rcv_byte_fin = end;
                } else {
                        STAT_BUMP(frcti, strm_fin_drop);
                }
        }

        if (frcti->rcv_fin_seen && after(end, frcti->rcv_byte_fin))
                end = frcti->rcv_byte_fin;

        frcti->rcv_byte_high = end;
}

/* Two-segment memcpy from buf into the rx ring at byte offset start. */
static void stream_ring_write(struct frcti * frcti,
                              uint32_t       start,
                              buffer_t       buf)
{
        size_t mask = frcti->rcv_ring_sz - 1;
        size_t off  = start & mask;

        if (off + buf.len <= frcti->rcv_ring_sz) {
                memcpy(frcti->rcv_ring + off, buf.data, buf.len);
        } else {
                size_t first = frcti->rcv_ring_sz - off;
                memcpy(frcti->rcv_ring + off, buf.data, first);
                memcpy(frcti->rcv_ring, buf.data + first, buf.len - first);
        }
}

/* Two-segment memcpy from the rx ring at byte offset start into buf. */
static void stream_ring_read(struct frcti * frcti,
                             uint32_t       start,
                             buffer_t       buf)
{
        size_t mask = frcti->rcv_ring_sz - 1;
        size_t off  = start & mask;

        if (off + buf.len <= frcti->rcv_ring_sz) {
                memcpy(buf.data, frcti->rcv_ring + off, buf.len);
        } else {
                size_t first = frcti->rcv_ring_sz - off;
                memcpy(buf.data, frcti->rcv_ring + off, first);
                memcpy(buf.data + first, frcti->rcv_ring, buf.len - first);
        }
}

/* Deliver-or-drop one stashed slot at lwe; advance lwe/rwe. Caller wrlock. */
static void stream_advance_lwe(struct frcti * frcti)
{
        size_t lp;

        lp = RQ_SLOT(frcti->rcv_cr.lwe);

        if (frcti->rcv_slots[lp].start != frcti->rcv_byte_high)
                STAT_BUMP(frcti, strm_drop);
        else
                stream_deliver_slot(frcti, lp);

        frcti->rcv_slots[lp].fin = 0;
        frcti->rcv_slots[lp].idx = -1;
        STORE_RELEASE(&frcti->rcv_cr.lwe, frcti->rcv_cr.lwe + 1);
        frcti->rcv_cr.rwe++;
}

/*
 * Validate a stream DATA packet before stashing. Returns 0 if the
 * packet may be written into rcv_ring + rq[], -1 otherwise.
 */
static __inline__ int stream_stash_check(struct frcti * frcti,
                                         uint32_t       start,
                                         uint32_t       end,
                                         size_t         plen,
                                         uint16_t       flags)
{
        if (end - start != (uint32_t) plen)
                return -1;

        /* FIN MUST be 0-byte. */
        if ((flags & FRCT_FIN) && plen != 0)
                return -1;

        /* Post-EOS: no further FIN once latched. */
        if (frcti->rcv_fin_seen && (flags & FRCT_FIN))
                return -1;

        /* Post-EOS: reject data at or past byte_fin. */
        if (frcti->rcv_fin_seen && !before(start, frcti->rcv_byte_fin))
                return -1;

        /* Stale: peer is behind the delivered edge. */
        if (before(end, frcti->rcv_byte_next))
                return -1;

        /* Exact-edge: only an empty-stream FIN is meaningful. */
        if (end == frcti->rcv_byte_next && !(flags & FRCT_FIN))
                return -1;

        if (end - frcti->rcv_byte_next > frcti->rcv_ring_sz)
                return -1;

        return 0;
}

/*
 * Stream-mode DATA receive: validate, stash payload in rcv_ring, mark
 * rq[pos], advance lwe through any newly-contiguous run. Returns 0
 * (spb released) or -1 (caller releases). Caller wrlock.
 */
static int frcti_stream_data_rcv(struct frcti *       frcti,
                                 struct ssm_pk_buff * spb,
                                 size_t               pos,
                                 uint16_t             flags)
{
        struct frct_pci_stream * spci;
        uint32_t                 start;
        uint32_t                 end;
        buffer_t                 buf;
        size_t                   skip;

        if (ssm_pk_buff_len(spb) < FRCT_PCI_STREAM_LEN)
                return -1;

        if (frcti->rcv_ring == NULL) {
                frcti->rcv_ring = calloc(1, frcti->rcv_ring_sz);
                if (frcti->rcv_ring == NULL)
                        return -ENOMEM;
        }

        spci = FRCT_HDR_POP(spb, frct_pci_stream);
        start = ntoh32(spci->start);
        end   = ntoh32(spci->end);

        buf.data = ssm_pk_buff_head(spb);
        buf.len  = ssm_pk_buff_len(spb);

        if (stream_stash_check(frcti, start, end, buf.len, flags) < 0)
                return -1;

        /* Trim front-overlap with already-delivered region. */
        if (before(start, frcti->rcv_byte_next)) {
                skip      = frcti->rcv_byte_next - start;
                buf.data += skip;
                buf.len  -= skip;
                start     = frcti->rcv_byte_next;
        }

        stream_ring_write(frcti, start, buf);
        STAT_ADD(frcti, strm_rcv_byte, buf.len);

        frcti->rcv_slots[pos].idx       = 1;
        frcti->rcv_slots[pos].start = start;
        frcti->rcv_slots[pos].end   = end;
        frcti->rcv_slots[pos].fin   = (flags & FRCT_FIN) ? 1 : 0;

        while (frcti->rcv_slots[RQ_SLOT(frcti->rcv_cr.lwe)].idx != -1)
                stream_advance_lwe(frcti);

        frct_spb_release(spb);

        return 0;
}

/*
 * DATA receive: stash idx at rq[pos], advance lwe through any
 * contiguous run. Caller wrlock.
 */
static void frcti_data_stash(struct frcti * frcti,
                             ssize_t        idx,
                             size_t         pos,
                             uint16_t       flags)
{
        frcti->rcv_slots[pos].idx = idx;

        if ((flags & FRCT_FR_MASK) != FRCT_FR_SOLE)
                STAT_BUMP(frcti, frag_rcv);

        /* lwe = cum-ACK edge; advance per fragment through contiguous run. */
        while (before(frcti->rcv_cr.lwe, frcti->rcv_cr.rwe)
               && frcti->rcv_slots[RQ_SLOT(frcti->rcv_cr.lwe)].idx != -1)
                STORE_RELEASE(&frcti->rcv_cr.lwe, frcti->rcv_cr.lwe + 1);
}

/* Stream consume: copy up to `count` contiguous bytes from ring into buf. */
static ssize_t frcti_consume_stream(struct frcti * frcti,
                                    uint8_t *      buf,
                                    size_t         count)
{
        size_t   avail;
        size_t   copy;
        ssize_t  ret;
        buffer_t dst;

        assert(frcti);

        pthread_rwlock_wrlock(&frcti->lock);

        avail = (size_t) (frcti->rcv_byte_high - frcti->rcv_byte_next);
        if (avail == 0) {
                /* EOS drained: signal EOF to the reader. */
                if (frcti->rcv_fin_seen
                    && frcti->rcv_byte_next == frcti->rcv_byte_fin)
                        ret = 0;
                else
                        ret = -EAGAIN;
                goto unlock;
        }

        copy = MIN(avail, count);

        dst.data = buf;
        dst.len  = copy;
        stream_ring_read(frcti, frcti->rcv_byte_next, dst);

        frcti->rcv_byte_next += (uint32_t) copy;
        STAT_ADD(frcti, strm_dlv_byte, copy);

        ret = (ssize_t) copy;

 unlock:
        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

/*
 * FRTX consume: copy next ready PDU (full SDU or nothing). Returns bytes,
 * -EAGAIN (no PDU), or -EMSGSIZE (oversize: run dropped to unblock flow).
 */
static ssize_t frcti_consume(struct frcti * frcti,
                             uint8_t *      buf,
                             size_t         count)
{
        size_t          n;
        size_t          total;
        bool            overflow;
        enum frag_state st;
        ssize_t         ret;

        assert(frcti);

        pthread_rwlock_wrlock(&frcti->lock);

        while (true) {
                st = frag_run_inspect(frcti, &n);
                if (st == FRAG_NOT_READY) {
                        ret = -EAGAIN;
                        goto unlock;
                }
                if (st == FRAG_DROP) {
                        STAT_ADD(frcti, frag_drop, n);
                        frag_drop(frcti, n);
                        continue;
                }
                /* FRAG_DELIVER */
                total = frag_total_len(frcti, n, &overflow);
                if (overflow || total > frcti->max_rcv_sdu || total > count) {
                        STAT_ADD(frcti, frag_drop, n);
                        frag_drop(frcti, n);
                        ret = -EMSGSIZE;
                        goto unlock;
                }
                ret = (ssize_t) frag_gather(frcti, n, buf);
                if (n > 1)
                        STAT_BUMP(frcti, sdu_reasm);
                goto unlock;
        }

 unlock:
        pthread_rwlock_unlock(&frcti->lock);

        return ret;
}

static bool frcti_pdu_ready(struct frcti * frcti)
{
        size_t pos;
        size_t count;
        bool   ready;

        assert(frcti);

        pthread_rwlock_rdlock(&frcti->lock);

        if (frcti->stream) {
                ready = frcti->rcv_byte_high != frcti->rcv_byte_next;
                pthread_rwlock_unlock(&frcti->lock);
                return ready;
        }

        if (frag_run_inspect(frcti, &count) != FRAG_DELIVER) {
                /* Drop case: frcti_consume will handle it; not ready. */
                pthread_rwlock_unlock(&frcti->lock);
                return false;
        }

        pos = RQ_SLOT(frcti->rcv_cr.rwe - RQ_SIZE);
        ready = frcti->rcv_slots[pos].idx != -1;

        pthread_rwlock_unlock(&frcti->lock);

        return ready;
}

/* No srtt yet: probe at the cold-probe cadence to seed it. */
#define PROBE_DUE_COLD(frcti, now_ns)                                     \
        ((now_ns) - (frcti)->t_snd_probe > (uint64_t) RTTP_COLD_NS)

/* Have srtt: probe when peer quiet for > 2*srtt and last probe > srtt. */
#define PROBE_DUE_WARM(frcti, now_ns)                                     \
        ((now_ns) - (frcti)->t_rcv_rtt > 2u * (uint64_t)(frcti)->srtt     \
         && (now_ns) - (frcti)->t_snd_probe > (uint64_t)(frcti)->srtt)

/* Seeds srtt for receive-only sides so they don't fall back to 1 s RTO. */
__attribute__((cold))
static void frcti_rcv_probe(struct frcti * frcti,
                            uint64_t       now_ns)
{
        uint32_t probe_id;
        uint8_t  nonce[RTTP_NONCE_LEN] = { 0 };

        pthread_rwlock_wrlock(&frcti->lock);

        if (frcti->srtt == 0 && !PROBE_DUE_COLD(frcti, now_ns)) {
                pthread_rwlock_unlock(&frcti->lock);
                return;
        }

        if (frcti->srtt != 0 && !PROBE_DUE_WARM(frcti, now_ns)) {
                pthread_rwlock_unlock(&frcti->lock);
                return;
        }

        probe_id = rttp_alloc_probe(frcti, now_ns, nonce);

        pthread_rwlock_unlock(&frcti->lock);

        if (probe_id != 0)
                frcti_rttp_snd(frcti, probe_id, 0, nonce);
}

/* Echo at slot `pos` matches our probe: id, slot, nonce all intact. */
static __inline__ bool probe_echo_matches(struct frcti * frcti,
                                          size_t         pos,
                                          uint32_t       echo_id,
                                          const uint8_t  nonce[RTTP_NONCE_LEN])
{
        if (frcti->probes[pos].id != echo_id)
                return false;

        if (frcti->probes[pos].ts == 0)
                return false;

        return memcmp(frcti->probes[pos].nonce, nonce, RTTP_NONCE_LEN) == 0;
}

/*
 * RTT probe (echo_id == 0): bounce the nonce back to peer.
 * RTT echo  (echo_id != 0): verify nonce + feed sample.
 */
static void frcti_rttp_rcv(struct frcti * frcti,
                           buffer_t       pkt,
                           uint64_t       now_ns)
{
        const struct frct_rttp * rttp;
        uint32_t                 probe_id;
        uint32_t                 echo_id;
        uint8_t                  nonce[RTTP_NONCE_LEN];
        size_t                   ring_pos;
        uint64_t                 sample;

        if (pkt.len < RTTP_PAYLOAD)
                return;

        rttp = (const struct frct_rttp *) pkt.data;
        probe_id = ntoh32(rttp->probe_id);
        echo_id  = ntoh32(rttp->echo_id);

        /* Forged/malformed: bouncing this would loop on echo_id == 0. */
        if (probe_id == 0 && echo_id == 0)
                return;

        memcpy(nonce, rttp->nonce, sizeof(nonce));

        if (echo_id == 0) {
                /* Probe: echo back with same nonce so peer can verify. */
                STAT_BUMP(frcti, rttp_rcv);
                frcti_rttp_snd(frcti, 0, probe_id, nonce);
                return;
        }

        ring_pos = RTTP_POS(echo_id);

        pthread_rwlock_wrlock(&frcti->lock);

        if (!probe_echo_matches(frcti, ring_pos, echo_id, nonce)) {
                pthread_rwlock_unlock(&frcti->lock);
                return;
        }

        sample = now_ns - frcti->probes[ring_pos].ts;
        frcti->probes[ring_pos].ts = 0;
        frcti->t_rcv_rtt = now_ns;

        /* Clamp probe sample to RTT_CLAMP_MUL * srtt to avoid poisoning. */
        if (frcti->srtt > 0)
                sample = MIN(sample, (uint64_t) frcti->srtt * RTT_CLAMP_MUL);

        rtt_update(frcti, sample, now_ns);

        pthread_rwlock_unlock(&frcti->lock);
}

/* Honours piggybacked ACK on the KA. */
static void frcti_ka_rcv(struct frcti *          frcti,
                         const struct frct_pci * pci,
                         uint64_t                now_ns,
                         uint16_t                flags)
{
        uint32_t ka_ackno;

        STORE_RELEASE(&frcti->t_ka_rcv, now_ns);
        STAT_BUMP(frcti, ka_rcv);

        if (!(flags & FRCT_ACK))
                return;

        ka_ackno = ntoh32(pci->ackno);

        pthread_rwlock_wrlock(&frcti->lock);

        if (within(ka_ackno, frcti->snd_cr.lwe, frcti->snd_cr.seqno))
                STORE_RELEASE(&frcti->snd_cr.lwe, ka_ackno);

        pthread_rwlock_unlock(&frcti->lock);
}

/*
 * Additive HoL re-emit (carries DRF); runs before rcv_cr->act
 * refresh so it doesn't pre-empt peer's first DRF.
 */
__attribute__((cold))
static void frcti_nack_rcv(struct frcti * frcti)
{
        struct timespec    now;
        uint64_t           now_ns;
        size_t             hp;
        struct rxm_entry * rxm;
        void *             pkt_copy = NULL;
        size_t             pkt_len  = 0;

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        pthread_rwlock_wrlock(&frcti->lock);

        STAT_BUMP(frcti, nack_rcv);

        if (frcti->snd_cr.seqno == frcti->snd_cr.lwe) {
                pthread_rwlock_unlock(&frcti->lock);
                return;
        }

        hp  = RQ_SLOT(frcti->snd_cr.lwe);
        rxm = LOAD_ACQUIRE(&frcti->snd_slots[hp].rxm);
        if (rxm == NULL || RXM_AGED_OUT(rxm->t0, now_ns, frcti->t_r)) {
                pthread_rwlock_unlock(&frcti->lock);
                return;
        }

        pkt_copy = malloc(rxm->len);
        if (pkt_copy != NULL) {
                memcpy(pkt_copy, rxm->pkt, rxm->len);
                pkt_len = rxm->len;
                /* Karn: suppress RTT sample for next ACK. */
                frcti->snd_slots[hp].flags |= SND_RTX | SND_FAST_RXM;
                frcti->rtt_lwe = frcti->snd_cr.lwe + 1;
        }

        pthread_rwlock_unlock(&frcti->lock);

        if (pkt_copy != NULL) {
                fast_rxm_send(frcti, pkt_copy, pkt_len);
                free(pkt_copy);
        }
}

__attribute__((cold))
static void frcti_rdv_rcv(struct frcti * frcti)
{
        uint32_t rwe;

        pthread_rwlock_rdlock(&frcti->lock);

        rwe = frcti_advert_rwe(frcti);

        pthread_rwlock_unlock(&frcti->lock);

        STAT_BUMP(frcti, rdv_rcv);

        frcti_pkt_snd(frcti, FRCT_FC, 0, rwe);
}

/*
 * FC window advert from any flag-bearing packet. Caps at lwe + RQ_SIZE,
 * rejects backward shrink (forged/stale FC), marks window open.
 * Caller wrlock.
 */
static __inline__ void frcti_fc_rcv(struct frcti *          frcti,
                                    const struct frct_pci * pci)
{
        struct frct_cr * snd_cr;
        uint32_t         rwe;
        uint32_t         rwe_max;

        snd_cr  = &frcti->snd_cr;
        rwe     = ntoh32(pci->window);
        rwe_max = snd_cr->lwe + RQ_SIZE;

        if (after(rwe, rwe_max))
                rwe = rwe_max;

        /* Reject backward shrink (forged/stale FC). */
        if (before(rwe, snd_cr->rwe))
                rwe = snd_cr->rwe;

        STORE_RELAXED(&snd_cr->rwe, rwe);
        frcti->open = true;
}

/* Packet copies captured under frcti->lock; emitted after release. */
struct pending {
        buffer_t fast_rxm;
        buffer_t sack_rxm[SACK_RXM_MAX];
        size_t   sack_rxm_cnt;
};

/* Idempotent; only extends when snd_cr.seqno advances past recovery_high. */
static void recovery_enter(struct frcti * frcti)
{
        uint32_t hi = frcti->snd_cr.seqno + RTT_QUARANTINE;

        if (!frcti->in_recovery || after(hi, frcti->recovery_high)) {
                frcti->in_recovery   = true;
                frcti->recovery_high = hi;
        }
}

/* True when cum-ACK clears recovery_high or all in-flight ACKed. */
static bool recovery_exit_reached(struct frcti * frcti,
                                  uint32_t       ackno)
{
        if (!frcti->in_recovery)
                return false;

        if (!before(ackno, frcti->recovery_high))
                return true;

        return ackno == frcti->snd_cr.seqno;
}

/* RTT sample gate: Karn + SACK-consume + 4x clamp + don't-seed. */
static bool rtt_sample_eligible(struct frcti * frcti,
                                size_t         p,
                                uint16_t       flags,
                                uint32_t       lwe)
{
        if (frcti->in_recovery)
                return false;
        if (flags & FRCT_RXM)
                return false;
        if (frcti->snd_slots[p].flags & SND_RTX)
                return false;
        if (LOAD_ACQUIRE(&frcti->snd_slots[p].rxm) == NULL)
                return false;
        if (before(lwe, frcti->rtt_lwe))
                return false;
        /* Don't seed srtt from a cum-ACK; let probes seed. */
        if (frcti->srtt == 0)
                return false;
        return true;
}

#define RXM_SLOT_EMPTY(rxm)     ((rxm) == NULL)
#define FAST_RXM_STAGED(pending) ((pending)->fast_rxm.data != NULL)
#define RXM_FAST_DONE(flags)    (((flags) & SND_FAST_RXM) != 0)

/* RACK fast retransmit on cum-ACK: HoL aged past R, not yet retransmitted. */
static void fast_rxm_consider(struct frcti *   frcti,
                              uint64_t         now_ns,
                              struct pending * pending)
{
        struct rxm_entry * rxm;
        struct snd_slot *  slot;
        size_t             hp;
        uint64_t           R;
        bool               rack_ok;

        hp     = RQ_SLOT(frcti->snd_cr.lwe);
        slot   = &frcti->snd_slots[hp];
        rxm    = LOAD_ACQUIRE(&slot->rxm);
        R      = rack_reorder_window(frcti);

        if (RXM_SLOT_EMPTY(rxm))
                return;

        /* RFC 8985 §6.2: time-based RACK OR DupThresh count. */
        rack_ok = (int64_t)(frcti->t_latest_ack - slot->time) > (int64_t) R;
        if (!rack_ok && frcti->dup_thresh < DUP_THRESH)
                return;

        /* HoL aged past t_r; let rxm_due tear the flow down. */
        if (RXM_AGED_OUT(rxm->t0, now_ns, frcti->t_r))
                return;

        /* Already on it. */
        if (FAST_RXM_STAGED(pending) || RXM_FAST_DONE(slot->flags))
                return;

        recovery_enter(frcti);

        pending->fast_rxm.data = malloc(rxm->len);
        if (pending->fast_rxm.data == NULL)
                return;

        pending->fast_rxm.len = rxm->len;
        memcpy(pending->fast_rxm.data, rxm->pkt, rxm->len);
        slot->flags |= SND_RTX | SND_FAST_RXM;
        frcti->rtt_lwe = frcti->snd_cr.lwe + 1;
        if (rack_ok)
                STAT_BUMP(frcti, rxm_rack);
        else
                STAT_BUMP(frcti, rxm_dupthresh);
}

/* Caller holds wrlock; RACK fast retransmit queued in pending. */
__attribute__((hot))
static void frcti_ack_rcv(struct frcti *          frcti,
                          const struct frct_pci * pci,
                          uint16_t                flags,
                          uint64_t                now_ns,
                          struct pending *        pending)
{
        uint32_t ackno;
        uint32_t lwe;
        size_t   p;
        size_t   fresh;

        if (!(flags & FRCT_DATA))
                STAT_BUMP(frcti, ack_rcv);

        ackno = ntoh32(pci->ackno);
        if (ackno == frcti->snd_cr.lwe) {
                /* RFC 8985 §6.2: only on scoreboard change. */
                if (frcti->snd_cr.lwe != frcti->rack_fired_lwe) {
                        fast_rxm_consider(frcti, now_ns, pending);
                        frcti->rack_fired_lwe = frcti->snd_cr.lwe;
                }
                return;
        }

        if (!within(ackno, frcti->snd_cr.lwe, frcti->snd_cr.seqno))
                return;

        lwe = frcti->snd_cr.lwe;
        p   = RQ_SLOT(lwe);

        STORE_RELEASE(&frcti->snd_cr.lwe, ackno);

        /* RFC 8985 §7.2: halve mult per REO_DECAY_PKTS fresh-ACK'd seqnos. */
        fresh = ackno - frcti->dsack_lwe_snap;
        if (frcti->reo_wnd_mult > 1 && fresh >= REO_DECAY_PKTS) {
                uint8_t half = frcti->reo_wnd_mult >> 1;
                frcti->reo_wnd_mult = half < 1 ? 1 : half;
                frcti->dsack_lwe_snap = ackno;
        }

        /* RFC 8985: latest cum-ACKed send-time (slot of ackno-1). */
        frcti->t_latest_ack = frcti->snd_slots[RQ_SLOT(ackno - 1)].time;

        /* RFC 8985: SACK-above-lwe count is per-recovery-episode. */
        frcti->dup_thresh = 0;

        /* Karn: only collapse RTO backoff on a fresh ACK. */
        if ((frcti->snd_slots[p].flags & SND_RTX) == 0)
                STORE_RELEASE(&frcti->rto_mul, 0);

        if (recovery_exit_reached(frcti, ackno))
                frcti->in_recovery = false;

        if (rtt_sample_eligible(frcti, p, flags, lwe)) {
                uint64_t mrtt = now_ns - frcti->snd_slots[p].time;
                if (!(flags & FRCT_DATA))
                        STAT_BUMP(frcti, ack_rtt);
                rtt_update(frcti, mrtt, now_ns);
                frcti->t_rcv_rtt = now_ns;
        }
}

/* Skip k == lwe under clamp: NULLing HoL from a stale SACK wedges it. */
static uint32_t sack_mark_blocks(struct frcti *  frcti,
                                 const uint8_t * payload,
                                 uint16_t        n,
                                 uint32_t *      newly_marked)
{
        uint32_t hi_sacked = frcti->snd_cr.lwe;
        uint32_t marked    = 0;
        uint16_t i;

        for (i = 0; i < n; ++i) {
                uint32_t s;
                uint32_t e;
                uint32_t k;
                bool     clamped;

                sack_block_get(payload, i, &s, &e);

                if (!before(s, e))
                        continue;

                clamped = before(s, frcti->snd_cr.lwe);
                if (clamped)
                        s = frcti->snd_cr.lwe;
                if (after(e, frcti->snd_cr.seqno))
                        e = frcti->snd_cr.seqno;

                for (k = s; before(k, e); ++k) {
                        size_t   kp  = RQ_SLOT(k);
                        uint64_t t_k;
                        if (clamped && k == frcti->snd_cr.lwe)
                                continue;
                        if (LOAD_ACQUIRE(&frcti->snd_slots[kp].rxm) == NULL)
                                continue;
                        STORE_RELEASE(&frcti->snd_slots[kp].rxm, NULL);
                        frcti->snd_slots[kp].flags = 0;
                        marked++;
                        /* RACK.fack: latest SACK-confirmed send-time. */
                        t_k = frcti->snd_slots[kp].time;
                        if (t_k > frcti->t_latest_ack)
                                frcti->t_latest_ack = t_k;
                }

                if (after(e, hi_sacked))
                        hi_sacked = e;
        }

        *newly_marked = marked;
        return hi_sacked;
}

/* Queue once per loss event (SND_FAST_RXM gates). Emit after unlock. */
static void sack_queue_rxm(struct frcti *    frcti,
                           uint32_t          hi_sacked,
                           uint64_t          now_ns,
                           struct pending *  pending)
{
        uint64_t R = rack_reorder_window(frcti);
        uint32_t k;
        bool     rack_ok;

        for (k = frcti->snd_cr.lwe; before(k, hi_sacked); ++k) {
                struct rxm_entry * rxm;
                size_t             kp  = RQ_SLOT(k);
                size_t             cnt = pending->sack_rxm_cnt;
                size_t             rack_age;

                rxm = LOAD_ACQUIRE(&frcti->snd_slots[kp].rxm);

                if (cnt >= SACK_RXM_MAX)
                        break;

                if (rxm == NULL)
                        continue;

                if (frcti->snd_slots[kp].flags & SND_FAST_RXM)
                        continue;

                if (RXM_AGED_OUT(rxm->t0, now_ns, frcti->t_r))
                        continue;

                rack_age = frcti->t_latest_ack - frcti->snd_slots[kp].time;
                /* RFC 8985 §6.2: time-based RACK OR DupThresh count. */
                rack_ok = (int64_t) rack_age > (int64_t) R;
                if (!rack_ok && frcti->dup_thresh < DUP_THRESH)
                        continue;

                if (!rack_ok)
                        STAT_BUMP(frcti, rxm_dupthresh);

                pending->sack_rxm[cnt].data = malloc(rxm->len);
                if (pending->sack_rxm[cnt].data == NULL)
                        break;

                pending->sack_rxm[cnt].len = rxm->len;
                memcpy(pending->sack_rxm[cnt].data, rxm->pkt, rxm->len);
                pending->sack_rxm_cnt++;
                /* NULL slot so the original timer self-cleans. */
                STORE_RELEASE(&frcti->snd_slots[kp].rxm, NULL);
                frcti->snd_slots[kp].time   = now_ns;
                frcti->snd_slots[kp].flags |= SND_RTX | SND_FAST_RXM;
                frcti->rtt_lwe = k + 1;
        }
}

/*
 * RFC 2883 D-SACK detector.  Returns true iff block[0] is a D-SACK
 * report:
 *   case 1: blocks[0].start < pkt_ackno (strictly below cum-ACK).
 *   case 2: blocks[0] is a strict sub-range of some blocks[i>0].
 * MAX_DSACK_LAG bounds case-1 distance to one rcv window (sanity).
 */
static bool sack_is_dsack(struct frcti *  frcti,
                          const uint8_t * payload,
                          uint16_t        n,
                          uint32_t        pkt_ackno)
{
        uint32_t s0;
        uint32_t e0;
        uint16_t i;

        if (n == 0)
                return false;

        sack_block_get(payload, 0, &s0, &e0);
        if (!before(s0, e0))
                return false;

        if (before(s0, pkt_ackno)) {
                if ((pkt_ackno - s0) <= (uint32_t) MAX_DSACK_LAG)
                        return true;
                STAT_BUMP(frcti, dsack_drop);
                return false;
        }

        for (i = 1; i < n; ++i) {
                uint32_t si;
                uint32_t ei;

                sack_block_get(payload, i, &si, &ei);
                if (!before(si, ei))
                        continue;
                if (!before(s0, si) && !after(e0, ei)
                    && (s0 != si || e0 != ei))
                        return true;
        }

        return false;
}

/* RFC 8985 §7.2: grow reo_wnd_mult on DSACK evidence. Caller wrlock. */
static __inline__ void reo_wnd_on_dsack(struct frcti * frcti)
{
        if (frcti->reo_wnd_mult < REO_WND_MULT_MAX)
                frcti->reo_wnd_mult++;

        frcti->dsack_lwe_snap = frcti->snd_cr.lwe;
}

/* Caller holds wrlock; retransmits queued for post-unlock emission. */
static void frcti_sack_rcv(struct frcti *   frcti,
                           buffer_t         pkt,
                           uint32_t         pkt_ackno,
                           uint64_t         now_ns,
                           struct pending * pending)
{
        uint32_t hi_sacked;
        uint32_t marked;
        uint16_t n;
        bool     dsack;
        uint16_t n_real;

        if (pkt.len < SACK_HDR_SIZE)
                return;

        n = ntoh16(*(const uint16_t *) pkt.data);
        if (n > SACK_MAX_BLOCKS)
                return;

        if (pkt.len < SACK_HDR_SIZE + (size_t) n * SACK_BLOCK_SIZE)
                return;

        STAT_BUMP(frcti, sack_rcv);

        dsack  = sack_is_dsack(frcti, pkt.data, n, pkt_ackno);
        n_real = n - (dsack ? 1 : 0);

        if (dsack) {
                STAT_BUMP(frcti, dsack_rcv);
                reo_wnd_on_dsack(frcti);
        }

        /* DSACK-only carries no new gap; don't enter recovery. */
        if (n_real > 0)
                recovery_enter(frcti);

        marked    = 0;
        hi_sacked = sack_mark_blocks(frcti, pkt.data, n, &marked);
        frcti->dup_thresh += marked;

        if (after(hi_sacked, frcti->snd_cr.lwe))
                sack_queue_rxm(frcti, hi_sacked, now_ns, pending);
}

/* Emit and free queued packet copies. */
static void pending_flush(struct frcti *   frcti,
                          struct pending * pending)
{
        size_t i;

        for (i = 0; i < pending->sack_rxm_cnt; ++i) {
                sack_rxm_snd(frcti, pending->sack_rxm[i].data,
                             pending->sack_rxm[i].len);
                free(pending->sack_rxm[i].data);
        }

        if (pending->fast_rxm.data != NULL) {
                fast_rxm_send(frcti, pending->fast_rxm.data,
                                   pending->fast_rxm.len);
                free(pending->fast_rxm.data);
        }
}

/* Pre-DRF NACK: ask peer to retransmit HoL; seqno is informational. */
static void frcti_nack_snd(struct frcti * frcti,
                           uint32_t       seqno_unseen)
{
        struct ssm_pk_buff * spb;
        struct frct_pci *    pci;

        if (frct_ctrl_alloc(&spb, &pci, 0) < 0)
                return;

        pci->flags = hton16(FRCT_NACK);
        pci->seqno = hton32(seqno_unseen);

        frct_hcs_set(pci, false);

        frct_tx(frcti, spb);
}

enum frct_act {
        FRCT_ACTIVE,
        FRCT_INACT_NEED_NACK,
        FRCT_INACT_DROP,
};

/* On rcv inactivity: rebase on DRF, or arm pre-DRF NACK. Caller wrlock. */
static enum frct_act rcv_inact_check(struct frcti * frcti,
                                       uint16_t       flags,
                                       uint32_t       seqno,
                                       uint64_t       now_ns)
{
        struct frct_cr * rcv_cr = &frcti->rcv_cr;
        uint64_t         cd;

        if (now_ns - rcv_cr->act <= rcv_cr->inact)
                return FRCT_ACTIVE;

        if (flags & FRCT_DRF) {
                /* Release stale rq[] slots before rebasing. */
                release_rq(frcti);
                STORE_RELEASE(&rcv_cr->lwe, seqno);
                rcv_cr->rwe = seqno + RQ_SIZE;
                rcv_cr->seqno = seqno;
                return FRCT_ACTIVE;
        }

        if (!(flags & FRCT_DATA))
                return FRCT_ACTIVE;

        /* Pre-DRF: nudge sender with NACK (rate-limited). */
        cd = frcti->srtt > 0 ? (uint64_t) frcti->srtt : NACK_COOLDOWN_NS;
        if (now_ns - frcti->t_nack < cd)
                return FRCT_INACT_DROP;

        frcti->t_nack = now_ns;
        STAT_BUMP(frcti, nack_snd);

        return FRCT_INACT_NEED_NACK;
}

/* Both modes: bounded accept into rq[seqno]. Caller wrlock. */
__attribute__((hot))
static bool rq_accept(struct frcti * frcti,
                      uint32_t       seqno,
                      size_t         pos,
                      uint16_t       flags)
{
        struct frct_cr * rcv_cr = &frcti->rcv_cr;

        if (!before(seqno, rcv_cr->rwe)) {
                STAT_BUMP(frcti, out_rcv);
                return false;
        }

        if (!before(seqno, rcv_cr->lwe + RQ_SIZE)) {
                STAT_BUMP(frcti, rqo_rcv);
                return false;
        }

        if (frcti->rcv_slots[pos].idx != -1) {
                if (flags & FRCT_RXM)
                        STAT_BUMP(frcti, rxm_rcv);
                else
                        STAT_BUMP(frcti, dup_rcv);
                /* RFC 2883 §4 case 2: in-window dup; sub-range marker. */
                frcti->dsack_seqno = seqno;
                frcti->dsack_valid = true;
                return false;
        }

        return true;
}

/* OOO arrival; throttle by min_gap + scoreboard dedup. */
static bool sack_check(struct frcti *     frcti,
                       uint32_t           seqno,
                       uint64_t           now_ns,
                       struct sack_args * out)
{
        struct frct_cr * rcv_cr = &frcti->rcv_cr;
        uint64_t         min_gap;
        uint16_t         n;

        if (!after(seqno, rcv_cr->lwe))
                return false;

        STAT_BUMP(frcti, ooo_rcv);

        /* SACK carries cum-ACK; bound by t_a like any other ACK. */
        if (ACK_AGED_OUT(rcv_cr->act, now_ns, frcti->t_a))
                return false;

        /* srtt/8 gate starved recovery under burst loss; floor to save CPU. */
        min_gap = (uint64_t) SACK_MIN_GAP_NS;

        if (now_ns - frcti->t_snd_sack < min_gap)
                return false;

        out->dsack = false;
        n = dsack_consume(frcti, out->blocks);
        if (n == 1)
                out->dsack = true;
        n += sack_blocks_build(frcti, out->blocks + n,
                               frcti->sack_n_max - n);

        if (!out->dsack
            && rcv_cr->lwe == frcti->sack_lwe && n == frcti->sack_n)
                return false;

        out->n   = n;
        out->ack = rcv_cr->lwe;
        out->rwe = frcti_advert_rwe(frcti);
        frcti->t_snd_sack = now_ns;
        frcti->sack_lwe   = rcv_cr->lwe;
        frcti->sack_n     = n;

        return true;
}

/* Wire-dup of fresh DATA at an already-ACKed seqno. */
static __inline__ bool is_dup_data(uint16_t flags,
                                   uint32_t seqno,
                                   uint32_t lwe)
{
        if (!(flags & FRCT_DATA))
                return false;

        if (flags & FRCT_RXM)
                return false;

        return before(seqno, lwe);
}

/*
 * Wire-dup ACK packet: same seqno as the previous emission. Updates
 * the dedup ackno on a fresh ACK; caller drops on true.
 */
static __inline__ bool is_dup_ack(struct frcti * frcti,
                                  uint16_t       flags,
                                  uint32_t       seqno)
{
        if (flags & FRCT_DATA)
                return false;

        if (!(flags & FRCT_ACK))
                return false;

        if (seqno == frcti->rcv_cr.ackno)
                return true;

        frcti->rcv_cr.ackno = seqno;

        return false;
}

/* Caller wrlock. */
__attribute__((cold))
static void seqno_rotate(struct frcti * frcti,
                         uint64_t       now_ns)
{
        struct frct_cr * snd_cr = &frcti->snd_cr;

        if (now_ns - snd_cr->act <= snd_cr->inact)
                return;
        /* Idle-on-wire ≠ idle e2e: don't orphan in-flight rxm. */
        if (snd_cr->seqno != snd_cr->lwe)
                return;

        random_buffer(&snd_cr->seqno, sizeof(snd_cr->seqno));
        STORE_RELEASE(&snd_cr->lwe, snd_cr->seqno);
        STORE_RELAXED(&snd_cr->rwe, snd_cr->lwe + START_WINDOW);
        frcti->rtt_lwe = snd_cr->seqno;
        frcti->in_recovery   = false;
        frcti->recovery_high = snd_cr->seqno;
}

__attribute__((hot))
static int frcti_snd(struct frcti *       frcti,
                     struct ssm_pk_buff * spb,
                     uint16_t             flags)
{
        struct frct_pci *        pci;
        struct frct_pci_stream * spci = NULL;
        struct timespec          now;
        struct frct_cr *         snd_cr;
        struct frct_cr *         rcv_cr;
        uint32_t                 seqno;
        uint16_t                 pci_flags = 0;
        bool                     rtx;
        uint64_t                 now_ns;
        uint64_t                 rcv_idle;
        uint32_t                 probe_id = 0;
        uint8_t                  probe_nonce[RTTP_NONCE_LEN] = { 0 };
        bool                     probe;
        size_t                   payload_len = 0;

        assert(frcti);
        /* Stream mode permits 0-byte sends for the EOS marker. */
        assert(ssm_pk_buff_len(spb) != 0 || frcti->stream);

        snd_cr = &frcti->snd_cr;
        rcv_cr = &frcti->rcv_cr;

        tw_move_safe();

        if (frcti->stream)
                payload_len = ssm_pk_buff_len(spb);

        pci = FRCT_HDR_PUSH(spb, frcti);
        if (pci == NULL)
                return -ENOMEM;

        memset(pci, 0, FRCT_PCILEN);

        if (frcti->stream)
                spci = FRCT_SPCI(pci);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        pthread_rwlock_wrlock(&frcti->lock);

        rtx = snd_cr->cflags & FRCTFRTX;

        pci_flags |= FRCT_DATA;
        if (!frcti->stream)
                pci_flags |= (flags & FRCT_FR_MASK);

        if (!frcti->stream && (flags & FRCT_FR_MASK) != FRCT_FR_SOLE)
                STAT_BUMP(frcti, frag_snd);

        if (frcti->stream) {
                if (flags & FRCT_FIN)
                        pci_flags |= FRCT_FIN;

                spci->start = hton32(frcti->snd_byte_next);
                frcti->snd_byte_next += (uint32_t) payload_len;
                spci->end   = hton32(frcti->snd_byte_next);
                STAT_ADD(frcti, strm_snd_byte, payload_len);
        }

        if (snd_cr->seqno == snd_cr->lwe)
                pci_flags |= FRCT_DRF;

        seqno_rotate(frcti, now_ns);

        seqno = snd_cr->seqno;
        pci->seqno = hton32(seqno);

        rcv_idle = now_ns - rcv_cr->act;

        if (rcv_idle < rcv_cr->inact) {
                pci_flags |= FRCT_FC;
                pci->window = hton32(frcti_advert_rwe(frcti));
        }

        if (!rtx) {
                STORE_RELEASE(&snd_cr->lwe, snd_cr->lwe + 1);
                STORE_RELEASE(&snd_cr->rwe, snd_cr->lwe + RQ_SIZE);
        } else {
                size_t p = RQ_SLOT(seqno);
                frcti->snd_slots[p].time = now_ns;
                /* Fresh send clears RTX bits. */
                frcti->snd_slots[p].flags = 0;
                if (rcv_idle <= (uint64_t) frcti->t_a) {
                        pci_flags |= FRCT_ACK;
                        pci->ackno = hton32(rcv_cr->lwe);
                        rcv_cr->seqno = rcv_cr->lwe;
                }
        }

        pci->flags = hton16(pci_flags);

        frct_hcs_set(pci, frcti->stream);

        snd_cr->seqno++;
        STORE_RELEASE(&snd_cr->act, now_ns);

        probe = rtt_probe_arm(frcti, now_ns, &probe_id, probe_nonce);

        pthread_rwlock_unlock(&frcti->lock);

        if (probe)
                frcti_rttp_snd(frcti, probe_id, 0, probe_nonce);

        if (rtx)
                rxm_arm(frcti, seqno, spb);

        return 0;
}

/* 0-byte FRCT_FIN DATA so peer's flow_read returns 0 at this byte. */
static void frcti_stream_fin_snd(struct frcti * frcti)
{
        struct ssm_pk_buff * spb;
        bool                 already;

        assert(frcti->stream);

        pthread_rwlock_wrlock(&frcti->lock);

        already = frcti->snd_fin_sent;
        frcti->snd_fin_sent = true;

        pthread_rwlock_unlock(&frcti->lock);

        if (already)
                return;

        if (frct_spb_reserve(frcti_data_hdr_len(frcti), &spb) < 0)
                return;

        /* Reset spb to 0-len so frcti_snd's head_alloc populates PCI. */
        ssm_pk_buff_truncate(spb, 0);

        if (frcti_snd(frcti, spb, FRCT_FIN) < 0) {
                frct_spb_release(spb);
                return;
        }

        if (frct_tx(frcti, spb) < 0)
                return;

        pthread_rwlock_wrlock(&frcti->lock);

        frcti->snd_fin_seqno = frcti->snd_cr.seqno - 1;

        pthread_rwlock_unlock(&frcti->lock);
}

static bool final_ack_due(struct frcti *   frcti,
                          struct frct_cr * rcv_cr,
                          uint64_t         now_ns)
{
        if (rcv_cr->lwe == rcv_cr->seqno)
                return false;

        if (ACK_AGED_OUT(rcv_cr->act, now_ns, frcti->t_a))
                return false;

        return true;
}

/* Drain-loop predicate: FLINGER cflag + unACK'd data below the FIN/seqno. */
static bool frcti_lingering(struct frcti * frcti)
{
        struct frct_cr * snd_cr;
        uint32_t         edge;
        bool             linger;

        /* Idempotent; FIN must be sent before any linger check uses it. */
        if (frcti->stream)
                frcti_stream_fin_snd(frcti);

        pthread_rwlock_rdlock(&frcti->lock);

        snd_cr = &frcti->snd_cr;

        if (frcti->snd_fin_sent)
                edge = frcti->snd_fin_seqno;
        else
                edge = snd_cr->seqno;

        linger = (snd_cr->cflags & FRCTFLINGER) && before(snd_cr->lwe, edge);

        pthread_rwlock_unlock(&frcti->lock);

        return linger;
}

static time_t frcti_dealloc(struct frcti * frcti)
{
        struct timespec  now;
        struct frct_cr * snd_cr;
        struct frct_cr * rcv_cr;
        int              ackno;
        bool             due;
        int64_t          now_ns;
        int64_t          rcv;
        int64_t          snd;

        snd_cr = &frcti->snd_cr;
        rcv_cr = &frcti->rcv_cr;

        /* Idempotent; usually already sent by frcti_lingering. */
        if (frcti->stream)
                frcti_stream_fin_snd(frcti);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        pthread_rwlock_rdlock(&frcti->lock);

        ackno = rcv_cr->lwe;
        rcv   = (int64_t)(rcv_cr->act + rcv_cr->inact) - now_ns;
        snd   = (int64_t)(snd_cr->act + snd_cr->inact) - now_ns;
        due   = final_ack_due(frcti, rcv_cr, now_ns);

        pthread_rwlock_unlock(&frcti->lock);

        if (due)
                frcti_pkt_snd(frcti, FRCT_ACK, ackno, 0);

        return (time_t) MAX((MAX(rcv, snd) / BILLION), 0);
}

__attribute__((hot))
static void frcti_rcv(struct frcti *       frcti,
                      struct ssm_pk_buff * spb)
{
        ssize_t             idx;
        size_t              pos;
        struct frct_pci *   pci;
        struct timespec     now;
        uint64_t            now_ns;
        struct frct_cr *    rcv_cr;
        uint32_t            seqno;
        uint16_t            flags;
        buffer_t            pkt;
        struct pending      pending = { 0 };
        bool                in_order;
        struct sack_args *  sa = NULL;
        bool                send_sack = false;

        assert(frcti);

        rcv_cr = &frcti->rcv_cr;

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        now_ns = TS_TO_UINT64(now);

        if (ssm_pk_buff_len(spb) < FRCT_PCILEN) {
                frct_spb_release(spb);
                return;
        }

        pci = FRCT_HDR_POP(spb, frct_pci);

        idx   = ssm_pk_buff_get_off(spb);
        seqno = ntoh32(pci->seqno);
        pos   = RQ_SLOT(seqno);

        flags = ntoh16(pci->flags);

        pkt.data = ssm_pk_buff_head(spb);
        pkt.len  = ssm_pk_buff_len(spb);

        /* Stateless / lock-free dispatches. spb released via ctrl_done. */
        if (flags & FRCT_KA) {
                frcti_ka_rcv(frcti, pci, now_ns, flags);
                goto ctrl_done;
        }

        if (flags & FRCT_RTTP) {
                frcti_rttp_rcv(frcti, pkt, now_ns);
                goto ctrl_done;
        }

        if (flags & FRCT_NACK) {
                frcti_nack_rcv(frcti);
                goto ctrl_done;
        }

        if (flags & FRCT_RDVS) {
                frcti_rdv_rcv(frcti);
                goto ctrl_done;
        }

        pthread_rwlock_wrlock(&frcti->lock);

        /* rcv_inact_check is a no-op for non-DATA non-DRF packets. */
        if (flags & (FRCT_DATA | FRCT_DRF)) {
                switch (rcv_inact_check(frcti, flags, seqno, now_ns)) {
                case FRCT_INACT_NEED_NACK:
                        pthread_rwlock_unlock(&frcti->lock);
                        frcti_nack_snd(frcti, seqno - 1);
                        frct_spb_release(spb);
                        return;
                case FRCT_INACT_DROP:
                        goto drop_packet;
                case FRCT_ACTIVE:
                        /* FALLTHRU */
                default:
                        break;
                }
        }

        /* DATA-only act refresh: non-DATA would lock out DRF rebase. */
        if (flags & FRCT_DATA)
                STORE_RELEASE(&rcv_cr->act, now_ns);

        /* Wire-dup ACK packet: same seqno as the previous emission. */
        if (is_dup_ack(frcti, flags, seqno)) {
                STAT_BUMP(frcti, ack_dup_rcv);
                goto drop_packet;
        }

        /* Wire-dup of DATA: piggybacked ACK info already processed. */
        if (is_dup_data(flags, seqno, rcv_cr->lwe)) {
                rcv_cr->seqno = seqno;
                STAT_BUMP(frcti, dup_rcv);
                /* RFC 2883 §4 case 1: dup below cum-ACK. */
                frcti->dsack_seqno = seqno;
                frcti->dsack_valid = true;
                goto drop_packet;
        }

        if (flags & FRCT_ACK)
                frcti_ack_rcv(frcti, pci, flags, now_ns, &pending);

        if (flags & FRCT_SACK)
                frcti_sack_rcv(frcti, pkt, ntoh32(pci->ackno),
                               now_ns, &pending);

        if (flags & FRCT_FC)
                frcti_fc_rcv(frcti, pci);

        if (!(flags & FRCT_DATA))
                goto drop_packet;

        if (before(seqno, rcv_cr->lwe)) {
                /* Bump rcv_cr.seqno to force ack_snd to fire on the dup. */
                rcv_cr->seqno = seqno;
                if (flags & FRCT_RXM)
                        STAT_BUMP(frcti, rxm_rcv);
                else
                        STAT_BUMP(frcti, dup_rcv);
                /* RFC 2883 §4 case 1: dup below cum-ACK. */
                frcti->dsack_seqno = seqno;
                frcti->dsack_valid = true;
                goto drop_packet;
        }

        if (!rq_accept(frcti, seqno, pos, flags))
                goto drop_packet;

        if (frcti->stream) {
                if (frcti_stream_data_rcv(frcti, spb, pos, flags) < 0) {
                        STAT_BUMP(frcti, strm_drop);
                        goto drop_packet;
                }
                /* spb consumed by stash; do not release in drop path. */
                spb = NULL;
        } else {
                frcti_data_stash(frcti, idx, pos, flags);
        }

        /* Lazy alloc: only OOO arrivals can trigger a SACK send. */
        if (after(seqno, rcv_cr->lwe) && frcti->sack_n_max > 0) {
                size_t sa_sz = sizeof(*sa)
                             + frcti->sack_n_max * sizeof(sa->blocks[0]);
                sa = malloc(sa_sz);
                /* If alloc fails, sack_check sees NULL and we skip SACK. */
        }

        send_sack = sa != NULL && sack_check(frcti, seqno, now_ns, sa);
        in_order  = !after(seqno, rcv_cr->lwe);

        pthread_rwlock_unlock(&frcti->lock);

        if (send_sack) {
                STAT_BUMP(frcti, sack_snd);
                if (sa->dsack)
                        STAT_BUMP(frcti, dsack_snd);
                frcti_sack_snd(frcti, sa);
        } else if (in_order) {
                ack_arm(frcti);
        }

        pending_flush(frcti, &pending);

        frcti_rcv_probe(frcti, now_ns);

        free(sa);
        return;

 ctrl_done:
        frct_spb_release(spb);
        return;

 drop_packet:
        pthread_rwlock_unlock(&frcti->lock);
        frct_spb_release(spb);
        /* with_sack=true: ack_snd no-ops if neither dsack nor SACK is due. */
        ack_snd(frcti, true);

        pending_flush(frcti, &pending);
        free(sa);
}

/* NULL-shim macros for the no-FRCT case. */

#define FRCTI_SND(frcti, spb, flags)                                    \
        ((frcti) == NULL ? 0 : frcti_snd((frcti), (spb), (flags)))

#define FRCTI_RCV(frcti, spb)                                           \
        do {                                                            \
                if ((frcti) != NULL)                                    \
                        frcti_rcv((frcti), (spb));                      \
        } while (0)

#define FRCTI_PDU_READY(frcti)                                          \
        ((frcti) != NULL && frcti_pdu_ready(frcti))

#define FRCTI_CONSUME(frcti, buf, count)                                \
        ((frcti) == NULL ? (ssize_t) -EAGAIN                            \
         : (frcti)->stream                                              \
                 ? frcti_consume_stream((frcti), (buf), (count))        \
                 : frcti_consume((frcti), (buf), (count)))

#define FRCTI_IS_FRTX(frcti)                                            \
        ((frcti) != NULL && ((frcti)->rcv_cr.cflags & FRCTFRTX))

#define FRCTI_IS_STREAM(frcti)  ((frcti) != NULL && (frcti)->stream)

#define FRCTI_PAYLOAD_CAP(frcti)                                        \
        ((frcti)->frag_mtu - frcti_data_hdr_len(frcti))

#define FRCTI_NEEDS_FRAG(frcti, count)                                  \
        ((frcti) != NULL && (count) > FRCTI_PAYLOAD_CAP(frcti))

#define FRCTI_IS_WINDOW_OPEN(frcti)                                     \
        ((frcti) == NULL ? true : frcti_is_window_open(frcti))

#define FRCTI_IS_WINDOW_OPEN_N(frcti, n)                                \
        ((frcti) == NULL ? true : frcti_is_window_open_n((frcti), (n)))

#define FRCTI_LINGERING(frcti)                                          \
        ((frcti) == NULL ? false : frcti_lingering(frcti))

#define FRCTI_DEALLOC(frcti)                                            \
        ((frcti) == NULL ? (time_t) 0 : frcti_dealloc(frcti))

