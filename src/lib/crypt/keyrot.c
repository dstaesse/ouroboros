/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Data-plane key-rotation schedule (node/leaf keys, selector)
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

#define _POSIX_C_SOURCE 200809L

#include <config.h>

#include <ouroboros/atomics.h>
#include <ouroboros/crypt.h>
#include <ouroboros/errno.h>
#include <ouroboros/pthread.h>
#include <ouroboros/rcu.h>

#include "crypt/keyrot.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/*
 * Per-flow keys are addressed by (epoch, node, leaf) and derived as:
 *   root  = per-batch HKDF PRK from the OAP exchange, wiped once expanded
 *   nodes = HKDF-Expand(root, "o7s-keyrot-node")  -> KEY_NODE_COUNT keys
 *   leaf  = HKDF-Expand(node, "o7s-keyrot-leaf"|dir|leaf)  -> AEAD key
 * The epoch is a small wrapping counter, carried in the selector, that picks
 * the live batch; a Tier-2 OAP re-key advances it. The "dir" byte forks the
 * leaf keys per direction.
 *
 * Concurrency: cur/prev batch pointers are published by a re-key and read on
 * the data path under an rcu_guard (lock-free RCU with liburcu, else a per-
 * keyrot rwlock). The per-batch TX counter is atomic, so the (epoch, counter)
 * nonce is unique without serialising TX. Leaf caches are THREAD-LOCAL (an app
 * writer and the FRCT retransmit timer never share cache state), keyed on a
 * global batch id and direct-mapped.
 */

#define KR_WITHIN_BITS (KEY_LEAF_BITS + KEY_NODE_BITS)
#define KR_WITHIN_MASK (((uint64_t) 1 << KR_WITHIN_BITS) - 1)
#define KR_N           (KEY_NODE_COUNT)
#define KR_LEAVES      (1u << KEY_NODE_BITS)
#define KR_BATCH_MAX   ((uint64_t) KR_N << KR_WITHIN_BITS)
#define KR_NODES_SZ    ((size_t) KR_N * SYMMKEYSZ)
#define KR_TCACHE_WAYS 16   /* per-thread cache slots per direction (pow2) */
#define KR_EPOCHS      16   /* 4-bit wire epoch: gens before wrap */

#define KR_RP_WORDS    (KEY_REPLAY_WINDOW / 64) /* pow2; RFC 6479 bitmap */
#define KR_RP_SHIFT    6
#define KR_RP_MASK     63
#define KR_RP_WINDOW   (KEY_REPLAY_WINDOW - 64) /* reserve 1 slack word */

static const char kr_node_label[] = "o7s-keyrot-node";
static const char kr_leaf_label[] = "o7s-keyrot-leaf";

struct kr_batch {
        uint64_t  id;      /* process-global, unique; cache key (no ABA) */
        uint8_t   epoch;   /* 4-bit wire selector                        */
        uint8_t * nodes;   /* KR_NODES_SZ in secure heap; NULL if empty  */
        uint64_t  tx_ctr;  /* atomic; per-batch so nonces never collide  */

        struct { /* RFC 6479-like anti-replay window */
                uint64_t        last; /* highest accepted ctr + 1 */
                uint64_t        bits[KR_RP_WORDS];
                pthread_mutex_t mtx;
        } rp;
};

struct kr_keycache {
        uint8_t * key;     /* SYMMKEYSZ, points into the per-thread slab */
        uint64_t  id;      /* batch the cached key belongs to            */
        uint16_t  node;
        uint8_t   leaf;
        uint8_t   dir;
        bool      valid;
};

struct keyrot {
        struct kr_batch *  cur;           /* published; read on data path  */
        struct kr_batch *  prev;          /* NULL = none                   */
        struct rcu_guard   guard;         /* re-key vs readers             */
        uint8_t            role;
        uint8_t            tx_epoch;      /* epoch TX currently stamps     */
        bool               peer_switched; /* peer is on the cur epoch      */
};

/* Per-thread leaf-key caches, freed by the thread-exit destructor. */
struct kr_tcache {
        struct kr_keycache tx[KR_TCACHE_WAYS];
        struct kr_keycache rx[KR_TCACHE_WAYS];
        uint8_t *          slab;   /* 2*KR_TCACHE_WAYS*SYMMKEYSZ secure heap */
};

static struct {
        uint64_t       next_id;     /* batch-id allocator (atomic) */
        pthread_key_t  tcache_key;  /* per-thread leaf-key caches  */
        pthread_once_t tcache_once;
} kr_g = { 0, 0, PTHREAD_ONCE_INIT };

static void kr_tcache_free(void * p)
{
        struct kr_tcache * t = p;

        if (t == NULL)
                return;

        crypt_secure_free(t->slab, 2 * KR_TCACHE_WAYS * SYMMKEYSZ);
        free(t);
}

static void kr_tcache_init(void)
{
        pthread_key_create(&kr_g.tcache_key, kr_tcache_free);
}

static struct kr_tcache * kr_tcache_get(void)
{
        struct kr_tcache * t;
        size_t             i;

        pthread_once(&kr_g.tcache_once, kr_tcache_init);

        t = pthread_getspecific(kr_g.tcache_key);
        if (t != NULL)
                return t;

        t = malloc(sizeof(*t));
        if (t == NULL)
                goto fail_alloc;

        memset(t, 0, sizeof(*t));

        t->slab = crypt_secure_malloc(2 * KR_TCACHE_WAYS * SYMMKEYSZ);
        if (t->slab == NULL)
                goto fail_slab;

        for (i = 0; i < KR_TCACHE_WAYS; i++) {
                t->tx[i].key = t->slab + i * SYMMKEYSZ;
                t->rx[i].key = t->slab + (KR_TCACHE_WAYS + i) * SYMMKEYSZ;
        }

        if (pthread_setspecific(kr_g.tcache_key, t) != 0)
                goto fail_set;

        return t;

 fail_set:
        crypt_secure_free(t->slab, 2 * KR_TCACHE_WAYS * SYMMKEYSZ);
 fail_slab:
        free(t);
 fail_alloc:
        return NULL;
}

static uint8_t * kr_expand_nodes(const uint8_t * root)
{
        uint8_t * nodes;
        buffer_t  prk;
        buffer_t  info;
        buffer_t  okm;

        nodes = crypt_secure_malloc(KR_NODES_SZ);
        if (nodes == NULL)
                return NULL;

        prk.len   = SYMMKEYSZ;
        prk.data  = (uint8_t *) root;
        info.len  = sizeof(kr_node_label) - 1;
        info.data = (uint8_t *) kr_node_label;
        okm.len   = KR_NODES_SZ;
        okm.data  = nodes;

        if (crypt_hkdf_expand(prk, info, okm) != 0)
                goto fail_expand;

        return nodes;

 fail_expand:
        crypt_secure_free(nodes, KR_NODES_SZ);
        return NULL;
}

static int kr_leaf_key(const uint8_t * node,
                       uint8_t         leaf,
                       uint8_t         dir,
                       uint8_t *       out)
{
        uint8_t  info_buf[sizeof(kr_leaf_label) - 1 + 2];
        buffer_t prk;
        buffer_t info;
        buffer_t okm;
        size_t   n = sizeof(kr_leaf_label) - 1;

        memcpy(info_buf, kr_leaf_label, n);
        info_buf[n]     = dir;
        info_buf[n + 1] = leaf;

        prk.len   = SYMMKEYSZ;
        prk.data  = (uint8_t *) node;
        info.len  = n + 2;
        info.data = info_buf;
        okm.len   = SYMMKEYSZ;
        okm.data  = out;

        return crypt_hkdf_expand(prk, info, okm);
}

static __inline__ bool kr_kc_hit(const struct kr_keycache * kc,
                                 const struct kr_batch *    b,
                                 uint16_t                   node,
                                 uint8_t                    leaf,
                                 uint8_t                    dir)
{
        if (!kc->valid)
                return false;

        if (kc->id != b->id)
                return false;

        if (kc->node != node)
                return false;

        if (kc->leaf != leaf)
                return false;

        return kc->dir == dir;
}

/* Fetch the leaf key; derive into the (direct-mapped) slot on a miss. */
static const uint8_t * kr_kc_get(struct kr_keycache *    cache,
                                 const struct kr_batch * b,
                                 uint16_t                node,
                                 uint8_t                 leaf,
                                 uint8_t                 dir)
{
        struct kr_keycache * kc;
        uint8_t *            nkey;

        kc = &cache[b->id & (KR_TCACHE_WAYS - 1)];

        if (kr_kc_hit(kc, b, node, leaf, dir))
                return kc->key;

        nkey = b->nodes + (size_t) node * SYMMKEYSZ;
        if (kr_leaf_key(nkey, leaf, dir, kc->key) != 0)
                return NULL;

        kc->valid = true;
        kc->id    = b->id;
        kc->node  = node;
        kc->leaf  = leaf;
        kc->dir   = dir;

        return kc->key;
}

static void kr_sel_enc(uint8_t  epoch,
                       uint16_t node,
                       uint32_t seq,
                       uint8_t  sel[KR_SELECTOR_LEN])
{
        sel[0] = (uint8_t) ((epoch << 4) | ((node >> 8) & 0x0F));
        sel[1] = (uint8_t) (node & 0xFF);
        sel[2] = (uint8_t) (seq >> 24);
        sel[3] = (uint8_t) (seq >> 16);
        sel[4] = (uint8_t) (seq >> 8);
        sel[5] = (uint8_t) (seq);
}

static void kr_sel_dec(const uint8_t sel[KR_SELECTOR_LEN],
                       uint8_t *     epoch,
                       uint16_t *    node,
                       uint32_t *    seq)
{
        *epoch = (uint8_t) (sel[0] >> 4);
        *node  = (uint16_t) (((sel[0] & 0x0F) << 8) | sel[1]);
        *seq   = ((uint32_t) sel[2] << 24) | ((uint32_t) sel[3] << 16) |
                 ((uint32_t) sel[4] << 8)  | (uint32_t) sel[5];
}

static uint64_t kr_ctr(uint16_t node,
                       uint32_t seq)
{
        return ((uint64_t) node << KR_WITHIN_BITS) |
               ((uint64_t) seq & KR_WITHIN_MASK);
}

static void kr_nonce(uint64_t  ctr,
                     uint8_t * nonce)
{
        size_t i;

        memset(nonce, 0, KR_NONCE_LEN);

        /* ctr big-endian in the low 8 bytes; high bytes stay zero */
        for (i = 0; i < 8; i++)
                nonce[i] = (uint8_t) (ctr >> (56 - 8 * i));
}

static struct kr_batch * kr_batch_create(uint8_t         epoch,
                                         const uint8_t * root)
{
        struct kr_batch * b;

        b = malloc(sizeof(*b));
        if (b == NULL)
                goto fail_alloc;

        b->nodes = kr_expand_nodes(root);
        if (b->nodes == NULL)
                goto fail_nodes;

        b->id     = FETCH_ADD_RELAXED(&kr_g.next_id, 1);
        b->epoch  = epoch;
        b->tx_ctr = 0;
        if (pthread_mutex_init(&b->rp.mtx, NULL) != 0)
                goto fail_lock;

        b->rp.last = 0;
        memset(b->rp.bits, 0, sizeof(b->rp.bits));

        return b;

 fail_lock:
        crypt_secure_free(b->nodes, KR_NODES_SZ);
        free(b);
        return NULL;
 fail_nodes:
        free(b);
 fail_alloc:
        return NULL;
}

static void kr_batch_free(struct kr_batch * b)
{
        if (b == NULL)
                return;

        pthread_mutex_destroy(&b->rp.mtx);
        crypt_secure_free(b->nodes, KR_NODES_SZ);
        free(b);
}

/*
 * RFC 6479 anti-replay window keyed on the per-batch counter, with
 * seq = ctr + 1 so 0 means "nothing accepted yet". Returns 0 if the
 * packet is fresh (and records it), -1 on a replay or a too-old ctr.
 */
static int kr_rp_commit(struct kr_batch * b,
                        uint64_t          ctr)
{
        uint64_t seq;
        uint64_t idx;
        uint64_t cur;
        uint64_t diff;

        seq = ctr + 1;

        pthread_mutex_lock(&b->rp.mtx);

        if (seq > b->rp.last) {
                idx  = seq >> KR_RP_SHIFT;
                cur  = b->rp.last >> KR_RP_SHIFT;
                diff = idx - cur;
                if (diff > KR_RP_WORDS)
                        diff = KR_RP_WORDS;

                while (diff-- > 0) {
                        cur++;
                        b->rp.bits[cur & (KR_RP_WORDS - 1)] = 0;
                }

                b->rp.bits[idx & (KR_RP_WORDS - 1)] |=
                        (uint64_t) 1 << (seq & KR_RP_MASK);
                b->rp.last = seq;
                goto finish;
        }

        if (b->rp.last - seq >= KR_RP_WINDOW)
                goto fail;

        idx = seq >> KR_RP_SHIFT;
        if (b->rp.bits[idx & (KR_RP_WORDS - 1)]
            & ((uint64_t) 1 << (seq & KR_RP_MASK)))
                goto fail;

        b->rp.bits[idx & (KR_RP_WORDS - 1)] |=
                (uint64_t) 1 << (seq & KR_RP_MASK);
 finish:
        pthread_mutex_unlock(&b->rp.mtx);

        return 0;
 fail:
        pthread_mutex_unlock(&b->rp.mtx);

        return -1;
}

struct keyrot * keyrot_create(const uint8_t * root,
                              uint8_t         epoch,
                              uint8_t         role)
{
        struct keyrot * kr;

        assert(root != NULL);
        assert(role <= 1);

        if (epoch >= KR_EPOCHS)
                goto fail_kr;

        kr = malloc(sizeof(*kr));
        if (kr == NULL)
                goto fail_kr;

        memset(kr, 0, sizeof(*kr));

        kr->role          = role;
        kr->tx_epoch      = epoch;
        kr->peer_switched = true;
        kr->prev          = NULL;

        kr->cur = kr_batch_create(epoch, root);
        if (kr->cur == NULL)
                goto fail_cur;

        if (rcu_guard_init(&kr->guard))
                goto fail_guard;

        return kr;

 fail_guard:
        kr_batch_free(kr->cur);
 fail_cur:
        free(kr);
 fail_kr:
        return NULL;
}

void keyrot_destroy(struct keyrot * kr)
{
        if (kr == NULL)
                return;

        /* Wait out any in-flight reader before freeing batches. */
        rcu_drain(&kr->guard);

        kr_batch_free(kr->cur);
        kr_batch_free(kr->prev);

        rcu_guard_fini(&kr->guard);

        free(kr);
}

/* A dup live epoch shadows straggler RX; epoch is peer-driven. */
static struct kr_batch * kr_live_batch(struct kr_batch * cur,
                                       struct kr_batch * prev,
                                       uint8_t           epoch)
{
        if (epoch == cur->epoch)
                return cur;

        if (prev != NULL && epoch == prev->epoch)
                return prev;

        return NULL;
}

int keyrot_rekey(struct keyrot * kr,
                 const uint8_t * root,
                 uint8_t         epoch)
{
        struct kr_batch * nb;
        struct kr_batch * old_prev;
        struct kr_batch * cur;
        struct kr_batch * prev;
        struct kr_batch * live;
        int               ret;

        assert(kr != NULL);
        assert(root != NULL);

        if (epoch >= KR_EPOCHS)
                return -1;

        nb = kr_batch_create(epoch, root);
        if (nb == NULL)
                return -1;

        rcu_wrlock(&kr->guard);

        cur  = rcu_deref(kr->cur);
        prev = rcu_deref(kr->prev);

        live = kr_live_batch(cur, prev, epoch);
        if (live != NULL) {
                /* The first node key identifies the root. */
                if (crypt_ct_cmp(live->nodes, nb->nodes, SYMMKEYSZ) == 0)
                        ret = -EREPLAY;
                else
                        ret = -1;
                rcu_wrunlock(&kr->guard);
                kr_batch_free(nb);
                return ret;
        }

        old_prev = kr->prev;
        rcu_assign(kr->prev, kr->cur);
        rcu_publish(nb);
        rcu_assign(kr->cur, nb);

        /* TX keeps the old epoch until the peer is seen on the new one. */
        STORE_RELEASE(&kr->peer_switched, false);

        rcu_wrunlock(&kr->guard);

        /* old_prev is unreachable now; reclaim past any live reader. */
        rcu_reclaim(&kr->guard);
        kr_batch_free(old_prev);

        return 0;
}

void keyrot_tx_promote(struct keyrot * kr)
{
        assert(kr != NULL);

        /* Serialise with keyrot_rekey so tx_epoch tracks a consistent cur. */
        rcu_wrlock(&kr->guard);
        STORE_RELAXED(&kr->tx_epoch, rcu_deref(kr->cur)->epoch);
        rcu_wrunlock(&kr->guard);
}

int keyrot_tx_next(struct keyrot *  kr,
                   uint8_t          sel[KR_SELECTOR_LEN],
                   const uint8_t ** key,
                   uint8_t          nonce[KR_NONCE_LEN])
{
        struct kr_tcache * tc;
        struct kr_batch *  cur;
        struct kr_batch *  prev;
        struct kr_batch *  b;
        uint64_t           ctr;
        uint16_t           node;
        uint8_t            leaf;
        uint8_t            txe;
        uint8_t            epoch;
        uint32_t           seq;
        const uint8_t *    k;

        assert(kr != NULL);
        assert(key != NULL);

        tc = kr_tcache_get();
        if (tc == NULL)
                return -1;

        rcu_rdlock(&kr->guard);

        cur  = rcu_deref(kr->cur);
        prev = rcu_deref(kr->prev);
        rcu_consume(cur);
        rcu_consume(prev);
        txe  = LOAD_RELAXED(&kr->tx_epoch);

        if (cur->epoch == txe)
                b = cur;
        else if (prev != NULL && prev->epoch == txe)
                b = prev;
        else
                b = NULL;

        if (b == NULL) {
                rcu_rdunlock(&kr->guard);
                return -1; /* tx_epoch batch gone; next promote resyncs */
        }

        /* Slot reserved even if exhausted; tx_nodes_left clamps the count. */
        ctr = FETCH_ADD_RELAXED(&b->tx_ctr, 1);
        if (ctr >= KR_BATCH_MAX) {
                rcu_rdunlock(&kr->guard);
                return -1; /* batch exhausted */
        }

        node  = (uint16_t) (ctr >> KR_WITHIN_BITS);
        leaf  = (uint8_t) ((ctr >> KEY_LEAF_BITS) & (KR_LEAVES - 1));
        seq   = (uint32_t) (ctr & KR_WITHIN_MASK);
        epoch = b->epoch;

        k = kr_kc_get(tc->tx, b, node, leaf, kr->role);

        rcu_rdunlock(&kr->guard);

        if (k == NULL)
                return -1;

        kr_sel_enc(epoch, node, seq, sel);
        kr_nonce(ctr, nonce);

        *key = k;

        return 0;
}

int keyrot_rx_lookup(struct keyrot *  kr,
                     const uint8_t    sel[KR_SELECTOR_LEN],
                     const uint8_t ** key,
                     uint8_t          nonce[KR_NONCE_LEN],
                     struct kr_rx *   rx)
{
        struct kr_tcache * tc;
        struct kr_batch *  cur;
        struct kr_batch *  prev;
        struct kr_batch *  b;
        uint8_t            epoch;
        uint16_t           node;
        uint32_t           seq;
        uint64_t           ctr;
        uint8_t            leaf;
        const uint8_t *    k;

        assert(kr != NULL);
        assert(key != NULL);

        kr_sel_dec(sel, &epoch, &node, &seq);

        if (node >= KR_N)
                return -1;

        tc = kr_tcache_get();
        if (tc == NULL)
                return -1;

        rcu_rdlock(&kr->guard);

        cur  = rcu_deref(kr->cur);
        prev = rcu_deref(kr->prev);
        rcu_consume(cur);
        rcu_consume(prev);

        if (epoch == cur->epoch) {
                b = cur;
        } else if (prev != NULL && epoch == prev->epoch) {
                b = prev;
        } else {
                rcu_rdunlock(&kr->guard);
                return -1; /* unknown epoch */
        }

        ctr  = kr_ctr(node, seq);
        leaf = (uint8_t) ((ctr >> KEY_LEAF_BITS) & (KR_LEAVES - 1));

        /* peer's tx direction */
        k = kr_kc_get(tc->rx, b, node, leaf, (uint8_t) (kr->role ^ 1));

        rx->id  = b->id;
        rx->ctr = ctr;

        rcu_rdunlock(&kr->guard);

        if (k == NULL)
                return -1;

        kr_nonce(ctr, nonce);

        *key = k;

        return 0;
}

/*
 * Commit a packet that authenticated under the batch keyrot_rx_lookup
 * selected. Re-finds that batch by id (epoch may have advanced) and,
 * if still resident, advances the replay window and records that the
 * peer is on the current batch. Runs only post-AEAD so a forged or
 * replayed packet can mutate no receiver state. Returns -1 on replay.
 */
int keyrot_rx_commit(struct keyrot *      kr,
                     const struct kr_rx * rx)
{
        struct kr_batch * cur;
        struct kr_batch * prev;
        struct kr_batch * b;
        int               rc;

        assert(kr != NULL);
        assert(rx != NULL);

        rcu_rdlock(&kr->guard);

        cur  = rcu_deref(kr->cur);
        prev = rcu_deref(kr->prev);
        rcu_consume(cur);
        rcu_consume(prev);

        if (cur->id == rx->id)
                b = cur;
        else if (prev != NULL && prev->id == rx->id)
                b = prev;
        else
                b = NULL;

        if (b == NULL) {
                rcu_rdunlock(&kr->guard);
                return 0; /* batch evicted post-auth; nothing to protect */
        }

        rc = kr_rp_commit(b, rx->ctr);
        if (rc == 0 && b == cur)
                STORE_RELEASE(&kr->peer_switched, true);

        rcu_rdunlock(&kr->guard);

        return rc;
}

bool keyrot_peer_switched(const struct keyrot * kr)
{
        assert(kr != NULL);

        return LOAD_ACQUIRE(&kr->peer_switched);
}

unsigned keyrot_tx_nodes_left(struct keyrot * kr)
{
        struct kr_batch * cur;
        struct kr_batch * prev;
        struct kr_batch * b;
        uint64_t          ctr;
        unsigned          used;
        uint8_t           txe;

        assert(kr != NULL);

        rcu_rdlock(&kr->guard);
        cur  = rcu_deref(kr->cur);
        prev = rcu_deref(kr->prev);
        rcu_consume(cur);
        rcu_consume(prev);
        txe  = LOAD_RELAXED(&kr->tx_epoch);

        if (cur->epoch == txe)
                b = cur;
        else if (prev != NULL && prev->epoch == txe)
                b = prev;
        else
                b = NULL;

        ctr  = b != NULL ? LOAD_RELAXED(&b->tx_ctr) : KR_BATCH_MAX;
        rcu_rdunlock(&kr->guard);

        used = (unsigned) (ctr >> KR_WITHIN_BITS);
        if (used >= KR_N)
                return 0;

        return KR_N - used;
}
